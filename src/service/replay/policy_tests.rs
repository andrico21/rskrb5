//! Capacity and skew contract regression tests.

use super::{Duration, Error, ReplayCache, ReplayKey, SystemTime};
use crate::service::Principal;

std::thread_local! {
    /// Expiry records examined on this test thread.
    pub(super) static DIGEST_VISITS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// A privately injected orphan is diagnosed rather than silently ignored.
#[test]
#[cfg(debug_assertions)]
fn orphan_trips_pairing_invariant() {
    let mut cache = ReplayCache::new();
    let _: Option<[u8; 32]> = cache.entries.insert(std::sync::Arc::new(key(1)), [1; 32]);
    let outcome = std::panic::catch_unwind(|| cache.assert_paired());
    assert!(outcome.is_err(), "orphan must trip paired-index assertion");
}

/// Distinct clients keep the capacity test independent of principal quotas.
fn key(id: u32) -> ReplayKey {
    ReplayKey {
        service: Principal::new("REALM".into(), 0, vec!["service".into()]),
        client: Principal::new("REALM".into(), 0, vec![id.to_string()]),
        ctime_seconds: 0,
        cusec: id,
    }
}

/// The documented default and custom admission limit both hold.
#[test]
fn capacity_default_and_custom_limit_are_enforced() {
    // Given a deliberately small cache.
    assert_eq!(ReplayCache::default().capacity, 65_536);
    let skew = Duration::from_secs(300);
    let mut cache = ReplayCache::with_limits(skew, 1);
    assert!(matches!(
        cache.insert(key(1), [1; 32], SystemTime::UNIX_EPOCH, skew),
        Ok(true)
    ));
    // When another principal presents a distinct authenticator.
    let outcome = cache.insert(key(2), [2; 32], SystemTime::UNIX_EPOCH, skew);
    // Then no live evidence is evicted to admit it.
    assert!(matches!(
        outcome,
        Err(Error::ReplayCacheCapacityExceeded { capacity: 1 })
    ));
    assert!(matches!(
        cache.insert(key(1), [1; 32], SystemTime::UNIX_EPOCH, skew),
        Ok(false)
    ));
}

/// A wider cache accepts a narrower validator.
#[test]
fn skew_900_accepts_validator_300() {
    // Given a 900-second cache.
    let mut cache = ReplayCache::with_limits(Duration::from_secs(900), 8);
    // When a 300-second validator admits a fresh authenticator.
    let outcome = cache.insert(
        key(1),
        [1; 32],
        SystemTime::UNIX_EPOCH,
        Duration::from_secs(300),
    );
    // Then the ceiling is compatible.
    assert!(matches!(outcome, Ok(true)));
}

/// A narrower cache refuses a wider validator.
#[test]
fn skew_300_rejects_validator_301() {
    // Given a 300-second cache.
    let mut cache = ReplayCache::with_limits(Duration::from_secs(300), 8);
    // When a 301-second validator requests admission.
    let outcome = cache.insert(
        key(1),
        [1; 32],
        SystemTime::UNIX_EPOCH,
        Duration::from_secs(301),
    );
    // Then the requested window cannot escape retention coverage.
    assert!(
        matches!(outcome, Err(Error::ReplayCacheSkewExceeded { maximum, requested })
        if maximum == Duration::from_secs(300) && requested == Duration::from_secs(301))
    );
}

/// Administrative expiry cannot advance the admission watermark.
#[test]
fn safe_pruning_preserves_replay_after_future_clock_sample() {
    // Given a live pair admitted at the epoch.
    let skew = Duration::from_secs(300);
    let mut cache = ReplayCache::with_limits(skew, 8);
    assert!(matches!(
        cache.insert(key(1), [1; 32], SystemTime::UNIX_EPOCH, skew),
        Ok(true)
    ));
    // When maintenance sees a time beyond retention, without an admission.
    let _: usize = cache.prune_expired_at(SystemTime::UNIX_EPOCH + Duration::from_secs(901));
    // Then rolling back to a valid presentation still rejects the replay.
    assert!(matches!(
        cache.insert(key(1), [1; 32], SystemTime::UNIX_EPOCH, skew),
        Ok(false)
    ));
}

/// Admission before expiry must not scan live digest records.
#[test]
fn admission_has_bounded_digest_visits() {
    // Given 256 live pairs.
    let skew = Duration::from_secs(300);
    let mut cache = ReplayCache::with_limits(skew, 512);
    for id in 0..256_u32 {
        let mut digest = [0; 32];
        for (byte, value) in digest.iter_mut().zip(id.to_le_bytes()) {
            *byte = value;
        }
        assert!(matches!(
            cache.insert(key(id), digest, SystemTime::UNIX_EPOCH, skew),
            Ok(true)
        ));
    }
    DIGEST_VISITS.set(0);
    // When a fresh pair arrives before the first expiry.
    assert!(matches!(
        cache.insert(key(257), [255; 32], SystemTime::UNIX_EPOCH, skew),
        Ok(true)
    ));
    // Then expiry work is independent of the live population.
    assert!(
        DIGEST_VISITS.get() <= 2,
        "visited {} digests",
        DIGEST_VISITS.get()
    );
}
