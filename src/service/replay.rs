//! Local replay-cache admission and maintenance.

#[cfg(test)]
use super::replay_tests;

#[cfg(test)]
mod policy_tests;
use super::{
    Arc, DEFAULT_MAX_CLOCK_SKEW, DigestRecord, Duration, Error, HashMap, ReplayCache, ReplayKey,
    SystemTime,
};

impl Default for ReplayCache {
    #[inline]
    fn default() -> Self {
        Self::with_limits(DEFAULT_MAX_CLOCK_SKEW, 0x0001_0000)
    }
}

impl ReplayCache {
    /// Create an empty cache with immutable skew and live-entry admission limits.
    ///
    /// Validators exceeding `max_clock_skew` are rejected on admission. Zero
    /// capacity rejects all new records. Expiry retains three times the skew
    /// from the last-seen watermark, covering future authenticators and rollback.
    /// Backward clock samples up to this skew are tolerated without lowering
    /// the high-water mark; larger rollbacks fail closed.
    #[must_use]
    #[inline]
    pub fn with_limits(max_clock_skew: Duration, capacity: usize) -> Self {
        Self {
            max_clock_skew,
            capacity,
            watermark: None,
            entries: HashMap::new(),
            authenticators: HashMap::new(),
        }
    }

    #[must_use]
    /// Create an empty replay cache.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Remove all cached replay entries.
    #[inline]
    pub fn clear(&mut self) {
        self.entries.clear();
        self.authenticators.clear();
    }

    #[must_use]
    /// Number of cached RFC 4120 replay entries, excluding the digest index.
    #[inline]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    /// Whether the RFC 4120 replay entries are empty, excluding the digest index.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Remove entries last seen more than `max_age` ago.
    ///
    /// Entries are aged by the watermark at which they were last seen, not by
    /// the clock sample of their presentation.
    #[inline]
    pub fn clear_older_than(&mut self, max_age: Duration) -> usize {
        self.clear_older_than_at(max_age, SystemTime::now())
    }

    /// Remove entries last seen more than `max_age` before `now`.
    ///
    /// Entries are aged by the watermark at which they were last seen, not by
    /// the clock sample of their presentation. A replay key and its
    /// authenticator digest are removed together.
    #[inline]
    pub fn clear_older_than_at(&mut self, max_age: Duration, now: SystemTime) -> usize {
        let entries = &mut self.entries;
        let before = entries.len();
        // One pass over the digests; the key index is touched only for the
        // pairs that expire, not probed once per live key.
        self.authenticators.retain(|_, record| {
            let live = now
                .duration_since(record.last_seen)
                .map_or(true, |age| age <= max_age);
            if !live {
                #[cfg(test)]
                replay_tests::KEY_INDEX_VISITS
                    .with(|visits| visits.set(visits.get().saturating_add(1)));
                // Pairing is one to one, so this removes the digest's only key.
                let _: Option<[u8; 32]> = entries.remove(&*record.key);
            }
            live
        });
        // Removal only shrinks the key index, so its length cannot have grown.
        before.saturating_sub(entries.len())
    }

    /// Record one presentation, or report it as a replay.
    ///
    /// Returns `false` when either the RFC 4120 replay key or authenticator digest
    /// was already seen, refreshing every matched key and digest pair together;
    /// `true` once both are recorded.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReplayCacheSkewExceeded`], [`Error::ReplayCacheClockRollback`]
    /// or [`Error::ReplayCacheCapacityExceeded`] when cache policy rejects admission.
    pub(super) fn insert(
        &mut self,
        key: ReplayKey,
        authenticator_digest: [u8; 32],
        presented_at: SystemTime,
        validator_skew: Duration,
    ) -> Result<bool, Error> {
        if validator_skew > self.max_clock_skew {
            return Err(Error::ReplayCacheSkewExceeded {
                maximum: self.max_clock_skew,
                requested: validator_skew,
            });
        }
        if self.watermark.is_some_and(|latest| {
            latest
                .duration_since(presented_at)
                .is_ok_and(|rollback| rollback > self.max_clock_skew)
        }) {
            return Err(Error::ReplayCacheClockRollback);
        }
        let latest = self
            .watermark
            .map_or(presented_at, |time| time.max(presented_at));
        self.watermark = Some(latest);
        // For first presentation P, c <= P+s. A tolerated sample T >= W-s
        // can accept c only if c >= T-s, hence P >= W-3s. Keep equality live.
        let retention = self.max_clock_skew.saturating_mul(3);
        let _: usize = self.clear_older_than_at(retention, latest);
        // A key hit refreshes the digest admitted with it, and a digest hit
        // refreshes its own record, so a pair never ages apart.
        let paired = self.entries.get(&key).copied();
        let mut replay = paired.is_some();
        for digest in paired.into_iter().chain([authenticator_digest]) {
            if let Some(record) = self.authenticators.get_mut(&digest) {
                record.last_seen = latest;
                replay = true;
            }
        }
        if replay {
            return Ok(false);
        }
        if self.entries.len() >= self.capacity {
            return Err(Error::ReplayCacheCapacityExceeded {
                capacity: self.capacity,
            });
        }
        // Both lookups above missed, so neither insert replaces an entry and
        // the new key and digest pair one to one.
        let shared_key = Arc::new(key);
        let _: Option<[u8; 32]> = self
            .entries
            .insert(Arc::clone(&shared_key), authenticator_digest);
        drop(self.authenticators.insert(
            authenticator_digest,
            DigestRecord {
                last_seen: latest,
                key: shared_key,
            },
        ));
        Ok(true)
    }
}
