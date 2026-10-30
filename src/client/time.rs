//! Shared Kerberos whole-second conversion boundary.

use core::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use rasn_kerberos::KerberosTime;

/// Convert an ASN.1 whole-second timestamp; fractions and out-of-range values return None.
pub(crate) fn from_kerberos(value: &KerberosTime) -> Option<SystemTime> {
    if value.0.timestamp_subsec_nanos() != 0 {
        return None;
    }
    let seconds = value.0.timestamp();
    let duration = Duration::from_secs(seconds.unsigned_abs());
    if seconds < 0 {
        UNIX_EPOCH.checked_sub(duration)
    } else {
        UNIX_EPOCH.checked_add(duration)
    }
}

/// Convert a system timestamp, rejecting fractions rather than truncating metadata.
pub(super) fn to_kerberos(value: SystemTime) -> Option<KerberosTime> {
    let (seconds, nanos) = super::unix_timestamp_parts(value).ok()?;
    if nanos != 0 {
        return None;
    }
    chrono::DateTime::from_timestamp(seconds, 0).map(|utc| KerberosTime(utc.fixed_offset()))
}

/// Conversion regressions exercise the client boundary before and after delegation.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error as StdError;

    use chrono::DateTime;
    use rasn_kerberos::KerberosTime;

    use crate::client::{Error, system_time_from_kerberos_time};

    /// Fractional ASN.1 timestamps cannot silently become the wrong pre-epoch instant.
    #[test]
    fn fractional_kerberos_time_is_rejected() -> Result<(), Box<dyn StdError>> {
        // Given fractional timestamps on both sides of the epoch.
        for seconds in [-1_i64, 0] {
            let value = KerberosTime(
                DateTime::from_timestamp(seconds, 500_000_000)
                    .ok_or("time")?
                    .fixed_offset(),
            );
            // When the timestamp crosses the Kerberos boundary.
            let converted = system_time_from_kerberos_time(&value);
            // Then a non-whole-second value is rejected rather than rounded incorrectly.
            assert!(matches!(converted, Err(Error::TimeOverflow)));
        }
        Ok(())
    }
}
