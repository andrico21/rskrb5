//! Configured skew and owned replay-cache compatibility.

use super::{Duration, TestError, VALID_AP_REQ, Validator, decode_hex, http_keytab, timestamp};

/// A fresh AP-REQ is accepted with a 301-second owned-cache window.
#[test]
fn configured_skew_accepts_fresh_request() -> Result<(), TestError> {
    let keytab = http_keytab()?;
    let mut validator = Validator::new(&keytab)
        .with_now(timestamp(1_893_553_447)?)
        .with_max_clock_skew(Duration::from_secs(301))?;
    drop(validator.validate_ap_req(&decode_hex(VALID_AP_REQ)?)?);
    Ok(())
}
