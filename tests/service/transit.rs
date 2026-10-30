//! Same-realm transit-policy regression tests.

use super::{TestError, Validator, http_keytab, timestamp, transit_ap_req};

/// Same-realm tickets and KDC-checked cross-realm paths retain their existing acceptance.
#[test]
fn transit_preserves_same_realm_and_kdc_checked_paths() -> Result<(), TestError> {
    for (client_realm, checked) in [("TEST.GOKRB5", false), ("FOREIGN.DUMMY", true)] {
        let keytab = http_keytab()?;
        let bytes = transit_ap_req(client_realm, 1, b"UNTRUSTED", checked)?;
        let mut validator = Validator::new(&keytab).with_now(timestamp(1_893_553_447)?);
        assert_eq!(
            validator.validate_ap_req(&bytes)?.client.realm,
            client_realm
        );
    }
    Ok(())
}
