use core::error::Error;

use rskrb5_ng::{
    config::Config,
    crypto::{CryptoPolicy, Use, checked},
    error::Policy,
};

/// Excluded dispatch fails before any password derivation or message operation.
#[test]
fn checked_dispatch_requires_permission() -> Result<(), Box<dyn Error>> {
    // Given a policy permitting only AES128-SHA1.
    let config = Config::parse("[libdefaults]\npermitted_enctypes = aes128-cts")?;
    let policy = CryptoPolicy::from_libdefaults(&config.libdefaults)?;
    // When attempting to obtain a checked AES256 primitive.
    let failure = checked::Etype::new(&policy, 18)
        .err()
        .ok_or("excluded dispatch accepted")?;
    // Then the failure is policy, before input lengths, KDF parameters or randomness.
    assert!(matches!(
        failure,
        Policy::EnctypeNotPermitted {
            etype: 18_i32,
            usage: Use::CheckedLowLevel
        }
    ));
    let allowed = checked::Etype::new(&policy, 17)?;
    let key = [0_u8; 16];
    let encrypted = allowed.encrypt_message_with_confounder(&key, b"checked", 1, &[0_u8; 16])?;
    assert_eq!(allowed.decrypt_message(&key, &encrypted, 1)?, b"checked");
    let checksum = allowed.checksum(&key, b"checked", 1)?;
    allowed.verify_checksum(&key, b"checked", &checksum, 1)?;
    Ok(())
}
