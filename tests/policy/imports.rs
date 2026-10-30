use core::error::Error;

use rasn::types::Integer;
use rasn_kerberos::{
    EncKrbCredPart, EncryptedData, EncryptionKey as WireKey, KrbCred, KrbCredInfo,
};
use rskrb5_ng::{
    Config,
    crypto::{CryptoPolicy, Use},
    error::{Crypto, Policy},
    keytab::EncryptionKey,
    krb_cred::import,
};

/// Semantic import refuses an excluded wrapping key before ciphertext processing.
#[test]
fn imported_wrapping_key_is_checked_before_decryption() -> Result<(), Box<dyn Error>> {
    // Given malformed ciphertext under an excluded AES256 key.
    let config = Config::parse("[libdefaults]\npermitted_enctypes = aes128-cts")?;
    let policy = CryptoPolicy::from_libdefaults(&config.libdefaults)?;
    let cred = KrbCred {
        pvno: Integer::from(5_i32),
        msg_type: Integer::from(22_i32),
        tickets: Vec::new(),
        enc_part: EncryptedData {
            etype: 18,
            kvno: None,
            cipher: vec![0_u8].into(),
        },
    };
    // When importing rather than calling a raw RFC decoder.
    let failure = import::decrypt(&policy, &cred, &EncryptionKey::new(18, Vec::new()))
        .err()
        .ok_or("excluded import accepted")?;
    // Then rejection precedes key-length/decryption failures.
    assert!(matches!(
        failure
            .source()
            .and_then(|source| source.downcast_ref::<Crypto>())
            .and_then(Error::source)
            .and_then(|source| source.downcast_ref::<Policy>()),
        Some(Policy::EnctypeNotPermitted {
            etype: 18_i32,
            usage: Use::ImportedCredential
        })
    ));
    Ok(())
}

/// Decrypted credential session keys are checked before semantic conversion.
#[test]
fn imported_session_key_is_checked_before_conversion() -> Result<(), Box<dyn Error>> {
    // Given an excluded session key and missing identity metadata.
    let config = Config::parse("[libdefaults]\npermitted_enctypes = aes128-cts")?;
    let policy = CryptoPolicy::from_libdefaults(&config.libdefaults)?;
    let info = KrbCredInfo {
        key: WireKey {
            r#type: 18,
            value: vec![0_u8; 32].into(),
        },
        prealm: None,
        pname: None,
        flags: None,
        auth_time: None,
        start_time: None,
        end_time: None,
        renew_till: None,
        srealm: None,
        sname: None,
        caddr: None,
    };
    let part = EncKrbCredPart {
        ticket_info: vec![info],
        nonce: None,
        timestamp: None,
        usec: None,
        sender_address: None,
        recipient_address: None,
    };
    let cred = KrbCred {
        pvno: Integer::from(5_i32),
        msg_type: Integer::from(22_i32),
        tickets: Vec::new(),
        enc_part: EncryptedData {
            etype: 17,
            kvno: None,
            cipher: Vec::new().into(),
        },
    };
    // When checking the decrypted import.
    let failure = import::decrypted(&policy, &cred, &part)
        .err()
        .ok_or("excluded imported key accepted")?;
    // Then policy precedes missing-field/count conversion failures.
    let crypto = failure.source().ok_or("missing crypto source")?;
    assert!(matches!(
        crypto
            .source()
            .and_then(|source| source.downcast_ref::<Policy>()),
        Some(Policy::EnctypeNotPermitted {
            etype: 18_i32,
            usage: Use::ImportedCredential
        })
    ));
    Ok(())
}
