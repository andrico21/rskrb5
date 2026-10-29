//! Independent owner observations for GSS plaintext staging.

use core::cell::RefCell;

use zeroize::Zeroizing;

use super::{Error, GSSAPI_INITIATOR_SEAL_USAGE, GSSAPI_INITIATOR_SIGN_USAGE, MicToken, WrapToken};
use crate::keytab::EncryptionKey;

thread_local! {
    /// Drop events scoped to this test thread, never mixed with another operation.
    static EVENTS: RefCell<Vec<(&'static str, usize, bool)>> = const { RefCell::new(Vec::new()) };
}

/// Observe initialized bytes after erasure, before deallocation, without unsafe access.
pub(super) fn observe(purpose: &'static str, bytes: &[u8]) {
    EVENTS.with_borrow_mut(|events| {
        events.push((purpose, bytes.len(), bytes.iter().all(|byte| *byte == 0)));
    });
}

/// Each operation must erase exactly its own staging, including malformed-header exits.
#[test]
fn every_staging_owner_erases_its_live_bytes() -> Result<(), Error> {
    let key = EncryptionKey::new(17, vec![0x42; 16]);
    drop(super::scratch::Scratch::new(vec![0x55], "observer-control"));
    assert_events(&[("observer-control", 1, true)]);
    EVENTS.with_borrow_mut(Vec::clear);
    let mic = MicToken::new_initiator(vec![0x77; 5], &key)?;
    assert_events(&[("mic-checksum", 21, true)]);
    mic.verify(&key, GSSAPI_INITIATOR_SIGN_USAGE)?;
    assert_events(&[("mic-checksum", 21, true)]);
    let mut wrap = WrapToken::new_initiator(vec![0x77; 5], &key)?;
    assert_events(&[("wrap-checksum", 21, true)]);
    let wire = wrap.encode()?;
    assert_events(&[("wrap-encode", 33, true)]);
    drop(WrapToken::decode(&wire, false)?);
    assert_events(&[("wrap-decode", 17, true)]);
    wrap.encrypt_payload_with_confounder(&key, GSSAPI_INITIATOR_SEAL_USAGE, &[0x11; 16])?;
    assert_events(&[("wrap-seal", 33, true)]);
    wrap.verify(&key, GSSAPI_INITIATOR_SEAL_USAGE)?;
    assert_events(&[("wrap-decrypt", 5, true), ("wrap-verify", 5, true)]);
    wrap.snd_seq_num = 1;
    assert!(matches!(
        wrap.decrypt_payload(&key, GSSAPI_INITIATOR_SEAL_USAGE),
        Err(Error::InvalidGssEncryptedHeader)
    ));
    assert_events(&[("wrap-decrypt", 33, true)]);
    Ok(())
}

/// Public payload storage keeps its erasing owner on replacement and decryption.
#[test]
fn payload_storage_requires_zeroizing_owners() -> Result<(), Error> {
    let key = EncryptionKey::new(17, vec![0x42; 16]);
    let mic = MicToken::new(0, 0)
        .with_payload(vec![1])
        .with_payload(vec![2]);
    let payload: &Option<Zeroizing<Vec<u8>>> = &mic.payload;
    assert_eq!(
        payload.as_ref().map(|bytes| bytes.as_slice()),
        Some([2].as_slice())
    );
    let mut wrap = WrapToken::new_initiator_sealed_with_confounder(vec![3], &key, &[0; 16])?;
    assert_eq!(
        wrap.decrypt_and_set_payload(&key, GSSAPI_INITIATOR_SEAL_USAGE)?,
        &[3]
    );
    let stored: &Option<Zeroizing<Vec<u8>>> = &wrap.payload;
    assert_eq!(
        stored.as_ref().map(|bytes| bytes.as_slice()),
        Some([3].as_slice())
    );
    Ok(())
}

/// Consuming constructors accept the caller's zeroizing allocation directly.
#[test]
fn constructors_accept_zeroizing_payloads() -> Result<(), Error> {
    let key = EncryptionKey::new(17, vec![0x42; 16]);
    let payload = Zeroizing::new(vec![0x77; 5]);
    let mic = MicToken::new_initiator(payload.clone(), &key)?;
    let wrap = WrapToken::new_initiator_sealed_with_confounder(payload, &key, &[0; 16])?;
    assert_eq!(mic.payload.as_ref().map(|bytes| bytes.len()), Some(5));
    assert_eq!(
        wrap.decrypt_payload(&key, GSSAPI_INITIATOR_SEAL_USAGE)?,
        vec![0x77; 5]
    );
    Ok(())
}

/// Consume the complete event list, so an unrelated owner's erasure cannot mask a missing one.
fn assert_events(expected: &[(&str, usize, bool)]) {
    EVENTS.with_borrow_mut(|events| {
        assert_eq!(events.as_slice(), expected);
        events.clear();
    });
}
