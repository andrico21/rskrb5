//! KRB-SAFE decoding and checksum helpers.

use rasn::{der, types::Integer};

use crate::{crypto::KerberosEtype, keytab::EncryptionKey};

/// Kerberos protocol version number carried in every message (RFC 4120).
const KRB5_PVNO: i32 = 5;

/// KRB-SAFE message type.
pub const KRB_SAFE_MSG_TYPE: i32 = 20;

/// Key usage for KRB-SAFE checksums.
pub const KRB_SAFE_CHECKSUM_USAGE: u32 = 15;

/// Decode and validate a DER-encoded KRB-SAFE message.
///
/// # Errors
///
/// Returns [`Error::Decode`] when `bytes` is not a DER KRB-SAFE, and
/// [`Error::InvalidMessage`] when its protocol version or message type is wrong.
#[inline]
pub fn decode(bytes: &[u8]) -> Result<rasn_kerberos::KrbSafe, Error> {
    let krb_safe = decode_der::<rasn_kerberos::KrbSafe>("KRB-SAFE", bytes)?;
    validate_integer("pvno", &krb_safe.pvno, KRB5_PVNO)?;
    validate_integer("msg-type", &krb_safe.msg_type, KRB_SAFE_MSG_TYPE)?;
    Ok(krb_safe)
}

/// Encode a KRB-SAFE message as DER.
///
/// # Errors
///
/// Returns [`Error::Encode`] when the DER encoder fails.
#[inline]
pub fn encode(krb_safe: &rasn_kerberos::KrbSafe) -> Result<Vec<u8>, Error> {
    encode_der("KRB-SAFE", krb_safe)
}

/// Build a KRB-SAFE message with a keyed checksum over the safe body.
///
/// # Errors
///
/// Returns the errors of [`checksum`].
#[inline]
pub fn build(
    body: rasn_kerberos::KrbSafeBody,
    key: &EncryptionKey,
) -> Result<rasn_kerberos::KrbSafe, Error> {
    let cksum = checksum(&body, key)?;
    Ok(rasn_kerberos::KrbSafe {
        pvno: Integer::from(KRB5_PVNO),
        msg_type: Integer::from(KRB_SAFE_MSG_TYPE),
        body,
        cksum,
    })
}

/// Compute the keyed checksum for a KRB-SAFE body.
///
/// # Errors
///
/// Returns [`Error::UnsupportedEtype`] for a key whose enctype is not
/// implemented, [`Error::Encode`] when the body cannot be encoded, and
/// [`Error::Crypto`] when the checksum cannot be computed.
#[inline]
pub fn checksum(
    body: &rasn_kerberos::KrbSafeBody,
    key: &EncryptionKey,
) -> Result<rasn_kerberos::Checksum, Error> {
    let etype =
        KerberosEtype::from_etype_id(key.etype).ok_or(Error::UnsupportedEtype(key.etype))?;
    let body_der = encode_der("KrbSafeBody", body)?;
    Ok(rasn_kerberos::Checksum {
        r#type: etype.checksum_type_id(),
        checksum: etype
            .checksum(&key.value, &body_der, KRB_SAFE_CHECKSUM_USAGE)?
            .into(),
    })
}

/// Verify the keyed checksum in a KRB-SAFE message.
///
/// # Errors
///
/// Returns [`Error::UnsupportedChecksumType`] for a checksum type that is not
/// implemented, [`Error::KeyChecksumTypeMismatch`] when the key's enctype does
/// not match the checksum type, [`Error::Encode`] when the body cannot be
/// encoded, and [`Error::ChecksumMismatch`] when the checksum does not verify.
#[inline]
pub fn verify_krb_safe_checksum(
    krb_safe: &rasn_kerberos::KrbSafe,
    key: &EncryptionKey,
) -> Result<(), Error> {
    let etype = KerberosEtype::from_checksum_type_id(krb_safe.cksum.r#type)
        .ok_or(Error::UnsupportedChecksumType(krb_safe.cksum.r#type))?;
    if etype.etype_id() != key.etype {
        return Err(Error::KeyChecksumTypeMismatch {
            key_etype: key.etype,
            checksum_type: krb_safe.cksum.r#type,
        });
    }
    let body_der = encode_der("KrbSafeBody", &krb_safe.body)?;
    if !etype.verify_checksum(
        &key.value,
        &body_der,
        krb_safe.cksum.checksum.as_ref(),
        KRB_SAFE_CHECKSUM_USAGE,
    ) {
        return Err(Error::ChecksumMismatch);
    }
    Ok(())
}

/// Decode a DER value with a typed error.
///
/// # Errors
///
/// Returns [`Error::Decode`] naming `target` when `bytes` is not valid DER for
/// `T`.
fn decode_der<T>(target: &'static str, bytes: &[u8]) -> Result<T, Error>
where
    T: rasn::Decode,
{
    der::decode(bytes).map_err(|source| Error::Decode {
        target,
        message: source.to_string(),
    })
}

/// Encode a value to DER with a typed error.
///
/// # Errors
///
/// Returns [`Error::Encode`] naming `target` when the DER encoder fails.
fn encode_der<T>(target: &'static str, value: &T) -> Result<Vec<u8>, Error>
where
    T: rasn::Encode,
{
    der::encode(value).map_err(|source| Error::Encode {
        target,
        message: source.to_string(),
    })
}

/// Check that a decoded protocol integer such as `pvno` equals `expected`.
///
/// # Errors
///
/// Returns [`Error::InvalidMessage`] naming `field` when the value differs.
fn validate_integer(field: &'static str, actual: &Integer, expected: i32) -> Result<(), Error> {
    if actual != &Integer::from(expected) {
        return Err(Error::InvalidMessage {
            field,
            expected,
            actual: actual.to_string(),
        });
    }
    Ok(())
}

use crate::error::KrbSafe as Error;
