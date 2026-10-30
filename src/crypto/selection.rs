//! Permanent algorithm prohibitions, independent of runtime legacy permission.
use super::KerberosEtype;
use crate::error::{Policy, RejectedFeature, RejectionReason};

/// Select an implemented enctype, rejecting permanently forbidden algorithms.
/// Unknown or secure unimplemented IDs return None; this does not authorize RC4/DES3.
/// # Errors
/// Returns the typed D2 rejection before cryptographic work.
#[inline]
pub fn enctype(id: i32) -> Result<Option<KerberosEtype>, Policy> {
    reject_enctype(id)?;
    Ok(KerberosEtype::from_etype_id(id))
}

/// Reject D2 enctype IDs even for raw callers with no runtime policy.
/// # Errors
/// Returns `SingleDes` for historical DES profiles, `Rc4Export` for 24 and
/// `WeakCrypto` for raw DES3.
#[inline]
pub const fn reject_enctype(id: i32) -> Result<(), Policy> {
    let feature = match id {
        1..=4 | 8_i32 => RejectedFeature::SingleDes,
        24_i32 => RejectedFeature::Rc4Export,
        5..=6 => RejectedFeature::WeakCrypto,
        _ => return Ok(()),
    };
    Err(Policy::RejectedFeature {
        feature,
        reason: RejectionReason::RemovedAndInsecure,
    })
}

/// Select an authenticated checksum profile without granting legacy permission.
/// # Errors
/// Returns `UnauthenticatedChecksum` for historical unkeyed/weak integrity profiles.
#[inline]
pub fn checksum(id: i32) -> Result<Option<KerberosEtype>, Policy> {
    reject_checksum(id)?;
    Ok(KerberosEtype::from_checksum_type_id(id))
}

/// Reject unkeyed or weak negotiable integrity, not protocol-internal hashes.
/// # Errors
/// Rejects CRC32, MD4/DES, DES-MAC, MD5/DES, raw SHA1 and SHA1 legacy forms.
#[inline]
pub const fn reject_checksum(id: i32) -> Result<(), Policy> {
    if matches!(id, 1..=10 | 14_i32) {
        return Err(Policy::RejectedFeature {
            feature: RejectedFeature::UnauthenticatedChecksum { id },
            reason: RejectionReason::MissingAuthentication,
        });
    }
    Ok(())
}

/// Recognize checksum names used by explicit integrity configuration.
#[inline]
#[must_use]
pub fn checksum_name(name: &str) -> Option<i32> {
    match name.to_ascii_lowercase().as_str() {
        "crc32" => Some(1),
        "rsa-md4" | "md4" => Some(2),
        "rsa-md4-des" => Some(3),
        "des-mac" => Some(4),
        "des-mac-k" => Some(5),
        "rsa-md4-des-k" => Some(6),
        "rsa-md5" | "md5" => Some(7),
        "rsa-md5-des" => Some(8),
        "rsa-md5-des3" | "sha" | "nist-sha" => Some(9),
        "sha1" | "sha-1" | "sha1-other" => Some(14),
        "hmac-sha1-des3" | "hmac-sha1-des3-kd" => Some(12),
        "hmac-md5-rc4" | "hmac-md5-enc" | "hmac-md5-earcfour" => Some(-138),
        "hmac-sha1-96-aes128" => Some(15),
        "hmac-sha1-96-aes256" => Some(16),
        "hmac-sha256-128-aes128" => Some(19),
        "hmac-sha384-192-aes256" => Some(20),
        "cmac-camellia128" => Some(17),
        "cmac-camellia256" => Some(18),
        "md5-hmac-rc4" => Some(-137),
        _ => None,
    }
}

impl TryFrom<i32> for KerberosEtype {
    type Error = Policy;
    #[inline]
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        enctype(value)?.ok_or(Policy::UnknownEnctype { etype: value })
    }
}
