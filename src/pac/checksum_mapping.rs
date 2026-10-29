//! Mapping between PAC wire checksums and Kerberos enctypes.

use super::{CHECKSUM_HMAC_MD5_UNSIGNED, KerberosEtype};

/// Kerberos encryption type whose checksum is `signature_type`, if any.
pub(super) fn kerberos_etype_for_checksum_type(signature_type: u32) -> Option<KerberosEtype> {
    let signed = match signature_type {
        CHECKSUM_HMAC_MD5_UNSIGNED => -138,
        positive => i32::try_from(positive).ok()?,
    };
    KerberosEtype::from_checksum_type_id(signed)
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;

    use hmac::{Hmac, KeyInit as _, Mac as _};
    use md5::{Digest as _, Md5};

    use crate::{keytab::EncryptionKey, pac::Pac};

    /// An independently signed RC4 PAC reaches HMAC-MD5 verification.
    #[test]
    fn rc4_pac_verifies_independent_usage17_signature() -> Result<(), Box<dyn Error>> {
        // Given a PAC container with server and KDC signature buffers.
        let key = [0x42; 16];
        let mut wire = Vec::new();
        wire.extend_from_slice(&2_u32.to_le_bytes());
        wire.extend_from_slice(&0_u32.to_le_bytes());
        for (kind, offset) in [(6_u32, 40_u64), (7, 64)] {
            wire.extend_from_slice(&kind.to_le_bytes());
            wire.extend_from_slice(&20_u32.to_le_bytes());
            wire.extend_from_slice(&offset.to_le_bytes());
        }
        wire.resize(84, 0);
        for offset in [40_usize, 64] {
            wire.get_mut(offset..offset.saturating_add(4))
                .ok_or("type slot")?
                .copy_from_slice(&0xffff_ff76_u32.to_le_bytes());
        }
        let mut signing = Hmac::<Md5>::new_from_slice(&key)?;
        signing.update(b"signaturekey\0");
        let signing_key = signing.finalize().into_bytes();
        let mut digest = Md5::new();
        digest.update(17_u32.to_le_bytes());
        digest.update(&wire);
        let mut signature = Hmac::<Md5>::new_from_slice(&signing_key)?;
        signature.update(&digest.finalize());
        wire.get_mut(44..60)
            .ok_or("signature slot")?
            .copy_from_slice(&signature.finalize().into_bytes());
        let service_key = EncryptionKey::new(23, key.to_vec());
        // When the real container parser and server verifier process the signed PAC.
        let pac = Pac::parse_and_process(&wire)?;
        let verified = pac.verify_server_checksum(&service_key)?;
        // Then the signature verifies, and a wire signature mutation does not.
        assert!(verified, "independent RC4 PAC signature rejected");
        *wire.get_mut(44).ok_or("signature byte")? ^= 1;
        assert!(
            !Pac::parse_and_process(&wire)?.verify_server_checksum(&service_key)?,
            "tampered signature accepted"
        );
        Ok(())
    }
}
