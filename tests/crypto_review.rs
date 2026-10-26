//! Regression probes for cryptography review findings.

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
    use rskrb5_ng::{crypto::Rc4HmacEtype, error::Crypto};

    /// Regression test error.
    type TestError = Box<dyn Error>;

    /// High usage values use the RFC 4757 four-byte little-endian encoding.
    #[test]
    fn rc4_checksum_matches_independent_high_usage_oracle() -> Result<(), TestError> {
        // Given a fixed key and usages beyond the single-byte fixture range.
        let key = [0x42_u8; 16];
        let data = b"high usage checksum";
        for usage in [128_u32, 1027, 0x1000_0001, 0x2000_0001, u32::MAX] {
            let mut signing = Hmac::<Md5>::new_from_slice(&key)?;
            signing.update(b"signaturekey\0");
            let signing_key = signing.finalize().into_bytes();
            let mut digest = Md5::new();
            digest.update(usage.to_le_bytes());
            digest.update(data);
            let mut oracle = Hmac::<Md5>::new_from_slice(&signing_key)?;
            oracle.update(&digest.finalize());
            let expected = oracle.finalize().into_bytes();
            // When the public checksum primitive derives its usage key.
            let actual = Rc4HmacEtype::checksum(&key, data, usage)?;
            // Then it agrees with an independent RFC encoding.
            assert_eq!(actual.as_slice(), expected.as_slice());
        }
        Ok(())
    }

    /// Distinct upper usage bits must not authorize the same ciphertext.
    #[test]
    fn rc4_rejects_ciphertext_under_previously_colliding_usage() -> Result<(), TestError> {
        // Given a message encrypted for one high usage.
        let key = [0x42_u8; 16];
        let encrypted = Rc4HmacEtype::encrypt_message_with_confounder(
            &key,
            b"bound message",
            0x1000_0001,
            &[0x24_u8; 8],
        )?;
        // When another formerly colliding usage attempts decryption.
        let result = Rc4HmacEtype::decrypt_message(&key, &encrypted, 0x2000_0001);
        // Then integrity fails, rather than releasing the message.
        assert_eq!(result, Err(Crypto::IntegrityCheckFailed));
        assert_eq!(
            Rc4HmacEtype::decrypt_message(&key, &encrypted, 0x1000_0001)?,
            b"bound message"
        );
        Ok(())
    }
}
