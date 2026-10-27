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
    use rskrb5_ng::{
        crypto::{AesSha1Etype, AesSha2Etype, Rc4HmacEtype, s2kparams_to_iterations},
        error::Crypto,
    };
    use sha2::{Sha256, Sha384};

    /// Regression test error.
    type TestError = Box<dyn Error>;

    /// Peer iteration hints above the local work ceiling are rejected without deriving.
    #[test]
    fn s2kparams_rejects_excessive_iterations() {
        // Given counts above the inclusive 2^24 work ceiling.
        for params in ["01000001", "ffffffff"] {
            // When the peer's work factor is parsed.
            let result = s2kparams_to_iterations(params);
            // Then it is rejected before any PBKDF2 operation.
            assert!(
                matches!(
                    result,
                    Err(Crypto::IterationCountTooHigh {
                        maximum: 0x0100_0000,
                        actual: 0x0100_0001 | u32::MAX,
                    })
                ),
                "excessive peer work factor accepted"
            );
        }
    }

    /// The work ceiling is inclusive and preserves standard iteration counts.
    #[test]
    fn s2kparams_accepts_iteration_policy_boundaries() {
        // Given admissible boundary and default counts.
        for (params, count) in [
            ("00000001", 1),
            ("00001000", 4096),
            ("00008000", 0x8000),
            ("01000000", 0x0100_0000),
        ] {
            // When the count is parsed without deriving a password key.
            let actual = s2kparams_to_iterations(params);
            // Then the exact count is preserved, not silently clamped.
            assert_eq!(actual, Ok(count));
        }
    }

    /// All four AES string-to-key entry points reject excessive peer work factors.
    #[test]
    fn aes_password_derivation_rejects_excessive_iterations() {
        // Given a count just beyond the inclusive local ceiling.
        let expected = Err(Crypto::IterationCountTooHigh {
            maximum: 0x0100_0000,
            actual: 0x0100_0001,
        });
        // When each AES family derives a password key with that hint.
        let results = [
            AesSha1Etype::Aes128.string_to_key(b"password", b"salt", "01000001"),
            AesSha1Etype::Aes256.string_to_key(b"password", b"salt", "01000001"),
            AesSha2Etype::Aes128.string_to_key(b"password", b"salt", "01000001"),
            AesSha2Etype::Aes256.string_to_key(b"password", b"salt", "01000001"),
        ];
        // Then all reject rather than allocating and running PBKDF2.
        for result in results {
            assert_eq!(result, expected);
        }
    }

    /// The SHA-256 PRF accepts empty context as defined by RFC 8009 sections 3 and 5.
    #[test]
    fn sha256_prf_accepts_empty_context() -> Result<(), TestError> {
        // Given the Appendix A key and independent empty-context HMAC framing.
        let key = hex::decode("3705d96080c17728a0e800eab6e0d23c")?;
        let mut oracle = Hmac::<Sha256>::new_from_slice(&key)?;
        oracle.update(b"\x00\x00\x00\x01prf\x00\x00\x00\x01\x00");
        let expected = oracle.finalize().into_bytes();
        // When the public PRF processes an empty context.
        let actual = AesSha2Etype::Aes128.derive_random(&key, b"")?;
        // Then all output bytes match the independent oracle.
        assert_eq!(actual.as_slice(), expected.as_slice());
        Ok(())
    }

    /// The SHA-384 PRF accepts empty context as defined by RFC 8009 sections 3 and 5.
    #[test]
    fn sha384_prf_accepts_empty_context() -> Result<(), TestError> {
        // Given the Appendix A key and independent empty-context HMAC framing.
        let key = hex::decode("6d404d37faf79f9df0d33568d320669800eb4836472ea8a026d16b7182460c52")?;
        let mut oracle = Hmac::<Sha384>::new_from_slice(&key)?;
        oracle.update(b"\x00\x00\x00\x01prf\x00\x00\x00\x01\x80");
        let expected = oracle.finalize().into_bytes();
        // When the public PRF processes an empty context.
        let actual = AesSha2Etype::Aes256.derive_random(&key, b"")?;
        // Then all output bytes match the independent oracle.
        assert_eq!(actual.as_slice(), expected.as_slice());
        Ok(())
    }

    /// Published RFC 8009 Appendix A PRFs retain their nonempty-context outputs.
    #[test]
    fn sha2_prf_matches_published_nonempty_vectors() -> Result<(), TestError> {
        // Given published keys and outputs for context "test".
        for (etype, key, expected) in [
            (
                AesSha2Etype::Aes128,
                "3705d96080c17728a0e800eab6e0d23c",
                "9d188616f63852fe86915bb840b4a886ff3e6bb0f819b49b893393d393854295",
            ),
            (
                AesSha2Etype::Aes256,
                "6d404d37faf79f9df0d33568d320669800eb4836472ea8a026d16b7182460c52",
                "9801f69a368c2bf675e59521e177d9a07f67efe1cfde8d3c8d6f6a0256e3b17db3c1b62ad1b8553360d17367eb1514d2",
            ),
        ] {
            // When the public PRF processes the published context.
            let actual = etype.derive_random(&hex::decode(key)?, b"test")?;
            // Then it matches the RFC output exactly.
            assert_eq!(actual, hex::decode(expected)?);
        }
        Ok(())
    }

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
