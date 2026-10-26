//! RC4-HMAC tests: metadata, dispatch and the gokrb5 string-to-key, checksum and encryption vectors.

/// RC4-HMAC tests.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error;

    use pretty_assertions::assert_eq;
    use rskrb5_ng::crypto::{Error, KerberosEtype, Rc4HmacEtype};

    /// Error type of the `Result`-returning tests.
    type TestError = Box<dyn error::Error>;

    /// Pins the RC4-HMAC etype metadata and its dispatch through `KerberosEtype`.
    #[test]
    fn reports_rc4_hmac_metadata_and_dispatch() {
        let etype = Rc4HmacEtype;

        assert_eq!(Rc4HmacEtype::from_etype_id(23), Some(Rc4HmacEtype));
        assert_eq!(Rc4HmacEtype::from_etype_id(24), None);
        assert_eq!(
            Rc4HmacEtype::from_checksum_type_id(-138),
            Some(Rc4HmacEtype)
        );

        assert_eq!(etype.etype_id(), 23_i32);
        assert_eq!(etype.checksum_type_id(), -138_i32);
        assert_eq!(etype.key_len(), 16);
        assert_eq!(etype.confounder_len(), 8);
        assert_eq!(etype.hmac_len(), 16);
        assert_eq!(etype.default_s2kparams(), "");

        assert_eq!(
            KerberosEtype::from_etype_id(23),
            Some(KerberosEtype::Rc4Hmac(Rc4HmacEtype))
        );
        assert_eq!(
            KerberosEtype::from_checksum_type_id(-138),
            Some(KerberosEtype::Rc4Hmac(Rc4HmacEtype))
        );
    }

    /// Pins the RC4-HMAC string-to-key output against the gokrb5 vector.
    #[test]
    fn rc4_hmac_string_to_key_matches_gokrb5_vector() -> Result<(), TestError> {
        let key = Rc4HmacEtype.string_to_key(b"foo", b"ignored-salt", "ignored-params")?;

        assert_eq!(hex::encode(&key), "ac8e657f83df82beea5d43bdaf7800cc");
        Ok(())
    }

    /// Pins the RC4-HMAC checksum against the gokrb5 vector, and its verification.
    #[test]
    fn rc4_hmac_checksum_matches_gokrb5_vector() -> Result<(), TestError> {
        let etype = Rc4HmacEtype;
        let key = hex::decode("ac8e657f83df82beea5d43bdaf7800cc")?;
        let checksum = etype.checksum(&key, b"kerberos rc4 checksum", 2)?;

        assert_eq!(hex::encode(&checksum), "97ab2d24a2a9746b2abb88e2df99578d");
        assert!(
            etype.verify_checksum(&key, b"kerberos rc4 checksum", &checksum, 2),
            "checksum verifies"
        );
        assert!(
            !etype.verify_checksum(&key, b"kerberos rc4 tampered", &checksum, 2),
            "checksum of tampered data does not verify"
        );
        Ok(())
    }

    /// Pins RC4-HMAC message encryption against the gokrb5 vector, and decryption directly and via dispatch.
    #[test]
    fn rc4_hmac_message_encryption_matches_gokrb5_vector() -> Result<(), TestError> {
        let etype = Rc4HmacEtype;
        let key = hex::decode("ac8e657f83df82beea5d43bdaf7800cc")?;
        let confounder = hex::decode("0001020304050607")?;
        let expected = hex::decode(
            "52b24c30a78833dc78994646b37f14108e7af6ecc788485cb4c3d8d536669996e6f2a7d46047ce81a766bab4",
        )?;

        let encrypted =
            etype.encrypt_message_with_confounder(&key, b"kerberos rc4 message", 2, &confounder)?;
        assert_eq!(encrypted, expected);

        let decrypted = etype.decrypt_message(&key, &encrypted, 2)?;
        assert_eq!(decrypted, b"kerberos rc4 message");

        let dispatcher = KerberosEtype::Rc4Hmac(Rc4HmacEtype);
        assert_eq!(
            dispatcher.decrypt_message(&key, &encrypted, 2)?,
            b"kerberos rc4 message"
        );
        Ok(())
    }

    /// Pins that RC4-HMAC rejects bad key, confounder and ciphertext lengths, a bad secret and tampering.
    #[test]
    fn rc4_hmac_rejects_invalid_inputs_and_tampering() -> Result<(), TestError> {
        let etype = Rc4HmacEtype;
        let key = hex::decode("ac8e657f83df82beea5d43bdaf7800cc")?;
        let confounder = hex::decode("0001020304050607")?;

        assert!(
            matches!(
                etype.encrypt_data(key.get(..15).ok_or("15-byte key prefix")?, b"data"),
                Err(Error::InvalidKeyLength {
                    expected: 16,
                    actual: 15
                })
            ),
            "short key is rejected"
        );
        assert!(
            matches!(
                etype.encrypt_message_with_confounder(
                    &key,
                    b"data",
                    2,
                    confounder.get(..7).ok_or("7-byte confounder prefix")?
                ),
                Err(Error::InvalidConfounderLength {
                    expected: 8,
                    actual: 7
                })
            ),
            "short confounder is rejected"
        );
        assert!(
            matches!(
                etype.decrypt_message(&key, &[0_u8; 23], 2),
                Err(Error::CiphertextTooShort {
                    minimum: 24,
                    actual: 23
                })
            ),
            "short ciphertext is rejected"
        );
        assert!(
            matches!(
                etype.string_to_key(&[0xff], b"", ""),
                Err(Error::InvalidStringToKeySecret)
            ),
            "non-UTF-8 secret is rejected"
        );

        let mut encrypted =
            etype.encrypt_message_with_confounder(&key, b"kerberos rc4 message", 2, &confounder)?;
        *encrypted.first_mut().ok_or("ciphertext is not empty")? ^= 1;
        assert_eq!(
            etype.decrypt_message(&key, &encrypted, 2),
            Err(Error::IntegrityCheckFailed)
        );
        Ok(())
    }
}
