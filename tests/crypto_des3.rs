//! Triple-DES (des3-cbc-sha1-kd) tests: metadata, dispatch and the gokrb5 key-derivation and crypto vectors.

/// Triple-DES tests.
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
    use rskrb5_ng::crypto::{Des3CbcSha1KdEtype, Error, KerberosEtype};

    /// Error type of the `Result`-returning tests.
    type TestError = Box<dyn error::Error>;

    /// A derive-random / derive-key vector.
    struct Des3DeriveVector {
        /// Base key, hex.
        key: &'static str,
        /// Usage constant, hex.
        usage: &'static str,
        /// Expected DR output, hex.
        dr: &'static str,
        /// Expected DK output, hex.
        dk: &'static str,
    }

    /// A string-to-key vector.
    struct Des3StringToKeyVector {
        /// Salt bytes.
        salt: &'static [u8],
        /// Password bytes.
        secret: &'static [u8],
        /// Expected key, hex.
        key: &'static str,
    }

    /// Pins the Triple-DES etype metadata and its dispatch through `KerberosEtype`.
    #[test]
    fn reports_des3_metadata_and_dispatch() {
        assert_eq!(
            Des3CbcSha1KdEtype::from_etype_id(16),
            Some(Des3CbcSha1KdEtype::new())
        );
        assert_eq!(Des3CbcSha1KdEtype::from_etype_id(7), None);
        assert_eq!(
            Des3CbcSha1KdEtype::from_checksum_type_id(12),
            Some(Des3CbcSha1KdEtype::new())
        );

        assert_eq!(Des3CbcSha1KdEtype::new().etype_id(), 16_i32);
        assert_eq!(Des3CbcSha1KdEtype::new().checksum_type_id(), 12_i32);
        assert_eq!(Des3CbcSha1KdEtype::new().key_len(), 24);
        assert_eq!(Des3CbcSha1KdEtype::new().confounder_len(), 8);
        assert_eq!(Des3CbcSha1KdEtype::new().hmac_len(), 20);
        assert_eq!(Des3CbcSha1KdEtype::new().default_s2kparams(), "");

        assert_eq!(
            KerberosEtype::from_etype_id(16),
            Some(KerberosEtype::Des3CbcSha1Kd(Des3CbcSha1KdEtype::new()))
        );
        assert_eq!(
            KerberosEtype::from_checksum_type_id(12),
            Some(KerberosEtype::Des3CbcSha1Kd(Des3CbcSha1KdEtype::new()))
        );
    }

    /// Pins Triple-DES derive-random and derive-key against the gokrb5 vectors.
    #[test]
    fn des3_derive_random_and_key_match_gokrb5_vectors() -> Result<(), TestError> {
        let etype = Des3CbcSha1KdEtype::new();
        let tests = [
            Des3DeriveVector {
                key: "dce06b1f64c857a11c3db57c51899b2cc1791008ce973b92",
                usage: "0000000155",
                dr: "935079d14490a75c3093c4a6e8c3b049c71e6ee705",
                dk: "925179d04591a79b5d3192c4a7e9c289b049c71f6ee604cd",
            },
            Des3DeriveVector {
                key: "5e13d31c70ef765746578531cb51c15bf11ca82c97cee9f2",
                usage: "00000001aa",
                dr: "9f58e5a047d894101c469845d67ae3c5249ed812f2",
                dk: "9e58e5a146d9942a101c469845d67a20e3c4259ed913f207",
            },
            Des3DeriveVector {
                key: "98e6fd8a04a4b6859b75a176540b9752bad3ecd610a252bc",
                usage: "0000000155",
                dr: "12fff90c773f956d13fc2ca0d0840349dbd39908eb",
                dk: "13fef80d763e94ec6d13fd2ca1d085070249dad39808eabf",
            },
            Des3DeriveVector {
                key: "622aec25a2fe2cad7094680b7c64940280084c1a7cec92b5",
                usage: "00000001aa",
                dr: "f8debf05b097e7dc0603686aca35d91fd9a5516a70",
                dk: "f8dfbf04b097e6d9dc0702686bcb3489d91fd9a4516b703e",
            },
            Des3DeriveVector {
                key: "d3f8298ccb166438dcb9b93ee5a7629286a491f838f802fb",
                usage: "6b65726265726f73",
                dr: "2270db565d2a3d64cfbfdc5305d4f778a6de42d9da",
                dk: "2370da575d2a3da864cebfdc5204d56df779a7df43d9da43",
            },
            Des3DeriveVector {
                key: "c1081649ada74362e6a1459d01dfd30d67c2234c940704da",
                usage: "0000000155",
                dr: "348056ec98fcc517171d2b4d7a9493af482d999175",
                dk: "348057ec98fdc48016161c2a4c7a943e92ae492c989175f7",
            },
            Des3DeriveVector {
                key: "5d154af238f46713155719d55e2f1f790dd661f279a7917c",
                usage: "00000001aa",
                dr: "a8818bc367dadacbe9a6c84627fb60c294b01215e5",
                dk: "a8808ac267dada3dcbe9a7c84626fbc761c294b01315e5c1",
            },
            Des3DeriveVector {
                key: "798562e049852f57dc8c343ba17f2ca1d97394efc8adc443",
                usage: "0000000155",
                dr: "c813f88b3be2b2f75424ce9175fbc8483b88c8713a",
                dk: "c813f88a3be3b334f75425ce9175fbe3c8493b89c8703b49",
            },
            Des3DeriveVector {
                key: "26dce334b545292f2feab9a8701a89a4b99eb9942cecd016",
                usage: "00000001aa",
                dr: "f58efc6f83f93e55e695fd252cf8fe59f7d5ba37ec",
                dk: "f48ffd6e83f83e7354e694fd252cf83bfe58f7d5ba37ec5d",
            },
        ];

        for vector in tests {
            let key = hex::decode(vector.key)?;
            let usage = hex::decode(vector.usage)?;

            assert_eq!(hex::encode(etype.derive_random(&key, &usage)?), vector.dr);
            assert_eq!(hex::encode(etype.derive_key(&key, &usage)?), vector.dk);
        }
        Ok(())
    }

    /// Pins Triple-DES string-to-key against the gokrb5 vectors.
    #[test]
    fn des3_string_to_key_matches_gokrb5_vectors() -> Result<(), TestError> {
        let etype = Des3CbcSha1KdEtype::new();
        let tests = [
            Des3StringToKeyVector {
                salt: b"ATHENA.MIT.EDUraeburn".as_slice(),
                secret: b"password".as_slice(),
                key: "850bb51358548cd05e86768c313e3bfef7511937dcf72c3e",
            },
            Des3StringToKeyVector {
                salt: b"WHITEHOUSE.GOVdanny".as_slice(),
                secret: b"potatoe".as_slice(),
                key: "dfcd233dd0a43204ea6dc437fb15e061b02979c1f74f377a",
            },
            Des3StringToKeyVector {
                salt: b"EXAMPLE.COMbuckaroo".as_slice(),
                secret: b"penny".as_slice(),
                key: "6d2fcdf2d6fbbc3ddcadb5da5710a23489b0d3b69d5d9d4a",
            },
            Des3StringToKeyVector {
                salt: "ATHENA.MIT.EDUJuri\u{0161}i\u{0107}".as_bytes(),
                secret: "\u{00df}".as_bytes(),
                key: "16d5a40e1ce3bacb61b9dce00470324c831973a7b952feb0",
            },
            Des3StringToKeyVector {
                salt: b"EXAMPLE.COMpianist".as_slice(),
                secret: "\u{1d11e}".as_bytes(),
                key: "85763726585dbc1cce6ec43e1f751f07f1c4cbb098f40b19",
            },
        ];

        for vector in tests {
            let key = etype.string_to_key(vector.secret, vector.salt, "")?;
            assert_eq!(hex::encode(&key), vector.key);
        }
        Ok(())
    }

    /// Pins the Triple-DES checksum and message encryption against the gokrb5 vectors.
    #[test]
    fn des3_checksum_and_message_encryption_match_gokrb5_vectors() -> Result<(), TestError> {
        let etype = Des3CbcSha1KdEtype::new();
        let key = hex::decode("850bb51358548cd05e86768c313e3bfef7511937dcf72c3e")?;
        let checksum = etype.checksum(&key, b"kerberos des3 checksum", 2)?;
        assert_eq!(
            hex::encode(&checksum),
            "f2d2ab0b54bd97a62daaedbb6d671ea2573ea961"
        );
        assert!(
            etype.verify_checksum(&key, b"kerberos des3 checksum", &checksum, 2),
            "checksum verifies"
        );
        assert!(
            !etype.verify_checksum(&key, b"kerberos des3 tampered", &checksum, 2),
            "checksum of tampered data does not verify"
        );

        let confounder = hex::decode("0001020304050607")?;
        let expected = hex::decode(
            "c18690ba486875c8df4e638ba41ec6ece9c3364e0ec411a8be30bb4b075ab1b6\
             c54450d1ea719792e1df15cdc2d74c7899cef236",
        )?;
        let encrypted = etype.encrypt_message_with_confounder(
            &key,
            b"kerberos des3 message",
            2,
            &confounder,
        )?;
        assert_eq!(encrypted, expected);

        let decrypted = etype.decrypt_message(&key, &encrypted, 2)?;
        assert_eq!(
            hex::encode(&decrypted),
            "6b65726265726f732064657333206d657373616765000000"
        );

        let dispatcher = KerberosEtype::Des3CbcSha1Kd(Des3CbcSha1KdEtype::new());
        assert_eq!(dispatcher.decrypt_message(&key, &encrypted, 2)?, decrypted);
        Ok(())
    }

    /// Pins that Triple-DES rejects bad parameters, seed, key, plaintext, ciphertext and confounder inputs and tampering.
    #[test]
    fn des3_rejects_invalid_inputs_and_tampering() -> Result<(), TestError> {
        let etype = Des3CbcSha1KdEtype::new();
        let key = hex::decode("850bb51358548cd05e86768c313e3bfef7511937dcf72c3e")?;
        let confounder = hex::decode("0001020304050607")?;

        assert_eq!(
            etype.string_to_key(b"password", b"salt", "00001000"),
            Err(Error::NonEmptyDes3S2kParams)
        );
        assert!(
            matches!(
                etype.random_to_key(&[0_u8; 20]),
                Err(Error::InvalidSeedLength {
                    expected: 21,
                    actual: 20
                })
            ),
            "short seed is rejected"
        );
        assert!(
            matches!(
                etype.encrypt_data(key.get(..23).ok_or("23-byte key prefix")?, b"data"),
                Err(Error::InvalidKeyLength {
                    expected: 24,
                    actual: 23
                })
            ),
            "short key is rejected"
        );
        assert_eq!(etype.encrypt_data(&key, b""), Err(Error::EmptyPlaintext));
        assert!(
            matches!(
                etype.decrypt_data(&key, &[0_u8; 7]),
                Err(Error::CiphertextTooShort {
                    minimum: 8,
                    actual: 7
                })
            ),
            "short ciphertext is rejected"
        );
        assert!(
            matches!(
                etype.decrypt_data(&key, &[0_u8; 9]),
                Err(Error::InvalidCiphertextBlockSize {
                    block_size: 8,
                    actual: 9
                })
            ),
            "partial ciphertext block is rejected"
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

        let mut encrypted = etype.encrypt_message_with_confounder(
            &key,
            b"kerberos des3 message",
            2,
            &confounder,
        )?;
        *encrypted.first_mut().ok_or("ciphertext is not empty")? ^= 1;
        assert_eq!(
            etype.decrypt_message(&key, &encrypted, 2),
            Err(Error::IntegrityCheckFailed)
        );
        Ok(())
    }
}
