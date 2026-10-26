//! AES tests: SHA-1 and SHA-2 AES etypes against the gokrb5 and RFC 3962 vectors.

#[expect(
    clippy::missing_const_for_fn,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
/// Returns the 5-byte key-derivation constant: the big-endian `usage` followed by `suffix`.
fn usage_constant(usage: u32, suffix: u8) -> [u8; 5] {
    let [byte0, byte1, byte2, byte3] = usage.to_be_bytes();
    [byte0, byte1, byte2, byte3, suffix]
}

/// AES tests.
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
    use rskrb5_ng::crypto::{
        AesSha1Etype, AesSha2Etype, Error, KerberosEtype, Rc4HmacEtype, iterations_to_s2kparams,
        nfold, s2kparams_to_iterations,
    };

    use super::usage_constant;

    /// Error type of the `Result`-returning tests.
    type TestError = Box<dyn error::Error>;

    /// An AES-SHA1 string-to-key vector.
    struct StringToKeyVector<'vector> {
        /// PBKDF2 iteration count.
        iterations: u32,
        /// Password bytes.
        phrase: &'vector [u8],
        /// Salt bytes.
        salt: &'vector [u8],
        /// Expected PBKDF2 output, hex.
        pbkdf2: &'vector str,
        /// Expected key, hex.
        key: &'vector str,
    }

    /// An AES-SHA2 string-to-key vector.
    struct Sha2StringToKeyVector<'vector> {
        /// The etype under test.
        etype: AesSha2Etype,
        /// PBKDF2 iteration count.
        iterations: u32,
        /// Password bytes.
        phrase: &'vector [u8],
        /// Salt bytes.
        salt: &'vector [u8],
        /// Expected salt-with-enctype-name (`saltp`), hex.
        saltp: &'vector str,
        /// Expected key, hex.
        key: &'vector str,
    }

    /// An AES-SHA2 raw-data and message encryption vector.
    struct Sha2CryptoVector<'vector> {
        /// Plaintext, hex.
        plain: &'vector str,
        /// Confounder, hex.
        confounder: &'vector str,
        /// Encryption key `Ke`, hex.
        ke: &'vector str,
        /// Expected raw ciphertext of confounder and plaintext, hex.
        encrypted: &'vector str,
        /// Expected message ciphertext including the checksum, hex.
        cipher: &'vector str,
    }

    /// An AES-CTS vector from RFC 3962.
    struct AesCtsVector<'vector> {
        /// Plaintext, hex.
        plain: &'vector str,
        /// Expected ciphertext, hex.
        cipher: &'vector str,
        /// Expected next initialization vector, hex.
        next_iv: &'vector str,
    }

    /// Pins the AES-SHA1 etype metadata.
    #[test]
    fn reports_aes_sha1_metadata() {
        assert_eq!(AesSha1Etype::from_etype_id(17), Some(AesSha1Etype::Aes128));
        assert_eq!(AesSha1Etype::from_etype_id(18), Some(AesSha1Etype::Aes256));
        assert_eq!(AesSha1Etype::from_etype_id(23), None);

        assert_eq!(AesSha1Etype::Aes128.etype_id(), 17_i32);
        assert_eq!(AesSha1Etype::Aes128.checksum_type_id(), 15_i32);
        assert_eq!(AesSha1Etype::Aes128.key_len(), 16_usize);
        assert_eq!(AesSha1Etype::Aes128.confounder_len(), 16_usize);
        assert_eq!(AesSha1Etype::Aes128.hmac_len(), 12_usize);
        assert_eq!(AesSha1Etype::Aes128.default_s2kparams(), "00001000");

        assert_eq!(AesSha1Etype::Aes256.etype_id(), 18_i32);
        assert_eq!(AesSha1Etype::Aes256.checksum_type_id(), 16_i32);
        assert_eq!(AesSha1Etype::Aes256.key_len(), 32_usize);
        assert_eq!(AesSha1Etype::Aes256.default_s2kparams(), "00001000");
    }

    /// Pins the AES-SHA2 etype metadata and the dispatch of every AES etype through `KerberosEtype`.
    #[test]
    fn reports_aes_sha2_metadata_and_dispatch() {
        assert_eq!(AesSha2Etype::from_etype_id(19), Some(AesSha2Etype::Aes128));
        assert_eq!(AesSha2Etype::from_etype_id(20), Some(AesSha2Etype::Aes256));
        assert_eq!(AesSha2Etype::from_etype_id(18), None);

        assert_eq!(AesSha2Etype::Aes128.etype_id(), 19_i32);
        assert_eq!(AesSha2Etype::Aes128.checksum_type_id(), 19_i32);
        assert_eq!(AesSha2Etype::Aes128.ename(), "aes128-cts-hmac-sha256-128");
        assert_eq!(AesSha2Etype::Aes128.key_len(), 16_usize);
        assert_eq!(AesSha2Etype::Aes128.confounder_len(), 16_usize);
        assert_eq!(AesSha2Etype::Aes128.hmac_len(), 16_usize);
        assert_eq!(AesSha2Etype::Aes128.default_s2kparams(), "00008000");

        assert_eq!(AesSha2Etype::Aes256.etype_id(), 20_i32);
        assert_eq!(AesSha2Etype::Aes256.checksum_type_id(), 20_i32);
        assert_eq!(AesSha2Etype::Aes256.ename(), "aes256-cts-hmac-sha384-192");
        assert_eq!(AesSha2Etype::Aes256.key_len(), 32_usize);
        assert_eq!(AesSha2Etype::Aes256.hmac_len(), 24_usize);
        assert_eq!(AesSha2Etype::Aes256.default_s2kparams(), "00008000");

        assert_eq!(
            KerberosEtype::from_etype_id(17),
            Some(KerberosEtype::Sha1(AesSha1Etype::Aes128))
        );
        assert_eq!(
            KerberosEtype::from_etype_id(20),
            Some(KerberosEtype::Sha2(AesSha2Etype::Aes256))
        );
        assert_eq!(
            KerberosEtype::from_checksum_type_id(19),
            Some(KerberosEtype::Sha2(AesSha2Etype::Aes128))
        );
        assert_eq!(
            KerberosEtype::from_etype_id(23),
            Some(KerberosEtype::Rc4Hmac(Rc4HmacEtype::new()))
        );

        assert_eq!(KerberosEtype::Sha1(AesSha1Etype::Aes256).etype_id(), 18_i32);
    }

    /// Pins the conversion between iteration counts and s2kparams, and its rejections.
    #[test]
    fn converts_s2kparams_iteration_counts() {
        assert_eq!(iterations_to_s2kparams(1), "00000001");
        assert_eq!(iterations_to_s2kparams(4096), "00001000");
        assert_eq!(s2kparams_to_iterations("00001000"), Ok(4096));

        assert!(
            matches!(
                s2kparams_to_iterations("001000"),
                Err(Error::InvalidS2kParamsLength(6))
            ),
            "short s2kparams are rejected"
        );
        assert!(
            matches!(
                s2kparams_to_iterations("0000000z"),
                Err(Error::InvalidS2kParamsHex('z'))
            ),
            "non-hex s2kparams are rejected"
        );
        assert!(
            matches!(
                s2kparams_to_iterations("00000000"),
                Err(Error::UnsupportedIterationCountZero)
            ),
            "a zero iteration count is rejected"
        );
    }

    /// Pins n-fold against the gokrb5 vectors.
    #[test]
    fn nfold_matches_gokrb5_vectors() -> Result<(), TestError> {
        let tests = [
            (64_usize, b"012345".as_slice(), "be072631276b1955"),
            (56, b"password".as_slice(), "78a07b6caf85fa"),
            (
                64,
                b"Rough Consensus, and Running Code".as_slice(),
                "bb6ed30870b7f0e0",
            ),
            (
                168,
                b"password".as_slice(),
                "59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e",
            ),
            (
                192,
                b"MASSACHVSETTS INSTITVTE OF TECHNOLOGY".as_slice(),
                "db3b0d8f0b061e603282b308a50841229ad798fab9540c1b",
            ),
            (
                168,
                b"Q".as_slice(),
                "518a54a215a8452a518a54a215a8452a518a54a215",
            ),
            (
                168,
                b"ba".as_slice(),
                "fb25d531ae8974499f52fd92ea9857c4ba24cf297e",
            ),
        ];

        for (bits, input, expected) in tests {
            assert_eq!(hex::encode(nfold(input, bits)?), expected);
        }
        Ok(())
    }

    /// Pins AES128-SHA1 PBKDF2 and string-to-key against the gokrb5 vectors.
    #[test]
    fn aes128_string_to_key_matches_gokrb5_vectors() -> Result<(), TestError> {
        let binary_salt = hex::decode("1234567878563412")?;
        let musical_symbol = hex::decode("f09d849e")?;
        let tests = [
            StringToKeyVector {
                iterations: 1,
                phrase: b"password".as_slice(),
                salt: b"ATHENA.MIT.EDUraeburn".as_slice(),
                pbkdf2: "cdedb5281bb2f801565a1122b2563515",
                key: "42263c6e89f4fc28b8df68ee09799f15",
            },
            StringToKeyVector {
                iterations: 2,
                phrase: b"password".as_slice(),
                salt: b"ATHENA.MIT.EDUraeburn".as_slice(),
                pbkdf2: "01dbee7f4a9e243e988b62c73cda935d",
                key: "c651bf29e2300ac27fa469d693bdda13",
            },
            StringToKeyVector {
                iterations: 1200,
                phrase: b"password".as_slice(),
                salt: b"ATHENA.MIT.EDUraeburn".as_slice(),
                pbkdf2: "5c08eb61fdf71e4e4ec3cf6ba1f5512b",
                key: "4c01cd46d632d01e6dbe230a01ed642a",
            },
            StringToKeyVector {
                iterations: 5,
                phrase: b"password".as_slice(),
                salt: binary_salt.as_slice(),
                pbkdf2: "d1daa78615f287e6a1c8b120d7062a49",
                key: "e9b23d52273747dd5c35cb55be619d8e",
            },
            StringToKeyVector {
                iterations: 1200,
                phrase: b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
                    .as_slice(),
                salt: b"pass phrase equals block size".as_slice(),
                pbkdf2: "139c30c0966bc32ba55fdbf212530ac9",
                key: "59d1bb789a828b1aa54ef9c2883f69ed",
            },
            StringToKeyVector {
                iterations: 1200,
                phrase: b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
                    .as_slice(),
                salt: b"pass phrase exceeds block size".as_slice(),
                pbkdf2: "9ccad6d468770cd51b10e6a68721be61",
                key: "cb8005dc5f90179a7f02104c0018751d",
            },
            StringToKeyVector {
                iterations: 50,
                phrase: musical_symbol.as_slice(),
                salt: b"EXAMPLE.COMpianist".as_slice(),
                pbkdf2: "6b9cf26d45455a43a5b8bb276a403b39",
                key: "f149c1f2e154a73452d43e7fe62a56e5",
            },
        ];

        assert_string_to_key_vectors(AesSha1Etype::Aes128, &tests)
    }

    /// Pins AES256-SHA1 PBKDF2 and string-to-key against the gokrb5 vectors.
    #[test]
    fn aes256_string_to_key_matches_gokrb5_vectors() -> Result<(), TestError> {
        let binary_salt = hex::decode("1234567878563412")?;
        let musical_symbol = hex::decode("f09d849e")?;
        let tests = [
            StringToKeyVector {
                iterations: 1,
                phrase: b"password".as_slice(),
                salt: b"ATHENA.MIT.EDUraeburn".as_slice(),
                pbkdf2: "cdedb5281bb2f801565a1122b25635150ad1f7a04bb9f3a333ecc0e2e1f70837",
                key: "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161",
            },
            StringToKeyVector {
                iterations: 2,
                phrase: b"password".as_slice(),
                salt: b"ATHENA.MIT.EDUraeburn".as_slice(),
                pbkdf2: "01dbee7f4a9e243e988b62c73cda935da05378b93244ec8f48a99e61ad799d86",
                key: "a2e16d16b36069c135d5e9d2e25f896102685618b95914b467c67622225824ff",
            },
            StringToKeyVector {
                iterations: 1200,
                phrase: b"password".as_slice(),
                salt: b"ATHENA.MIT.EDUraeburn".as_slice(),
                pbkdf2: "5c08eb61fdf71e4e4ec3cf6ba1f5512ba7e52ddbc5e5142f708a31e2e62b1e13",
                key: "55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a",
            },
            StringToKeyVector {
                iterations: 5,
                phrase: b"password".as_slice(),
                salt: binary_salt.as_slice(),
                pbkdf2: "d1daa78615f287e6a1c8b120d7062a493f98d203e6be49a6adf4fa574b6e64ee",
                key: "97a4e786be20d81a382d5ebc96d5909cabcdadc87ca48f574504159f16c36e31",
            },
            StringToKeyVector {
                iterations: 1200,
                phrase: b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
                    .as_slice(),
                salt: b"pass phrase equals block size".as_slice(),
                pbkdf2: "139c30c0966bc32ba55fdbf212530ac9c5ec59f1a452f5cc9ad940fea0598ed1",
                key: "89adee3608db8bc71f1bfbfe459486b05618b70cbae22092534e56c553ba4b34",
            },
            StringToKeyVector {
                iterations: 1200,
                phrase: b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
                    .as_slice(),
                salt: b"pass phrase exceeds block size".as_slice(),
                pbkdf2: "9ccad6d468770cd51b10e6a68721be611a8b4d282601db3b36be9246915ec82a",
                key: "d78c5c9cb872a8c9dad4697f0bb5b2d21496c82beb2caeda2112fceea057401b",
            },
            StringToKeyVector {
                iterations: 50,
                phrase: musical_symbol.as_slice(),
                salt: b"EXAMPLE.COMpianist".as_slice(),
                pbkdf2: "6b9cf26d45455a43a5b8bb276a403b39e7fe37a0c41e02c281ff3069e1e94f52",
                key: "4b6d9839f84406df1f09cc166db4b83c571848b784a3d6bdc346589a3e393f9e",
            },
        ];

        assert_string_to_key_vectors(AesSha1Etype::Aes256, &tests)
    }

    /// Pins AES-SHA2 saltp and string-to-key against the gokrb5 vectors.
    #[test]
    fn aes_sha2_string_to_key_matches_gokrb5_vectors() -> Result<(), TestError> {
        let random = hex::decode("10df9dd783e5bc8acea1730e74355f61")?;
        let mut salt = random;
        salt.extend_from_slice(b"ATHENA.MIT.EDUraeburn");

        let tests = [
            Sha2StringToKeyVector {
                etype: AesSha2Etype::Aes128,
                iterations: 0x8000,
                phrase: b"password".as_slice(),
                salt: salt.as_slice(),
                saltp: "6165733132382d6374732d686d61632d7368613235362d3132380010df9dd783e5bc8acea1730e74355f61415448454e412e4d49542e4544557261656275726e",
                key: "089bca48b105ea6ea77ca5d2f39dc5e7",
            },
            Sha2StringToKeyVector {
                etype: AesSha2Etype::Aes256,
                iterations: 0x8000,
                phrase: b"password".as_slice(),
                salt: salt.as_slice(),
                saltp: "6165733235362d6374732d686d61632d7368613338342d3139320010df9dd783e5bc8acea1730e74355f61415448454e412e4d49542e4544557261656275726e",
                key: "45bd806dbf6a833a9cffc1c94589a222367a79bc21c413718906e9f578a78467",
            },
        ];

        for test in tests {
            assert_eq!(hex::encode(test.etype.saltp(test.salt)), test.saltp);
            let key = test.etype.string_to_key(
                test.phrase,
                test.salt,
                &iterations_to_s2kparams(test.iterations),
            )?;
            assert_eq!(hex::encode(&key), test.key);
        }
        Ok(())
    }

    /// Pins AES128-SHA2 key derivation, checksum and encryption against the gokrb5 vectors.
    #[test]
    fn aes128_sha2_derive_checksum_integrity_and_crypto_match_gokrb5_vectors()
    -> Result<(), TestError> {
        assert_sha2_derive_vectors(
            AesSha2Etype::Aes128,
            "3705d96080c17728a0e800eab6e0d23c",
            "b31a018a48f54776f403e9a396325dc3",
            "9b197dd1e8c5609d6e67c3e37c62c72e",
            "9fda0e56ab2d85e1569a688696c26a6c",
        )?;
        assert_sha2_checksum_vector(
            AesSha2Etype::Aes128,
            "3705d96080c17728a0e800eab6e0d23c",
            "000102030405060708090a0b0c0d0e0f1011121314",
            "d78367186643d67b411cba9139fc1dee",
        )?;
        assert_sha2_crypto_vectors(
            AesSha2Etype::Aes128,
            "3705d96080c17728a0e800eab6e0d23c",
            &[
                Sha2CryptoVector {
                    plain: "",
                    confounder: "7e5895eaf2672435bad817f545a37148",
                    ke: "9b197dd1e8c5609d6e67c3e37c62c72e",
                    encrypted: "ef85fb890bb8472f4dab20394dca781d",
                    cipher: "ef85fb890bb8472f4dab20394dca781dad877eda39d50c870c0d5a0a8e48c718",
                },
                Sha2CryptoVector {
                    plain: "000102030405",
                    confounder: "7bca285e2fd4130fb55b1a5c83bc5b24",
                    ke: "9b197dd1e8c5609d6e67c3e37c62c72e",
                    encrypted: "84d7f30754ed987bab0bf3506beb09cfb55402cef7e6",
                    cipher: "84d7f30754ed987bab0bf3506beb09cfb55402cef7e6877ce99e247e52d16ed4421dfdf8976c",
                },
                Sha2CryptoVector {
                    plain: "000102030405060708090a0b0c0d0e0f",
                    confounder: "56ab21713ff62c0a1457200f6fa9948f",
                    ke: "9b197dd1e8c5609d6e67c3e37c62c72e",
                    encrypted: "3517d640f50ddc8ad3628722b3569d2ae07493fa8263254080ea65c1008e8fc2",
                    cipher: "3517d640f50ddc8ad3628722b3569d2ae07493fa8263254080ea65c1008e8fc295fb4852e7d83e1e7c48c37eebe6b0d3",
                },
                Sha2CryptoVector {
                    plain: "000102030405060708090a0b0c0d0e0f1011121314",
                    confounder: "a7a4e29a4728ce10664fb64e49ad3fac",
                    ke: "9b197dd1e8c5609d6e67c3e37c62c72e",
                    encrypted: "720f73b18d9859cd6ccb4346115cd336c70f58edc0c4437c5573544c31c813bce1e6d072c1",
                    cipher: "720f73b18d9859cd6ccb4346115cd336c70f58edc0c4437c5573544c31c813bce1e6d072c186b39a413c2f92ca9b8334a287ffcbfc",
                },
            ],
        )?;
        Ok(())
    }

    /// Pins AES256-SHA2 key derivation, checksum and encryption against the gokrb5 vectors.
    #[test]
    fn aes256_sha2_derive_checksum_integrity_and_crypto_match_gokrb5_vectors()
    -> Result<(), TestError> {
        assert_sha2_derive_vectors(
            AesSha2Etype::Aes256,
            "6d404d37faf79f9df0d33568d320669800eb4836472ea8a026d16b7182460c52",
            "ef5718be86cc84963d8bbb5031e9f5c4ba41f28faf69e73d",
            "56ab22bee63d82d7bc5227f6773f8ea7a5eb1c825160c38312980c442e5c7e49",
            "69b16514e3cd8e56b82010d5c73012b622c4d00ffc23ed1f",
        )?;
        assert_sha2_checksum_vector(
            AesSha2Etype::Aes256,
            "6d404d37faf79f9df0d33568d320669800eb4836472ea8a026d16b7182460c52",
            "000102030405060708090a0b0c0d0e0f1011121314",
            "45ee791567eefca37f4ac1e0222de80d43c3bfa06699672a",
        )?;
        assert_sha2_crypto_vectors(
            AesSha2Etype::Aes256,
            "6d404d37faf79f9df0d33568d320669800eb4836472ea8a026d16b7182460c52",
            &[
                Sha2CryptoVector {
                    plain: "",
                    confounder: "f764e9fa15c276478b2c7d0c4e5f58e4",
                    ke: "56ab22bee63d82d7bc5227f6773f8ea7a5eb1c825160c38312980c442e5c7e49",
                    encrypted: "41f53fa5bfe7026d91faf9be959195a0",
                    cipher: "41f53fa5bfe7026d91faf9be959195a058707273a96a40f0a01960621ac612748b9bbfbe7eb4ce3c",
                },
                Sha2CryptoVector {
                    plain: "000102030405",
                    confounder: "b80d3251c1f6471494256ffe712d0b9a",
                    ke: "56ab22bee63d82d7bc5227f6773f8ea7a5eb1c825160c38312980c442e5c7e49",
                    encrypted: "4ed7b37c2bcac8f74f23c1cf07e62bc7b75fb3f637b9",
                    cipher: "4ed7b37c2bcac8f74f23c1cf07e62bc7b75fb3f637b9f559c7f664f69eab7b6092237526ea0d1f61cb20d69d10f2",
                },
                Sha2CryptoVector {
                    plain: "000102030405060708090a0b0c0d0e0f",
                    confounder: "53bf8a0d105265d4e276428624ce5e63",
                    ke: "56ab22bee63d82d7bc5227f6773f8ea7a5eb1c825160c38312980c442e5c7e49",
                    encrypted: "bc47ffec7998eb91e8115cf8d19dac4bbbe2e163e87dd37f49beca92027764f6",
                    cipher: "bc47ffec7998eb91e8115cf8d19dac4bbbe2e163e87dd37f49beca92027764f68cf51f14d798c2273f35df574d1f932e40c4ff255b36a266",
                },
                Sha2CryptoVector {
                    plain: "000102030405060708090a0b0c0d0e0f1011121314",
                    confounder: "763e65367e864f02f55153c7e3b58af1",
                    ke: "56ab22bee63d82d7bc5227f6773f8ea7a5eb1c825160c38312980c442e5c7e49",
                    encrypted: "40013e2df58e8751957d2878bcd2d6fe101ccfd556cb1eae79db3c3ee86429f2b2a602ac86",
                    cipher: "40013e2df58e8751957d2878bcd2d6fe101ccfd556cb1eae79db3c3ee86429f2b2a602ac86fef6ecb647d6295fae077a1feb517508d2c16b4192e01f62",
                },
            ],
        )?;
        Ok(())
    }

    /// Pins AES-CTS encryption and decryption against the RFC 3962 vectors.
    #[test]
    fn aes_cts_encrypts_and_decrypts_rfc3962_vectors() -> Result<(), TestError> {
        let key = hex::decode("636869636b656e207465726979616b69")?;
        let tests = [
            AesCtsVector {
                plain: "4920776f756c64206c696b652074686520",
                cipher: "c6353568f2bf8cb4d8a580362da7ff7f97",
                next_iv: "c6353568f2bf8cb4d8a580362da7ff7f",
            },
            AesCtsVector {
                plain: "4920776f756c64206c696b65207468652047656e6572616c20476175277320",
                cipher: "fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5",
                next_iv: "fc00783e0efdb2c1d445d4c8eff7ed22",
            },
            AesCtsVector {
                plain: "4920776f756c64206c696b65207468652047656e6572616c2047617527732043",
                cipher: "39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584",
                next_iv: "39312523a78662d5be7fcbcc98ebf5a8",
            },
            AesCtsVector {
                plain: "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c",
                cipher: "97687268d6ecccc0c07b25e25ecfe584b3fffd940c16a18c1b5549d2f838029e39312523a78662d5be7fcbcc98ebf5",
                next_iv: "b3fffd940c16a18c1b5549d2f838029e",
            },
            AesCtsVector {
                plain: "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c20",
                cipher: "97687268d6ecccc0c07b25e25ecfe5849dad8bbb96c4cdc03bc103e1a194bbd839312523a78662d5be7fcbcc98ebf5a8",
                next_iv: "9dad8bbb96c4cdc03bc103e1a194bbd8",
            },
            AesCtsVector {
                plain: "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c20616e6420776f6e746f6e20736f75702e",
                cipher: "97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a84807efe836ee89a526730dbc2f7bc8409dad8bbb96c4cdc03bc103e1a194bbd8",
                next_iv: "4807efe836ee89a526730dbc2f7bc840",
            },
        ];

        for test in tests {
            let plain = hex::decode(test.plain)?;
            let (next_iv, cipher) = AesSha1Etype::Aes128.encrypt_data(&key, &plain)?;
            assert_eq!(hex::encode(&cipher), test.cipher);
            assert_eq!(hex::encode(&next_iv), test.next_iv);

            let decrypted = AesSha1Etype::Aes128.decrypt_data(&key, &cipher)?;
            assert_eq!(decrypted, plain);
        }
        Ok(())
    }

    /// Pins the AES128-SHA1 checksum and message encryption against the gokrb5 vectors.
    #[test]
    fn checksums_and_messages_match_gokrb5_aes128() -> Result<(), TestError> {
        assert_checksum_and_message_vector(
            AesSha1Etype::Aes128,
            "42263c6e89f4fc28b8df68ee09799f15",
            "2b8e69736fe39ecdf288436e",
            "57269a6fb1a2e5d4fc8d9749767e7d75f4d31ac8b66531ebf1f81ad3f7fb1cc7fd0311164f604577ae6aa6b22c79ac59ca7e",
        )?;
        Ok(())
    }

    /// Pins the AES256-SHA1 checksum and message encryption against the gokrb5 vectors.
    #[test]
    fn checksums_and_messages_match_gokrb5_aes256() -> Result<(), TestError> {
        assert_checksum_and_message_vector(
            AesSha1Etype::Aes256,
            "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161",
            "eff61bf5eb38bc0ea3c18200",
            "c4408e3c7e212d5f11805303ebd1f356d64a289ce228bfd159e34294fb4448204512c3757ae2bd207cd0adbcc44ed0e6ef47",
        )?;
        Ok(())
    }

    /// Pins that AES rejects bad key, plaintext, ciphertext and confounder lengths.
    #[test]
    fn rejects_invalid_crypto_inputs() {
        assert!(
            matches!(
                AesSha1Etype::Aes128.encrypt_data(&[0_u8; 15], b"x"),
                Err(Error::InvalidKeyLength {
                    expected: 16,
                    actual: 15
                })
            ),
            "short key is rejected"
        );
        assert!(
            matches!(
                AesSha1Etype::Aes128.encrypt_data(&[0_u8; 16], b""),
                Err(Error::EmptyPlaintext)
            ),
            "empty plaintext is rejected"
        );
        assert!(
            matches!(
                AesSha1Etype::Aes128.decrypt_data(&[0_u8; 16], &[0_u8; 15]),
                Err(Error::CiphertextTooShort {
                    minimum: 16,
                    actual: 15
                })
            ),
            "short ciphertext is rejected"
        );
        assert!(
            matches!(
                AesSha1Etype::Aes128.encrypt_message_with_confounder(
                    &[0_u8; 16],
                    b"x",
                    1,
                    &[0_u8; 15]
                ),
                Err(Error::InvalidConfounderLength {
                    expected: 16,
                    actual: 15
                })
            ),
            "short confounder is rejected"
        );
    }

    /// Asserts AES-SHA1 PBKDF2 and string-to-key outputs for every vector.
    fn assert_string_to_key_vectors(
        etype: AesSha1Etype,
        tests: &[StringToKeyVector<'_>],
    ) -> Result<(), TestError> {
        for test in tests {
            let pbkdf2 = etype.string_to_pbkdf2(test.phrase, test.salt, test.iterations);
            assert_eq!(hex::encode(&pbkdf2), test.pbkdf2);

            let s2kparams = iterations_to_s2kparams(test.iterations);
            let key = etype.string_to_key(test.phrase, test.salt, &s2kparams)?;
            assert_eq!(hex::encode(&key), test.key);
        }
        Ok(())
    }

    /// Asserts the AES-SHA2 `Kc`, `Ke` and `Ki` keys derived from `key_hex` with usage 2.
    fn assert_sha2_derive_vectors(
        etype: AesSha2Etype,
        key_hex: &str,
        checksum_key_hex: &str,
        encryption_key_hex: &str,
        integrity_key_hex: &str,
    ) -> Result<(), TestError> {
        let key = hex::decode(key_hex)?;
        assert_eq!(
            hex::encode(etype.derive_key(&key, &usage_constant(2, 0x99))?),
            checksum_key_hex
        );
        assert_eq!(
            hex::encode(etype.derive_key(&key, &usage_constant(2, 0xaa))?),
            encryption_key_hex
        );
        assert_eq!(
            hex::encode(etype.derive_key(&key, &usage_constant(2, 0x55))?),
            integrity_key_hex
        );
        Ok(())
    }

    /// Asserts an AES-SHA2 checksum with usage 2 and its verification.
    fn assert_sha2_checksum_vector(
        etype: AesSha2Etype,
        key_hex: &str,
        data_hex: &str,
        checksum_hex: &str,
    ) -> Result<(), TestError> {
        let key = hex::decode(key_hex)?;
        let data = hex::decode(data_hex)?;
        let checksum = etype.checksum(&key, &data, 2)?;
        assert_eq!(hex::encode(&checksum), checksum_hex);
        assert!(
            etype.verify_checksum(&key, &data, &checksum, 2),
            "checksum verifies"
        );
        assert!(
            !etype.verify_checksum(&key, b"tampered", &checksum, 2),
            "checksum of tampered data does not verify"
        );
        Ok(())
    }

    /// Asserts AES-SHA2 raw-data and message encryption with usage 2, and tamper detection, for every vector.
    fn assert_sha2_crypto_vectors(
        etype: AesSha2Etype,
        key_hex: &str,
        tests: &[Sha2CryptoVector<'_>],
    ) -> Result<(), TestError> {
        let key = hex::decode(key_hex)?;

        for test in tests {
            let plain = hex::decode(test.plain)?;
            let confounder = hex::decode(test.confounder)?;
            let encryption_key = hex::decode(test.ke)?;

            let mut raw_plain = confounder.clone();
            raw_plain.extend_from_slice(&plain);
            let (_, encrypted) = etype.encrypt_data(&encryption_key, &raw_plain)?;
            assert_eq!(hex::encode(&encrypted), test.encrypted);
            assert_eq!(etype.decrypt_data(&encryption_key, &encrypted)?, raw_plain);

            let cipher = etype.encrypt_message_with_confounder(&key, &plain, 2, &confounder)?;
            assert_eq!(hex::encode(&cipher), test.cipher);
            assert_eq!(etype.decrypt_message(&key, &cipher, 2)?, plain);

            let mut tampered = cipher;
            *tampered.first_mut().ok_or("ciphertext is not empty")? ^= 0x01;
            assert!(
                matches!(
                    etype.decrypt_message(&key, &tampered, 2),
                    Err(Error::IntegrityCheckFailed)
                ),
                "tampered ciphertext fails the integrity check"
            );
        }
        Ok(())
    }

    /// Asserts an AES-SHA1 checksum and message encryption with usage 1027, and tamper detection.
    fn assert_checksum_and_message_vector(
        etype: AesSha1Etype,
        key_hex: &str,
        checksum_hex: &str,
        encrypted_hex: &str,
    ) -> Result<(), TestError> {
        let usage = 1027_u32;
        let key = hex::decode(key_hex)?;
        let confounder = hex::decode("000102030405060708090a0b0c0d0e0f")?;
        let checksum_data = b"gokrb5 checksum fixture";
        let message = b"gokrb5 message fixture";

        let checksum = etype.checksum(&key, checksum_data, usage)?;
        assert_eq!(hex::encode(&checksum), checksum_hex);
        assert!(
            etype.verify_checksum(&key, checksum_data, &checksum, usage),
            "checksum verifies"
        );
        assert!(
            !etype.verify_checksum(&key, b"tampered", &checksum, usage),
            "checksum of tampered data does not verify"
        );

        let encrypted = etype.encrypt_message_with_confounder(&key, message, usage, &confounder)?;
        assert_eq!(hex::encode(&encrypted), encrypted_hex);

        let decrypted = etype.decrypt_message(&key, &encrypted, usage)?;
        assert_eq!(decrypted, message);

        let mut tampered = encrypted;
        *tampered.first_mut().ok_or("ciphertext is not empty")? ^= 0x01;
        assert!(
            matches!(
                etype.decrypt_message(&key, &tampered, usage),
                Err(Error::IntegrityCheckFailed)
            ),
            "tampered ciphertext fails the integrity check"
        );
        Ok(())
    }
}
