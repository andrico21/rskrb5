//! Service AP-REQ validation, AP-REP, replay cache and keytab loading tests against the gokrb5 vectors.
#![cfg(feature = "messages")]

#[path = "support/context.rs"]
mod context;
#[path = "support/env.rs"]
mod env;
#[path = "support/pac_ad_win2k.rs"]
mod pac_ad_win2k;

/// Service acceptor tests.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::time::Duration;
    use std::{
        env::{temp_dir, var},
        fs,
        path::PathBuf,
        process,
        time::{SystemTime, UNIX_EPOCH},
    };

    use chrono::{DateTime, FixedOffset, Utc};
    use hex::FromHexError;
    use pretty_assertions::assert_eq;
    use rasn::der;
    use rskrb5_ng::{
        config::Config,
        crypto::{AesSha1Etype, Error as CryptoError},
        keytab::{EncryptionKey, Keytab},
        pac,
        service::{
            ApRepOptions, Error, Principal, ServiceValidator, SharedReplayCache, ValidatedApReq,
        },
        ticket::decrypt_ticket_enc_part,
    };

    use super::{
        context::{Context as _, TestError},
        env, pac_ad_win2k,
    };

    const HTTP_KEYTAB: &str = concat!(
        "0502000000440002000b544553542e474f4b5242350004485454500010686f73742e746573742e676f6b",
        "72623500000001590dc4dc010011001057a7754c70c4d85c155c718c2f1292b0000000540002000b",
        "544553542e474f4b5242350004485454500010686f73742e746573742e676f6b72623500000001590d",
        "c4dc01001200209cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51",
        "000000440002000b544553542e474f4b5242350004485454500010686f73742e746573742e676f6b",
        "72623500000001590dc4dc020011001057a7754c70c4d85c155c718c2f1292b0000000540002000b",
        "544553542e474f4b5242350004485454500010686f73742e746573742e676f6b72623500000001590d",
        "c4dc02001200209cad00bbc72d703258e911dc18e6d5487cf737bf67fd111f0c2463ad6033bf51",
    );

    const VALID_AP_REQ: &str = concat!(
        "6e8201f8308201f4a003020105a10302010ea20703050000000000a382012f6182012b30820127a0",
        "03020105a10d1b0b544553542e474f4b524235a2233021a003020101a11a30181b04485454501b",
        "10686f73742e746573742e676f6b726235a381eb3081e8a003020112a103020101a281db0481d8",
        "5e7242bdf5331825046b4692f2f850f62dedee984e72a490ac48fc3375f5bc1a50c07ff766338",
        "cbb1486cd8f9974b0865f3fd3ecb4e72b6dc556bb73a1cea8f4579983e625676b43854ff9910",
        "a0b60996f148ee1b6a49a1896d41afde6e82d2d8ed9f7304ac0ded7a74f88694dc69ab532",
        "ff51f5e7ba7fce87f4ba19885fc915e6d83f11f2152bd64f3fd63cb8b160148fed6fa9b01",
        "d86acd337d20c3b99622b166b6b283cd3704f36147972015c3a750ce9c855ae58ec598929ed",
        "953b4008dbad1ca6f0a715eb07ee19f5124ff7354ded3928fccd6cc7e8a481ab3081a8a0",
        "03020112a103020101a2819b04819882e028aad111ace518b36bd7305f9ff06545036b2214916",
        "00d07509d4e1bbcacb5a6bde72ec8812c2ef087cb64dcd905d7eba708d7a7c1a782e7bc",
        "cc3d46bfc503e5075bd6ca1d2f27b218ebb907483b6b0b8bac5137fa15fb59b1df434371",
        "e041c817d652e3068912e55203ec6ea5ce374a20e5b9b5ed9dfb6bdb06137b90b2db2a",
        "db192d415375581bdf9a2bfe73d19c13ba1d983bf513",
    );

    const VALID_SESSION_KEY: &str =
        "8845cbaccbf11cb9f467fd577ba51c70d73de6554980a05395bf319e18bdda07";
    const AP_REP_CONFOUNDER: &str = "000102030405060708090a0b0c0d0e0f";
    const PAC_TICKET_CONFOUNDER: &str = "101112131415161718191a1b1c1d1e1f";
    const PAC_AUTHENTICATOR_CONFOUNDER: &str = "202122232425262728292a2b2c2d2e2f";
    const KDC_REP_TICKET_USAGE_FOR_TEST: u32 = 2;
    const AP_REQ_AUTHENTICATOR_USAGE_FOR_TEST: u32 = 11;
    const AP_REP_SERVER_SUBKEY: &str =
        "00112233445566778899aabbccddeeff102132435465768798a9babbdcddfeff";
    const AP_REP_WITH_SUBKEY: &str = concat!(
        "6f818b308188a003020105a10302010fa27c307aa003020112a103020105a26e046c6943c730",
        "93314cc1980e95e3c8717dc2fe29c97f4305e55ac11912728f3b6c53f813e33f29188cc4b",
        "125596d747ac20c2d898c0a445ec50b12ec1c2870ac32b6fe2c0163de4b0c7c229cc63",
        "c80aa23a76914e6278f293a364dfaff666f374836bbd1209ceb97f9a17bd0fa2e",
    );

    const INVALID_TICKET_AP_REQ: &str = concat!(
        "6e8201f8308201f4a003020105a10302010ea20703050000000000a382012f6182012b30820127a0",
        "03020105a10d1b0b544553542e474f4b524235a2233021a003020101a11a30181b04485454501b",
        "10686f73742e746573742e676f6b726235a381eb3081e8a003020112a103020101a281db0481d8",
        "389cd5b96595d2d1d8cebc6963a1c8fbb223c4a94b76f1369f10bf9c87d63c5514ff7b",
        "bb00bd28dd9804b6899e36af95f79ab3b0d85501bff6dded727cb67ad5a748f2ad3367",
        "1ff930910cdefccbaa1e108450a3e4ff6f9f263daf1a24f3073ffd7c5130fb7a192999",
        "c35315b96d09659f4921d573a7806bc3b70adcb3c5842a6c66ea46b0351889e8ad1b",
        "9007c29ff594aaade18be2cc893914de43062699cc3a8c407e0f001c88c2472bbb10f2",
        "6a1966f0984de309dd311a65359d520690a9ac9a267125fadc2ceed4e46be0bf151fd",
        "b4295e3d37933bba481ab3081a8a003020112a103020101a2819b0481980e807bcf2123",
        "ba5724d8ab08fc2fd96e3c21793ca1c15d1565bc5ce2e42e2016430d7601bf49a1a7",
        "c40546749242f1ec56c8ae16a7498d4925dca885bceb4a3b5b8de02bb99a967060d",
        "4e7cf3d3b0666dcafa3a6c36287aeb99a9fa0279c20bb988763276a3da6f306a827",
        "b53e2868f560a3b71b7047e5630b19074a4176fd8c29c49cc039dd53b158771a93c",
        "a2ebe8ee42fde2c060fb2d1",
    );

    const BADMATCH_AP_REQ: &str = concat!(
        "6e8201f7308201f3a003020105a10302010ea20703050000000000a382012f6182012b30820127a0",
        "03020105a10d1b0b544553542e474f4b524235a2233021a003020101a11a30181b04485454501b",
        "10686f73742e746573742e676f6b726235a381eb3081e8a003020112a103020101a281db0481d8",
        "8256b413abf60f64f76692684a3cbedff3822acc4bc9edf1ca36f085828520de09ae593",
        "971e02ff706b9ab985436f516734009bd02a557cea8648a66c3106c37567f5c1c1b77620",
        "6e452d348c65ced2e3dccd22bebdc9f86f48c1543cea7c8125ae839490cf3361d762b",
        "9e206da0fa2da25e8381f525f5e0383aba2139a44d563b16da14c8bc12b83b096ee35",
        "5051e201f96d76fe8c01fa81db7a10a90b446229f1a10f047d889ca1696d01a3867d5",
        "7652fb3870ba07f7b7eafdf00b939784cce3d15e932640f9a0358939c2640befba0f",
        "3efcf9de18268ba481aa3081a7a003020112a103020101a2819a048197d80b4b768e13fd5a",
        "b024375e464e5a99beab36169a48fc33abb129c21db948c7b2c0c28a1ac0ef7540cf",
        "5109a5efdb45da8a7bf2cb57356da2d052b0d79fa49149c6928bcb1572b2e31c1",
        "f6019aa27c74e3691c2716a0ec72042624316e3f4c98e73fac734ce397101a6b2b49",
        "41fa20afc16f3f0845a6b7e1e9b25054cb02bd95fb97db781020cb5a6cf5ee81314",
        "0c6183e5483650d1e9",
    );

    /// Pins that the validator accepts the gokrb5 AP-REQ fixture and reports its identities.
    #[test]
    fn validates_gokrb5_ap_req_fixture() -> Result<(), TestError> {
        let keytab = http_keytab()?;
        let mut validator = ServiceValidator::new(&keytab).with_now(timestamp(1_893_553_447)?);

        let validated = validator
            .validate_ap_req(&decode_hex(VALID_AP_REQ)?)
            .context("AP-REQ validates")?;

        assert_eq!(
            validated.client,
            Principal::new("TEST.GOKRB5".to_owned(), 1, vec!["testuser1".to_owned()])
        );
        assert_eq!(validated.client.name(), "testuser1");
        assert_eq!(
            validated.service,
            Principal::new(
                "TEST.GOKRB5".to_owned(),
                1,
                vec!["HTTP".to_owned(), "host.test.gokrb5".to_owned()]
            )
        );
        assert_eq!(validated.session_key.etype, 18_i32);
        assert_eq!(hex_encode(&validated.session_key.value), VALID_SESSION_KEY);
        assert_eq!(validated.subkey.context("subkey exists")?.etype, 18_i32);
        assert_eq!(validated.sequence_number, Some(42));
        assert_eq!(validated.ticket_start, timestamp(1_893_553_445)?);
        assert_eq!(validated.ticket_end, timestamp(1_893_639_845)?);
        assert_eq!(validated.authenticator_ctime, timestamp(1_893_553_447)?);
        assert_eq!(validated.authenticator_cusec, 123_456);
        assert_eq!(
            validated.authenticator_time,
            timestamp(1_893_553_447)? + Duration::from_micros(123_456)
        );
        assert!(validated.pac.is_none());
        Ok(())
    }

    /// Pins that a validator loaded from a keytab name accepts the gokrb5 AP-REQ.
    #[test]
    fn validates_ap_req_from_keytab_name() -> Result<(), TestError> {
        let keytab = http_keytab()?;
        let path = temp_service_keytab_file("validate-name")?;
        let name = format!("FILE:{}", path.display());
        keytab.save_name(&name).context("keytab saves by name")?;
        let mut validator = ServiceValidator::from_keytab_name(&name)
            .context("validator loads keytab by name")?
            .with_now(timestamp(1_893_553_447)?);
        fs::remove_file(&path).context("temporary keytab is removed")?;

        let validated = validator
            .validate_ap_req(&decode_hex(VALID_AP_REQ)?)
            .context("AP-REQ validates")?;

        assert_eq!(validated.client.name(), "testuser1");
        assert_eq!(validated.service.name(), "HTTP/host.test.gokrb5");
        assert_eq!(validated.session_key.etype, 18_i32);
        Ok(())
    }

    /// Pins that `ServiceValidator::from_keytab_env` validates with the `KRB5_KTNAME` keytab.
    #[test]
    fn validates_ap_req_from_keytab_env() -> Result<(), TestError> {
        const TEST_PATH: &str = "tests::validates_ap_req_from_keytab_env";
        if !env::in_child(TEST_PATH) {
            let path = temp_service_keytab_file("validate-env")?;
            let name = format!("FILE:{}", path.display());
            env::run_in_child(TEST_PATH, &[("KRB5_KTNAME", Some(name.as_ref()))]);
            return Ok(());
        }
        let keytab = http_keytab()?;
        let name = var("KRB5_KTNAME")
            .map_err(|cause| format!("the parent test sets KRB5_KTNAME: {cause}"))?;
        let path = PathBuf::from(
            name.strip_prefix("FILE:")
                .ok_or("KRB5_KTNAME names a FILE: path")?,
        );
        keytab
            .save_name(&name)
            .map_err(|cause| format!("keytab saves by name: {cause}"))?;
        let mut validator = ServiceValidator::from_keytab_env()
            .map_err(|cause| format!("validator loads keytab from env: {cause}"))?
            .with_now(timestamp(1_893_553_447)?);
        fs::remove_file(&path).context("temporary keytab is removed")?;

        let validated = validator
            .validate_ap_req(&decode_hex(VALID_AP_REQ)?)
            .map_err(|cause| format!("AP-REQ validates: {cause}"))?;

        assert_eq!(validated.client.name(), "testuser1");
        assert_eq!(validated.service.name(), "HTTP/host.test.gokrb5");
        assert_eq!(validated.session_key.etype, 18_i32);
        Ok(())
    }

    /// Pins that a validator loaded from the config default keytab name accepts the gokrb5 AP-REQ.
    #[test]
    fn validates_ap_req_from_default_keytab_name() -> Result<(), TestError> {
        let keytab = http_keytab()?;
        let path = temp_service_keytab_file("validate-default-name")?;
        let name = format!("FILE:{}", path.display());
        keytab.save_name(&name).context("keytab saves by name")?;
        let config = config_with_default_keytab_name(&name)?;
        let mut validator = ServiceValidator::from_default_keytab_name(&config)
            .context("validator loads default keytab name")?
            .with_now(timestamp(1_893_553_447)?);
        fs::remove_file(&path).context("temporary keytab is removed")?;

        let validated = validator
            .validate_ap_req(&decode_hex(VALID_AP_REQ)?)
            .context("AP-REQ validates")?;

        assert_eq!(validated.client.name(), "testuser1");
        assert_eq!(validated.service.name(), "HTTP/host.test.gokrb5");
        assert_eq!(validated.session_key.etype, 18_i32);
        Ok(())
    }

    /// Pins that the validator falls back to the config default keytab without `KRB5_KTNAME`.
    #[test]
    fn validates_ap_req_from_default_keytab_when_env_is_absent() -> Result<(), TestError> {
        const TEST_PATH: &str = "tests::validates_ap_req_from_default_keytab_when_env_is_absent";
        if !env::in_child(TEST_PATH) {
            env::run_in_child(TEST_PATH, &[("KRB5_KTNAME", None)]);
            return Ok(());
        }
        let keytab = http_keytab()?;
        let path = temp_service_keytab_file("validate-default-env-fallback")?;
        let name = format!("FILE:{}", path.display());
        keytab
            .save_name(&name)
            .map_err(|cause| format!("keytab saves by name: {cause}"))?;
        let config = config_with_default_keytab_name(&name)?;
        let mut validator = ServiceValidator::from_default_keytab(&config)
            .map_err(|cause| format!("validator loads default keytab: {cause}"))?
            .with_now(timestamp(1_893_553_447)?);
        fs::remove_file(&path).context("temporary keytab is removed")?;

        let validated = validator
            .validate_ap_req(&decode_hex(VALID_AP_REQ)?)
            .map_err(|cause| format!("AP-REQ validates: {cause}"))?;

        assert_eq!(validated.client.name(), "testuser1");
        assert_eq!(validated.service.name(), "HTTP/host.test.gokrb5");
        assert_eq!(validated.session_key.etype, 18_i32);
        Ok(())
    }

    /// Pins that the validator prefers `KRB5_KTNAME` over the config default keytab.
    #[test]
    fn validates_ap_req_prefers_env_keytab_over_config_default() -> Result<(), TestError> {
        const TEST_PATH: &str = "tests::validates_ap_req_prefers_env_keytab_over_config_default";
        if !env::in_child(TEST_PATH) {
            let path = temp_service_keytab_file("validate-env-precedence")?;
            let env_name = format!("FILE:{}", path.display());
            env::run_in_child(TEST_PATH, &[("KRB5_KTNAME", Some(env_name.as_ref()))]);
            return Ok(());
        }
        let keytab = http_keytab()?;
        let env_name = var("KRB5_KTNAME")
            .map_err(|cause| format!("the parent test sets KRB5_KTNAME: {cause}"))?;
        let path = PathBuf::from(
            env_name
                .strip_prefix("FILE:")
                .ok_or("KRB5_KTNAME names a FILE: path")?,
        );
        keytab
            .save_name(&env_name)
            .map_err(|cause| format!("keytab saves by name: {cause}"))?;
        let missing_config_name = format!(
            "FILE:{}",
            temp_service_keytab_file("missing-config-default")?.display()
        );
        let config = config_with_default_keytab_name(&missing_config_name)?;
        let mut validator = ServiceValidator::from_default_keytab(&config)
            .map_err(|cause| format!("validator loads env keytab before config default: {cause}"))?
            .with_now(timestamp(1_893_553_447)?);
        fs::remove_file(&path).context("temporary keytab is removed")?;

        let validated = validator
            .validate_ap_req(&decode_hex(VALID_AP_REQ)?)
            .map_err(|cause| format!("AP-REQ validates: {cause}"))?;

        assert_eq!(validated.client.name(), "testuser1");
        assert_eq!(validated.service.name(), "HTTP/host.test.gokrb5");
        assert_eq!(validated.session_key.etype, 18_i32);
        Ok(())
    }

    /// Pins that a ticket PAC with a valid server checksum is verified and returned.
    #[test]
    fn validates_ap_req_with_verified_ticket_pac() -> Result<(), TestError> {
        let keytab = syshttp_keytab()?;
        let mut validator = ServiceValidator::new(&keytab).with_now(timestamp(1_893_553_447)?);

        let validated = validator
            .validate_ap_req(&ap_req_with_pac()?)
            .context("AP-REQ with PAC validates")?;

        assert_eq!(validated.client.name(), "testuser1");
        assert_eq!(validated.service.name(), "sysHTTP");
        assert_eq!(validated.session_key.etype, 18_i32);
        assert_eq!(hex_encode(&validated.session_key.value), VALID_SESSION_KEY);
        let pac = validated
            .pac
            .as_ref()
            .context("PAC extracted and verified")?;
        assert_eq!(pac.c_buffers, 5);
        assert_eq!(
            pac.kerb_validation_info
                .as_ref()
                .context("KVI parsed")?
                .effective_name
                .value,
            "testuser1"
        );
        assert_eq!(
            pac.upn_dns_info.as_ref().context("UPN/DNS parsed")?.upn,
            "testuser1@test.gokrb5"
        );
        Ok(())
    }

    /// Pins that a ticket PAC with a flipped server checksum bit is rejected.
    #[test]
    fn rejects_ap_req_with_invalid_ticket_pac_checksum() -> Result<(), TestError> {
        let keytab = syshttp_keytab()?;
        let mut validator = ServiceValidator::new(&keytab).with_now(timestamp(1_893_553_447)?);
        let mut pac_bytes = decode_hex(pac_ad_win2k::PAC_AD_WIN2K)?;
        let pac_header = pac::Pac::parse(&pac_bytes).context("PAC header parses")?;
        let server_signature = pac_header
            .buffer(pac::INFO_TYPE_PAC_SERVER_SIGNATURE_DATA)
            .context("server checksum buffer exists")?;
        let signature_offset = usize::try_from(server_signature.offset)
            .context("offset fits")?
            .checked_add(4)
            .context("signature offset fits")?;
        let signature_byte = pac_bytes
            .get_mut(signature_offset)
            .context("PAC holds the server signature")?;
        *signature_byte ^= 0x01;

        assert!(matches!(
            validator
                .validate_ap_req(&ap_req_with_pac_bytes(pac_bytes)?)
                .err()
                .context("bad PAC checksum is rejected")?,
            Error::Pac(pac::Error::ServerChecksumVerificationFailed)
        ));
        Ok(())
    }

    /// Pins that the acceptor's AP-REP verifies against the validated AP-REQ.
    #[test]
    fn builds_and_verifies_ap_rep_mutual_auth_reply() -> Result<(), TestError> {
        let validated = valid_ap_req()?;
        let options = ap_rep_options()?;

        let ap_rep = validated
            .build_ap_rep_with_confounder(&decode_hex(AP_REP_CONFOUNDER)?, options.clone())
            .context("AP-REP builds")?;
        assert_eq!(hex_encode(&ap_rep), AP_REP_WITH_SUBKEY);
        let verified = validated
            .verify_ap_rep(&ap_rep)
            .context("AP-REP verifies")?;

        assert_eq!(verified.ctime, validated.authenticator_ctime);
        assert_eq!(verified.cusec, validated.authenticator_cusec);
        assert_eq!(verified.authenticator_time, validated.authenticator_time);
        assert_eq!(verified.subkey, options.subkey);
        assert_eq!(verified.sequence_number, options.sequence_number);
        Ok(())
    }

    /// Pins that an AP-REP whose timestamp differs from the authenticator is rejected.
    #[test]
    fn rejects_ap_rep_timestamp_mismatch() -> Result<(), TestError> {
        let validated = valid_ap_req()?;
        let ap_rep = validated
            .build_ap_rep_with_confounder(&decode_hex(AP_REP_CONFOUNDER)?, ApRepOptions::default())
            .context("AP-REP builds")?;
        let mut wrong_request = validated;
        wrong_request.authenticator_cusec += 1;
        wrong_request.authenticator_time += Duration::from_micros(1);

        assert!(matches!(
            wrong_request
                .verify_ap_rep(&ap_rep)
                .err()
                .context("mismatched AP-REP timestamp rejected")?,
            Error::ApRepTimestampMismatch {
                expected: _,
                actual: _
            }
        ));
        Ok(())
    }

    /// Pins that a tampered AP-REP fails its integrity check.
    #[test]
    fn rejects_tampered_ap_rep() -> Result<(), TestError> {
        let validated = valid_ap_req()?;
        let mut ap_rep = validated
            .build_ap_rep_with_confounder(&decode_hex(AP_REP_CONFOUNDER)?, ApRepOptions::default())
            .context("AP-REP builds")?;
        let last = ap_rep.last_mut().context("AP-REP is non-empty")?;
        *last ^= 0x01;

        assert!(matches!(
            validated
                .verify_ap_rep(&ap_rep)
                .err()
                .context("tampered AP-REP rejected")?,
            Error::Crypto(CryptoError::IntegrityCheckFailed)
        ));
        Ok(())
    }

    /// Pins that presenting the same AP-REQ twice is a replay.
    #[test]
    fn detects_ap_req_replay() -> Result<(), TestError> {
        let keytab = http_keytab()?;
        let mut validator = ServiceValidator::new(&keytab).with_now(timestamp(1_893_553_447)?);
        drop(
            validator
                .validate_ap_req(&decode_hex(VALID_AP_REQ)?)
                .context("first AP-REQ validates")?,
        );

        assert!(matches!(
            validator
                .validate_ap_req(&decode_hex(VALID_AP_REQ)?)
                .err()
                .context("second AP-REQ is replay")?,
            Error::Replay
        ));

        validator.replay_cache_mut().clear();
        drop(
            validator
                .validate_ap_req(&decode_hex(VALID_AP_REQ)?)
                .context("cleared replay cache permits request")?,
        );
        Ok(())
    }

    /// Pins that clearing old replay entries removes expired ones.
    #[test]
    fn clears_old_replay_cache_entries() -> Result<(), TestError> {
        let keytab = http_keytab()?;
        let now = timestamp(1_893_553_447)?;
        let mut validator = ServiceValidator::new(&keytab).with_now(now);
        drop(
            validator
                .validate_ap_req(&decode_hex(VALID_AP_REQ)?)
                .context("first AP-REQ validates")?,
        );
        assert_eq!(validator.replay_cache_mut().len(), 1);

        let removed = validator.replay_cache_mut().clear_older_than_at(
            Duration::from_mins(5),
            now.checked_add(Duration::from_secs(5 * 60 + 1))
                .context("cleanup time")?,
        );

        assert_eq!(removed, 1);
        assert!(
            validator.replay_cache_mut().is_empty(),
            "the expired entry is cleared"
        );

        drop(
            validator
                .validate_ap_req(&decode_hex(VALID_AP_REQ)?)
                .context("expired replay entry no longer rejects request")?,
        );
        Ok(())
    }

    /// Pins that validators sharing a replay cache reject each other's replays.
    #[test]
    fn shared_replay_cache_rejects_replay_across_validators() -> Result<(), TestError> {
        let keytab = http_keytab()?;
        let now = timestamp(1_893_553_447)?;
        let replay_cache = SharedReplayCache::new();
        let mut first = ServiceValidator::new(&keytab)
            .with_now(now)
            .with_shared_replay_cache(replay_cache.clone());
        let mut second = ServiceValidator::new(&keytab)
            .with_now(now)
            .with_shared_replay_cache(replay_cache.clone());

        assert!(
            replay_cache
                .is_empty()
                .context("shared replay cache reads")?,
            "new shared replay cache is empty"
        );
        drop(
            first
                .validate_ap_req(&decode_hex(VALID_AP_REQ)?)
                .context("first AP-REQ validates")?,
        );
        assert_eq!(replay_cache.len().context("shared replay cache counts")?, 1);

        assert!(matches!(
            second
                .validate_ap_req(&decode_hex(VALID_AP_REQ)?)
                .err()
                .context("second validator sees replay")?,
            Error::Replay
        ));

        let removed = replay_cache
            .clear_older_than_at(
                Duration::from_secs(1),
                now.checked_add(Duration::from_secs(2))
                    .context("cleanup time")?,
            )
            .context("shared replay cache ages entries")?;
        assert_eq!(removed, 1);
        drop(
            second
                .validate_ap_req(&decode_hex(VALID_AP_REQ)?)
                .context("aged shared replay entry no longer rejects request")?,
        );

        let mut local = ServiceValidator::new(&keytab)
            .with_now(now)
            .with_shared_replay_cache(replay_cache)
            .without_shared_replay_cache();
        drop(
            local
                .validate_ap_req(&decode_hex(VALID_AP_REQ)?)
                .context("opted-out validator uses local replay cache")?,
        );
        Ok(())
    }

    /// Pins that a keytab principal override without a matching key fails validation.
    #[test]
    fn validates_keytab_principal_override_failure() -> Result<(), TestError> {
        let keytab = http_keytab()?;
        let mut validator = ServiceValidator::new(&keytab)
            .with_now(timestamp(1_893_553_447)?)
            .with_keytab_principal(["foo"]);

        assert!(matches!(
            validator
                .validate_ap_req(&decode_hex(VALID_AP_REQ)?)
                .err()
                .context("wrong service principal key is rejected")?,
            Error::Keytab(_)
        ));
        Ok(())
    }

    /// Pins that an authenticator naming a different client than the ticket is rejected.
    #[test]
    fn rejects_client_principal_mismatch() -> Result<(), TestError> {
        let keytab = http_keytab()?;
        let mut validator = ServiceValidator::new(&keytab).with_now(timestamp(1_893_553_447)?);

        assert!(matches!(
            validator
                .validate_ap_req(&decode_hex(BADMATCH_AP_REQ)?)
                .err()
                .context("client mismatch rejected")?,
            Error::ClientPrincipalMismatch {
                ticket: _,
                authenticator: _
            }
        ));
        Ok(())
    }

    /// Pins that tickets used before their start time or after their end time are rejected.
    #[test]
    fn rejects_invalid_future_and_expired_tickets() -> Result<(), TestError> {
        let keytab = http_keytab()?;
        let mut invalid_validator =
            ServiceValidator::new(&keytab).with_now(timestamp(1_893_553_447)?);
        assert!(matches!(
            invalid_validator
                .validate_ap_req(&decode_hex(INVALID_TICKET_AP_REQ)?)
                .err()
                .context("invalid ticket rejected")?,
            Error::TicketNotYetValid {
                service: _,
                realm: _
            }
        ));

        let mut future_validator =
            ServiceValidator::new(&keytab).with_now(timestamp(1_893_553_445 - 301)?);
        assert!(matches!(
            future_validator
                .validate_ap_req(&decode_hex(VALID_AP_REQ)?)
                .err()
                .context("future ticket rejected")?,
            Error::TicketNotYetValid {
                service: _,
                realm: _
            }
        ));

        let mut expired_validator =
            ServiceValidator::new(&keytab).with_now(timestamp(1_893_639_845 + 301)?);
        assert!(matches!(
            expired_validator
                .validate_ap_req(&decode_hex(VALID_AP_REQ)?)
                .err()
                .context("expired ticket rejected")?,
            Error::TicketExpired {
                service: _,
                realm: _
            }
        ));
        Ok(())
    }

    /// Pins that an authenticator outside the clock-skew window is rejected.
    #[test]
    fn rejects_large_authenticator_clock_skew() -> Result<(), TestError> {
        let keytab = http_keytab()?;
        let mut validator =
            ServiceValidator::new(&keytab).with_now(timestamp(1_893_553_447 + 301)?);

        assert!(matches!(
            validator
                .validate_ap_req(&decode_hex(VALID_AP_REQ)?)
                .err()
                .context("authenticator skew rejected")?,
            Error::ClockSkew { max_clock_skew: _ }
        ));
        Ok(())
    }

    /// Pins that an addressless ticket is rejected when a client address is required.
    #[test]
    fn rejects_addressless_ticket_when_client_address_is_required() -> Result<(), TestError> {
        let keytab = http_keytab()?;
        let mut validator = ServiceValidator::new(&keytab)
            .with_now(timestamp(1_893_553_447)?)
            .require_client_address(true);

        assert!(matches!(
            validator
                .validate_ap_req(&decode_hex(VALID_AP_REQ)?)
                .err()
                .context("addressless ticket rejected")?,
            Error::RequiredClientAddressMissing {
                service: _,
                realm: _
            }
        ));
        Ok(())
    }

    fn http_keytab() -> Result<Keytab, TestError> {
        Keytab::parse(&decode_hex(HTTP_KEYTAB)?).context("HTTP keytab parses")
    }

    fn syshttp_keytab() -> Result<Keytab, TestError> {
        Keytab::parse(&decode_hex(pac_ad_win2k::SYSHTTP_KEYTAB)?).context("sysHTTP keytab parses")
    }

    fn config_with_default_keytab_name(keytab_name: &str) -> Result<Config, TestError> {
        let input = format!(
            "
[libdefaults]
 default_keytab_name = {keytab_name}
",
        );
        Config::parse(&input).context("config parses")
    }

    fn ap_req_with_pac() -> Result<Vec<u8>, TestError> {
        ap_req_with_pac_bytes(decode_hex(pac_ad_win2k::PAC_AD_WIN2K)?)
    }

    fn ap_req_with_pac_bytes(pac_bytes: Vec<u8>) -> Result<Vec<u8>, TestError> {
        let keytab = syshttp_keytab()?;
        let (service_key, _) = keytab
            .find_key(&["sysHTTP"], "TEST.GOKRB5", 2, 18)
            .context("sysHTTP service key exists")?;
        let session_key = EncryptionKey::new(18, decode_hex(VALID_SESSION_KEY)?);
        let client = principal(["testuser1"])?;
        let service = principal(["sysHTTP"])?;
        let pac_authorization_data = pac_authorization_data(pac_bytes)?;
        let auth_time = kerberos_time(1_893_553_445)?;
        let ctime = kerberos_time(1_893_553_447)?;

        let enc_ticket = rasn_kerberos::EncTicketPart {
            flags: rasn_kerberos::TicketFlags(zero_kerberos_flags()),
            key: encryption_key(&session_key),
            crealm: realm("TEST.GOKRB5")?,
            cname: client.clone(),
            transited: rasn_kerberos::TransitedEncoding {
                r#type: 1,
                contents: Vec::new().into(),
            },
            auth_time: auth_time.clone(),
            start_time: Some(auth_time),
            end_time: kerberos_time(1_893_639_845)?,
            renew_till: None,
            caddr: None,
            authorization_data: Some(pac_authorization_data),
        };
        let ticket_cipher = encrypt_message(
            service_key,
            &der::encode(&enc_ticket).context("EncTicketPart encodes")?,
            KDC_REP_TICKET_USAGE_FOR_TEST,
            PAC_TICKET_CONFOUNDER,
        )?;

        let authenticator = rasn_kerberos::Authenticator {
            authenticator_vno: 5_i32.into(),
            crealm: realm("TEST.GOKRB5")?,
            cname: client,
            cksum: None,
            cusec: 123_456_i32.into(),
            ctime,
            subkey: None,
            seq_number: Some(42),
            authorization_data: None,
        };
        let authenticator_cipher = encrypt_message(
            &session_key,
            &der::encode(&authenticator).context("Authenticator encodes")?,
            AP_REQ_AUTHENTICATOR_USAGE_FOR_TEST,
            PAC_AUTHENTICATOR_CONFOUNDER,
        )?;

        let ap_req = rasn_kerberos::ApReq {
            pvno: 5_i32.into(),
            msg_type: 14_i32.into(),
            ap_options: rasn_kerberos::ApOptions(zero_kerberos_flags()),
            ticket: rasn_kerberos::Ticket {
                tkt_vno: 5_i32.into(),
                realm: realm("TEST.GOKRB5")?,
                sname: service,
                enc_part: rasn_kerberos::EncryptedData {
                    etype: service_key.etype,
                    kvno: Some(2),
                    cipher: ticket_cipher.into(),
                },
            },
            authenticator: rasn_kerberos::EncryptedData {
                etype: session_key.etype,
                kvno: None,
                cipher: authenticator_cipher.into(),
            },
        };

        der::encode(&ap_req).context("AP-REQ encodes")
    }

    fn pac_authorization_data(
        pac_bytes: Vec<u8>,
    ) -> Result<rasn_kerberos::AuthorizationData, TestError> {
        let nested =
            rasn_kerberos::AuthorizationData::from(vec![rasn_kerberos::AuthorizationDataValue {
                r#type: pac::AD_WIN2K_PAC,
                data: pac_bytes.into(),
            }]);
        let nested_der = der::encode(&nested).context("nested authorization-data encodes")?;
        Ok(rasn_kerberos::AuthorizationData::from(vec![
            rasn_kerberos::AuthorizationDataValue {
                r#type: pac::AD_IF_RELEVANT,
                data: nested_der.into(),
            },
        ]))
    }

    fn encrypt_message(
        key: &EncryptionKey,
        plaintext: &[u8],
        usage: u32,
        confounder_hex: &str,
    ) -> Result<Vec<u8>, TestError> {
        let etype =
            AesSha1Etype::from_etype_id(key.etype).context("AES-SHA1 etype is supported")?;
        etype
            .encrypt_message_with_confounder(
                &key.value,
                plaintext,
                usage,
                &decode_hex(confounder_hex)?,
            )
            .context("message encrypts")
    }

    fn encryption_key(key: &EncryptionKey) -> rasn_kerberos::EncryptionKey {
        rasn_kerberos::EncryptionKey {
            r#type: key.etype,
            value: key.value.clone().into(),
        }
    }

    fn principal<const N: usize>(
        components: [&str; N],
    ) -> Result<rasn_kerberos::PrincipalName, TestError> {
        Ok(rasn_kerberos::PrincipalName {
            r#type: 1,
            string: components
                .into_iter()
                .map(kerberos_string)
                .collect::<Result<_, _>>()?,
        })
    }

    fn realm(value: &str) -> Result<rasn_kerberos::Realm, TestError> {
        kerberos_string(value)
    }

    fn kerberos_string(value: &str) -> Result<rasn_kerberos::KerberosString, TestError> {
        rasn_kerberos::KerberosString::from_bytes(value.as_bytes())
            .context("Kerberos string uses permitted characters")
    }

    fn kerberos_time(seconds: u64) -> Result<rasn_kerberos::KerberosTime, TestError> {
        let utc = DateTime::<Utc>::from_timestamp(
            i64::try_from(seconds).context("fixture timestamp fits")?,
            0,
        )
        .context("fixture timestamp is representable")?;
        let offset = FixedOffset::east_opt(0).context("UTC offset exists")?;
        Ok(rasn_kerberos::KerberosTime(utc.with_timezone(&offset)))
    }

    fn zero_kerberos_flags() -> rasn_kerberos::KerberosFlags {
        rasn_kerberos::KerberosFlags::repeat(false, 32)
    }

    fn valid_ap_req() -> Result<ValidatedApReq, TestError> {
        let keytab = http_keytab()?;
        ServiceValidator::new(&keytab)
            .with_now(timestamp(1_893_553_447)?)
            .validate_ap_req(&decode_hex(VALID_AP_REQ)?)
            .context("AP-REQ validates")
    }

    fn ap_rep_options() -> Result<ApRepOptions, TestError> {
        Ok(ApRepOptions::default()
            .with_subkey(Some(EncryptionKey::new(
                18,
                decode_hex(AP_REP_SERVER_SUBKEY)?,
            )))
            .with_sequence_number(Some(17))
            .with_kvno(Some(5)))
    }

    /// Returns the instant `seconds` after the Unix epoch.
    fn timestamp(seconds: u64) -> Result<SystemTime, TestError> {
        UNIX_EPOCH
            .checked_add(Duration::from_secs(seconds))
            .context("timestamp is representable")
    }

    fn temp_service_keytab_file(name: &str) -> Result<PathBuf, TestError> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("current time is after unix epoch")?
            .as_nanos();
        Ok(temp_dir().join(format!(
            "rskrb5-service-keytab-{name}-{}-{nanos}",
            process::id()
        )))
    }

    /// Pins that flipping only the ticket sname name-type is still a replay.
    #[test]
    fn replay_identity_ignores_the_ticket_name_type() -> Result<(), TestError> {
        let keytab = http_keytab()?;
        let mut validator = ServiceValidator::new(&keytab).with_now(timestamp(1_893_553_447)?);
        drop(
            validator
                .validate_ap_req(&decode_hex(VALID_AP_REQ)?)
                .map_err(|cause| format!("first AP-REQ validates: {cause}"))?,
        );
        assert_eq!(validator.replay_cache_mut().len(), 1);

        // RFC 4120 section 6.2: the name-type is advisory and "not significant
        // when checking for equivalence". The ticket's outer sname is cleartext,
        // so a peer can flip its name-type without touching any ciphertext; the
        // mutated request is the same presentation and must be rejected.
        let mut mutated = valid_ap_req_struct()?;
        mutated.ticket.sname.r#type = 0_i32;
        let mutated_der =
            der::encode(&mutated).map_err(|cause| format!("mutated AP-REQ encodes: {cause}"))?;

        assert!(matches!(
            validator
                .validate_ap_req(&mutated_der)
                .err()
                .ok_or("name-type-only mutation is a replay")?,
            Error::Replay
        ));
        assert_eq!(validator.replay_cache_mut().len(), 1);
        Ok(())
    }

    /// Pins that with a keytab principal override the accepted key, not the sname, is the replay identity.
    #[test]
    fn replay_identity_follows_the_accepted_key_identity() -> Result<(), TestError> {
        let keytab = http_keytab()?;
        let mut validator = ServiceValidator::new(&keytab)
            .with_now(timestamp(1_893_553_447)?)
            .with_keytab_principal(["HTTP", "host.test.gokrb5"]);

        // The override selects the key; the ticket's own sname is then advisory
        // for replay purposes, so an alias for the same service key is the same
        // server principal.
        let mut alias = valid_ap_req_struct()?;
        alias.ticket.sname.string = vec![
            kerberos_string("HTTP")?,
            kerberos_string("alias.test.gokrb5")?,
        ];
        let alias_der =
            der::encode(&alias).map_err(|cause| format!("alias AP-REQ encodes: {cause}"))?;

        drop(
            validator
                .validate_ap_req(&alias_der)
                .map_err(|cause| format!("alias sname validates under the override: {cause}"))?,
        );
        assert!(matches!(
            validator
                .validate_ap_req(&decode_hex(VALID_AP_REQ)?)
                .err()
                .ok_or("same accepted key is the same server principal")?,
            Error::Replay
        ));
        Ok(())
    }

    /// Pins that the same authenticator under a shared-key sname alias is a replay.
    #[test]
    fn replay_identity_survives_a_shared_key_sname_alias() -> Result<(), TestError> {
        let keytab = http_keytab_with_alias()?;
        let mut validator = ServiceValidator::new(&keytab).with_now(timestamp(1_893_553_447)?);
        drop(
            validator
                .validate_ap_req(&decode_hex(VALID_AP_REQ)?)
                .map_err(|cause| format!("first AP-REQ validates: {cause}"))?,
        );

        assert!(matches!(
            validator
                .validate_ap_req(&alias_ap_req()?)
                .err()
                .ok_or("same authenticator under a shared-key alias is a replay")?,
            Error::Replay
        ));
        assert_eq!(validator.replay_cache_mut().len(), 1);
        Ok(())
    }

    /// Pins that a shared replay cache rejects the same authenticator under a shared-key alias.
    #[test]
    fn shared_replay_cache_rejects_a_shared_key_sname_alias() -> Result<(), TestError> {
        let keytab = http_keytab_with_alias()?;
        let replay_cache = SharedReplayCache::new();
        let mut first = ServiceValidator::new(&keytab)
            .with_now(timestamp(1_893_553_447)?)
            .with_shared_replay_cache(replay_cache.clone());
        let mut second = ServiceValidator::new(&keytab)
            .with_now(timestamp(1_893_553_447)?)
            .with_shared_replay_cache(replay_cache.clone());
        drop(
            first
                .validate_ap_req(&decode_hex(VALID_AP_REQ)?)
                .map_err(|cause| format!("first AP-REQ validates: {cause}"))?,
        );

        assert!(matches!(
            second
                .validate_ap_req(&alias_ap_req()?)
                .err()
                .ok_or("shared cache rejects the same authenticator under an alias")?,
            Error::Replay
        ));
        assert_eq!(
            replay_cache
                .len()
                .map_err(|cause| format!("shared cache counts: {cause}"))?,
            1
        );
        Ok(())
    }

    /// Pins that clearing old replay entries also forgets their authenticator digests.
    #[test]
    fn clearing_old_entries_also_forgets_authenticator_digests() -> Result<(), TestError> {
        let keytab = http_keytab_with_alias()?;
        let mut validator = ServiceValidator::new(&keytab).with_now(timestamp(1_893_553_447)?);
        drop(
            validator
                .validate_ap_req(&decode_hex(VALID_AP_REQ)?)
                .map_err(|cause| format!("first AP-REQ validates: {cause}"))?,
        );

        assert_eq!(
            validator
                .replay_cache_mut()
                .clear_older_than_at(Duration::ZERO, timestamp(1_893_553_448)?),
            1
        );
        drop(
            validator
                .validate_ap_req(&alias_ap_req()?)
                .map_err(|cause| {
                    format!("expired digest permits the alias presentation: {cause}")
                })?,
        );
        Ok(())
    }

    /// Pins that an authenticator client realm differing from the ticket's is rejected.
    #[test]
    fn rejects_authenticator_client_realm_mismatch() -> Result<(), TestError> {
        let keytab = http_keytab()?;
        let mut validator = ServiceValidator::new(&keytab).with_now(timestamp(1_893_553_447)?);

        // RFC 4120 section 3.2.3: the ticket's client realm must match the
        // authenticator's. The components match here; only the realm differs.
        let mut ap_req = valid_ap_req_struct()?;
        reencrypt_authenticator(&mut ap_req, "EVIL.VERIFIER.REALM", 1)?;
        let ap_req_der =
            der::encode(&ap_req).map_err(|cause| format!("mutated AP-REQ encodes: {cause}"))?;

        let error = validator
            .validate_ap_req(&ap_req_der)
            .err()
            .ok_or("realm mismatch rejected")?;
        let Error::ClientPrincipalMismatch {
            ticket,
            authenticator,
        } = error
        else {
            return Err(format!("expected ClientPrincipalMismatch, got {error:?}").into());
        };
        assert_eq!(ticket, "testuser1@TEST.GOKRB5");
        assert_eq!(authenticator, "testuser1@EVIL.VERIFIER.REALM");
        Ok(())
    }

    /// Pins that the accepted identity is the ticket's client, not the authenticator's.
    #[test]
    fn returns_the_ticket_client_identity() -> Result<(), TestError> {
        let keytab = http_keytab()?;
        let mut validator = ServiceValidator::new(&keytab).with_now(timestamp(1_893_553_447)?);

        // RFC 4120 section 6.2: the name-type is advisory, so a differing
        // authenticator name-type is not a mismatch - but the accepted identity
        // must be the KDC-encrypted ticket's, not the authenticator's.
        let mut ap_req = valid_ap_req_struct()?;
        reencrypt_authenticator(&mut ap_req, "TEST.GOKRB5", 5)?;
        let ap_req_der =
            der::encode(&ap_req).map_err(|cause| format!("variant AP-REQ encodes: {cause}"))?;

        let validated = validator
            .validate_ap_req(&ap_req_der)
            .map_err(|cause| format!("name-type difference is not a mismatch: {cause}"))?;

        let (service_key, _) = keytab
            .find_key(&["HTTP", "host.test.gokrb5"], "TEST.GOKRB5", 1, 18)
            .map_err(|cause| format!("HTTP service key exists: {cause}"))?;
        let ticket = decrypt_ticket_enc_part(&valid_ap_req_struct()?.ticket, service_key)
            .map_err(|cause| format!("ticket decrypts: {cause}"))?;

        assert_ne!(validated.client.name_type, 5_i32);
        assert_eq!(
            validated.client,
            Principal::new(
                "TEST.GOKRB5".to_owned(),
                ticket.cname.r#type,
                vec!["testuser1".to_owned()]
            )
        );
        Ok(())
    }

    /// Pins that the config `clockskew` bounds authenticator freshness for both default-keytab constructors.
    #[test]
    fn config_clockskew_bounds_authenticator_freshness() -> Result<(), TestError> {
        const TEST_PATH: &str = "tests::config_clockskew_bounds_authenticator_freshness";
        if !env::in_child(TEST_PATH) {
            env::run_in_child(TEST_PATH, &[("KRB5_KTNAME", None)]);
            return Ok(());
        }
        let keytab = http_keytab()?;
        let path = temp_service_keytab_file("config-clockskew")?;
        let name = format!("FILE:{}", path.display());
        keytab
            .save_name(&name)
            .map_err(|cause| format!("keytab saves by name: {cause}"))?;
        let config = config_with_default_keytab_name_and_clockskew(&name, "1s")?;

        let mut named = ServiceValidator::from_default_keytab_name(&config)
            .map_err(|cause| format!("validator loads the configured keytab: {cause}"))?
            .with_now(timestamp(1_893_553_447 + 2)?);
        assert!(matches!(
            named
                .validate_ap_req(&decode_hex(VALID_AP_REQ)?)
                .err()
                .ok_or("declared 1 s window rejects a 2 s stale authenticator")?,
            Error::ClockSkew { max_clock_skew: _ }
        ));

        let mut fresh = ServiceValidator::from_default_keytab_name(&config)
            .map_err(|cause| format!("validator loads the configured keytab: {cause}"))?
            .with_now(timestamp(1_893_553_447)?);
        drop(
            fresh
                .validate_ap_req(&decode_hex(VALID_AP_REQ)?)
                .map_err(|cause| format!("fresh authenticator stays accepted: {cause}"))?,
        );

        let mut default = ServiceValidator::from_default_keytab(&config)
            .map_err(|cause| format!("validator loads the default keytab: {cause}"))?
            .with_now(timestamp(1_893_553_447 + 2)?);
        assert!(matches!(
            default
                .validate_ap_req(&decode_hex(VALID_AP_REQ)?)
                .err()
                .ok_or("default-keytab constructor uses the declared window")?,
            Error::ClockSkew { max_clock_skew: _ }
        ));

        fs::remove_file(&path).map_err(|cause| format!("keytab file is removed: {cause}"))?;
        Ok(())
    }

    /// Pins that `ServiceValidator::new` keeps the gokrb5-compatible 300 s default skew.
    #[test]
    fn service_validator_new_keeps_default_skew() -> Result<(), TestError> {
        let keytab = http_keytab()?;
        let mut tolerant = ServiceValidator::new(&keytab).with_now(timestamp(1_893_553_447 + 2)?);
        drop(
            tolerant
                .validate_ap_req(&decode_hex(VALID_AP_REQ)?)
                .map_err(|cause| {
                    format!("the gokrb5-compatible default accepts a 2 s skew: {cause}")
                })?,
        );

        let mut strict = ServiceValidator::new(&keytab).with_now(timestamp(1_893_553_447 + 301)?);
        assert!(matches!(
            strict
                .validate_ap_req(&decode_hex(VALID_AP_REQ)?)
                .err()
                .ok_or("the default window rejects more than 300 s")?,
            Error::ClockSkew { max_clock_skew: _ }
        ));
        Ok(())
    }

    /// The fixture HTTP keytab plus a copy of its AES-256 key under a second service name.
    fn http_keytab_with_alias() -> Result<Keytab, TestError> {
        let mut keytab = http_keytab()?;
        let mut alias = keytab
            .entries()
            .iter()
            .find(|entry| entry.key.etype == 18_i32 && entry.kvno == 1)
            .ok_or("fixture service key exists")?
            .clone();
        alias.principal.components = vec!["HTTP".to_owned(), "alias.test.gokrb5".to_owned()];
        keytab.entries_mut().push(alias);
        Ok(keytab)
    }

    /// The fixture AP-REQ with its ticket sname replaced by the shared-key alias.
    fn alias_ap_req() -> Result<Vec<u8>, TestError> {
        let mut alias = valid_ap_req_struct()?;
        alias.ticket.sname.string = vec![
            kerberos_string("HTTP")?,
            kerberos_string("alias.test.gokrb5")?,
        ];
        Ok(der::encode(&alias).map_err(|cause| format!("alias AP-REQ encodes: {cause}"))?)
    }

    /// A config naming `keytab_name` as the default keytab, with `clockskew`.
    fn config_with_default_keytab_name_and_clockskew(
        keytab_name: &str,
        clockskew: &str,
    ) -> Result<Config, TestError> {
        let input = format!(
            "
[libdefaults]
 default_keytab_name = {keytab_name}
 clockskew = {clockskew}
",
        );
        Ok(Config::parse(&input).map_err(|cause| format!("config parses: {cause}"))?)
    }

    /// Decode the fixture AP-REQ so a test can vary one cleartext field.
    fn valid_ap_req_struct() -> Result<rasn_kerberos::ApReq, TestError> {
        Ok(der::decode(&decode_hex(VALID_AP_REQ)?)
            .map_err(|cause| format!("fixture AP-REQ decodes: {cause}"))?)
    }

    /// Re-encrypt the fixture authenticator under the ticket session key with a
    /// different client realm and name-type.
    fn reencrypt_authenticator(
        ap_req: &mut rasn_kerberos::ApReq,
        crealm: &str,
        name_type: i32,
    ) -> Result<(), TestError> {
        let session_key = EncryptionKey::new(18, decode_hex(VALID_SESSION_KEY)?);
        let authenticator = rasn_kerberos::Authenticator {
            authenticator_vno: 5_i32.into(),
            crealm: realm(crealm)?,
            cname: rasn_kerberos::PrincipalName {
                r#type: name_type,
                string: vec![kerberos_string("testuser1")?],
            },
            cksum: None,
            cusec: 123_456_i32.into(),
            ctime: kerberos_time(1_893_553_447)?,
            subkey: None,
            seq_number: Some(42),
            authorization_data: None,
        };
        let encoded = der::encode(&authenticator)
            .map_err(|cause| format!("Authenticator encodes: {cause}"))?;
        ap_req.authenticator = rasn_kerberos::EncryptedData {
            etype: session_key.etype,
            kvno: None,
            cipher: encrypt_message(
                &session_key,
                &encoded,
                AP_REQ_AUTHENTICATOR_USAGE_FOR_TEST,
                PAC_AUTHENTICATOR_CONFOUNDER,
            )?
            .into(),
        };
        Ok(())
    }

    /// Decodes a hex fixture.
    fn decode_hex(input: &str) -> Result<Vec<u8>, FromHexError> {
        hex::decode(input)
    }

    /// Encodes bytes as lowercase hex.
    fn hex_encode(bytes: &[u8]) -> String {
        hex::encode(bytes)
    }
}
