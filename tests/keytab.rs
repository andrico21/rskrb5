//! Keytab parsing, round-trip and environment tests.
use core::error;
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use rskrb5::keytab::{EncryptionKey, Entry, Error, Keytab, KeytabName, Principal};

#[path = "support/env.rs"]
mod env;

/// Error type of the `Result`-returning tests.
type TestError = Box<dyn error::Error>;

const KEYTAB_TESTUSER1_TEST_GOKRB5: &str = "05020000003b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d80100110010698c4df8e9f60e7eea5a21bf4526ad25000000010000004b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d80100120020bbdc430aab7e2d4622a0b6951481453b0962e9db8e2f168942ad175cda6d9de9000000010000003b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d80200110010698c4df8e9f60e7eea5a21bf4526ad25000000020000004b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d80200120020bbdc430aab7e2d4622a0b6951481453b0962e9db8e2f168942ad175cda6d9de9000000020000003b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d801001300102eb8501967a7886e1f0c63ac9be8c4a0000000010000003b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d802001300102eb8501967a7886e1f0c63ac9be8c4a0000000020000004b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d801001400208ad66f209bb07daa186f8a229830f5ba06a3a2a33638f4ec66e1d29324e417ee000000010000004b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d802001400208ad66f209bb07daa186f8a229830f5ba06a3a2a33638f4ec66e1d29324e417ee00000002000000430001000b544553542e474f4b52423500097465737475736572310000000159beb1d801001000184580fb91760dabe6f808c22c26494f644cb35d61d32c79e300000001000000430001000b544553542e474f4b52423500097465737475736572310000000159beb1d802001000184580fb91760dabe6f808c22c26494f644cb35d61d32c79e3000000020000003b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d80100170010084768c373663b3bef1f6385883cf7ff000000010000003b0001000b544553542e474f4b52423500097465737475736572310000000159beb1d80200170010084768c373663b3bef1f6385883cf7ff00000002";
const KTUTIL_USER_KEYTAB: &str = "0502000000460001000b4558414d504c452e4f5247000475736572000000015e5e3d001f001200206e88eb2b3931ef17c92e780a4ee421f1411ff5b104e3f75b50dd13f9ed04f9c60000001f000000360001000b4558414d504c452e4f5247000475736572000000015e5e3d001f001100109bb7d5ba0f554412558441a31f2377120000001f000000360001000b4558414d504c452e4f5247000475736572000000015e5e3d001f00170010110d0c51e144d36fb7e4f9e012fbb8880000001f";
const KTUTIL_SERVICE_KEYTAB: &str = "0502000000570002000b4558414d504c452e4f5247000448545450000f7777772e6578616d706c652e6f7267000000015e5e3d820a001200203824a933909d899427d7ead4b4bb6deac4eb83949ac350d724c6a2eef0d627440000000a000000470002000b4558414d504c452e4f5247000448545450000f7777772e6578616d706c652e6f7267000000015e5e3d820a001100103a5cce80f2111d63b1ccf445691384230000000a000000470002000b4558414d504c452e4f5247000448545450000f7777772e6578616d706c652e6f7267000000015e5e3d820a00170010b3f6ed87c7d13879ac3f86b4991099740000000a";

#[expect(
    clippy::default_numeric_fallback,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::tests_outside_test_module,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
#[test]
fn parses_gokrb5_keytab_fixture() {
    let bytes = decode_hex(KEYTAB_TESTUSER1_TEST_GOKRB5);
    let keytab = Keytab::parse(&bytes).expect("keytab fixture parses");

    assert_eq!(keytab.version(), 2);
    assert_eq!(keytab.entries().len(), 12);

    let first = &keytab.entries()[0];
    assert_eq!(first.kvno, 1);
    assert_eq!(first.kvno8, 1);
    assert_eq!(first.timestamp, 1_505_669_592);
    assert_eq!(first.key.etype, 17);
    assert_eq!(
        encode_hex(&first.key.value),
        "698c4df8e9f60e7eea5a21bf4526ad25"
    );
    assert_eq!(first.principal.realm, "TEST.GOKRB5");
    assert_eq!(first.principal.components, ["testuser1"]);
    assert_eq!(first.principal.name_type, 1);
}

#[expect(
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::tests_outside_test_module,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
#[test]
fn roundtrips_gokrb5_keytab_fixture() {
    let bytes = decode_hex(KEYTAB_TESTUSER1_TEST_GOKRB5);
    let keytab = Keytab::parse(&bytes).expect("keytab fixture parses");
    assert_eq!(keytab.to_bytes().expect("keytab serializes"), bytes);
}

#[expect(
    clippy::default_numeric_fallback,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::tests_outside_test_module,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
#[test]
fn generates_gokrb5_user_keytab_entries_from_password() {
    let expected = decode_hex(KTUTIL_USER_KEYTAB);
    let expected_keytab = Keytab::parse(&expected).expect("ktutil keytab parses");
    let timestamp = expected_keytab.entries()[0].system_time();
    let mut keytab = Keytab::new();
    let principal = Principal::new("EXAMPLE.ORG", 1, ["user"]);

    for etype in [18, 17, 23] {
        keytab
            .add_entry_from_password(principal.clone(), b"hello123", timestamp, 31, etype)
            .expect("entry is added");
    }

    assert_eq!(keytab.to_bytes().expect("keytab serializes"), expected);
}

#[expect(
    clippy::default_numeric_fallback,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::tests_outside_test_module,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
#[test]
fn generates_gokrb5_service_keytab_entries_from_password() {
    let expected = decode_hex(KTUTIL_SERVICE_KEYTAB);
    let expected_keytab = Keytab::parse(&expected).expect("ktutil keytab parses");
    let timestamp = expected_keytab.entries()[0].system_time();
    let mut keytab = Keytab::new();
    let principal = Principal::new("EXAMPLE.ORG", 1, ["HTTP", "www.example.org"]);

    for etype in [18, 17, 23] {
        keytab
            .add_entry_from_password(principal.clone(), b"hello456", timestamp, 10, etype)
            .expect("entry is added");
    }

    assert_eq!(keytab.to_bytes().expect("keytab serializes"), expected);
}

#[expect(
    clippy::absolute_paths,
    clippy::default_numeric_fallback,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::tests_outside_test_module,
    unused_qualifications,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
#[test]
fn generates_gokrb5_keytab_entries_from_principal_name() {
    let expected = decode_hex(KTUTIL_SERVICE_KEYTAB);
    let expected_keytab = Keytab::parse(&expected).expect("ktutil keytab parses");
    let timestamp = expected_keytab.entries()[0].system_time();
    let mut keytab = Keytab::new();

    for etype in [18, 17, 23] {
        keytab
            .add_entry_from_password_name(
                "HTTP/www.example.org",
                "EXAMPLE.ORG",
                b"hello456",
                timestamp,
                10,
                etype,
            )
            .expect("entry is added");
    }

    assert_eq!(keytab.to_bytes().expect("keytab serializes"), expected);
    assert!(matches!(
        Principal::from_name("EXAMPLE.ORG", 1, "HTTP/").expect_err("empty component rejected"),
        rskrb5::keytab::Error::InvalidPrincipalName
    ));
}

#[expect(
    clippy::absolute_paths,
    clippy::expect_used,
    clippy::let_underscore_must_use,
    clippy::let_underscore_untyped,
    clippy::missing_panics_doc,
    clippy::tests_outside_test_module,
    let_underscore_drop,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
#[test]
fn saves_and_loads_keytab_file() {
    let bytes = decode_hex(KEYTAB_TESTUSER1_TEST_GOKRB5);
    let keytab = Keytab::parse(&bytes).expect("keytab fixture parses");
    let path = temp_file("save-load");

    keytab.save(&path).expect("keytab saves");
    let loaded = Keytab::load(&path).expect("keytab loads");
    let _ = std::fs::remove_file(&path);

    assert_eq!(loaded, keytab);
}

/// Child-process test of the `KRB5_KTNAME` keytab round trip.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod keytab_env_round_trip {
    use std::env::var;

    use super::*;

    #[expect(
        clippy::absolute_paths,
        clippy::let_underscore_must_use,
        clippy::let_underscore_untyped,
        let_underscore_drop,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )]
    /// Pins that a keytab saved under the `KRB5_KTNAME` file name loads back unchanged.
    #[test]
    fn saves_and_loads_keytab_from_env() -> Result<(), TestError> {
        const TEST_PATH: &str = "keytab_env_round_trip::saves_and_loads_keytab_from_env";
        if !env::in_child(TEST_PATH) {
            let path = temp_file("save-load-env");
            let name = format!("FILE:{}", path.display());
            env::run_in_child(TEST_PATH, &[("KRB5_KTNAME", Some(name.as_ref()))]);
            return Ok(());
        }
        let bytes = decode_hex(KEYTAB_TESTUSER1_TEST_GOKRB5);
        let keytab =
            Keytab::parse(&bytes).map_err(|cause| format!("keytab fixture parses: {cause}"))?;
        let name = var("KRB5_KTNAME")
            .map_err(|cause| format!("the parent test sets KRB5_KTNAME: {cause}"))?;
        let path = PathBuf::from(
            name.strip_prefix("FILE:")
                .ok_or("KRB5_KTNAME names a FILE: path")?,
        );

        keytab
            .save_to_env()
            .map_err(|cause| format!("keytab saves to env name: {cause}"))?;
        let loaded = Keytab::load_from_env()
            .map_err(|cause| format!("keytab loads from env name: {cause}"))?;
        let _ = std::fs::remove_file(&path);

        assert_eq!(loaded, keytab);
        Ok(())
    }
}

/// Child-process test of a missing `KRB5_KTNAME`.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod keytab_env_missing {
    use super::*;

    #[expect(
        clippy::absolute_paths,
        clippy::expect_used,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )]
    /// Pins that loading or saving without `KRB5_KTNAME` names the missing variable.
    #[test]
    fn rejects_missing_keytab_env_name() -> Result<(), TestError> {
        const TEST_PATH: &str = "keytab_env_missing::rejects_missing_keytab_env_name";
        if !env::in_child(TEST_PATH) {
            env::try_run_in_child(TEST_PATH, &[("KRB5_KTNAME", None)])?;
            return Ok(());
        }
        assert!(matches!(
            Keytab::load_from_env().expect_err("missing KRB5_KTNAME rejected on load"),
            Error::DefaultKeytabName(std::env::VarError::NotPresent)
        ));
        assert!(matches!(
            Keytab::new()
                .save_to_env()
                .expect_err("missing KRB5_KTNAME rejected on save"),
            Error::DefaultKeytabName(std::env::VarError::NotPresent)
        ));
        Ok(())
    }
}

#[expect(
    clippy::absolute_paths,
    clippy::expect_used,
    clippy::literal_string_with_formatting_args,
    clippy::missing_panics_doc,
    clippy::tests_outside_test_module,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
#[test]
fn resolves_file_keytab_names() {
    assert_eq!(
        Keytab::file_path_from_keytab_name("/etc/krb5.keytab").expect("bare path resolves"),
        PathBuf::from("/etc/krb5.keytab")
    );
    assert_eq!(
        Keytab::file_path_from_keytab_name("FILE:/etc/krb5.keytab").expect("FILE path resolves"),
        PathBuf::from("/etc/krb5.keytab")
    );
    assert_eq!(
        Keytab::file_path_from_keytab_name("file:/etc/krb5.keytab")
            .expect("lowercase FILE path resolves"),
        PathBuf::from("/etc/krb5.keytab")
    );
    assert_eq!(
        Keytab::file_path_from_keytab_name("WRFILE:relative.keytab").expect("WRFILE path resolves"),
        PathBuf::from("relative.keytab")
    );
    assert_eq!(
        Keytab::file_path_from_keytab_name("C:\\temp\\krb5.keytab").expect("Windows path resolves"),
        PathBuf::from("C:\\temp\\krb5.keytab")
    );

    let uid = std::env::var("UID").unwrap_or_else(|_| "0".to_owned());
    assert_eq!(
        Keytab::file_path_from_keytab_name("FILE:/tmp/krb5_%{uid}.keytab")
            .expect("uid path token resolves"),
        PathBuf::from(format!("/tmp/krb5_{uid}.keytab"))
    );
    assert_eq!(
        Keytab::file_path_from_keytab_name("WRFILE:/tmp/krb5_%{euid}.keytab")
            .expect("euid path token resolves"),
        PathBuf::from(format!("/tmp/krb5_{uid}.keytab"))
    );
}

#[expect(
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::shadow_unrelated,
    clippy::tests_outside_test_module,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
#[test]
fn parses_typed_file_keytab_names() {
    let parsed = KeytabName::parse("FILE:/etc/krb5.keytab").expect("FILE keytab name parses");
    assert_eq!(parsed.file_path(), PathBuf::from("/etc/krb5.keytab"));
    assert_eq!(parsed.into_file_path(), PathBuf::from("/etc/krb5.keytab"));

    let parsed: KeytabName = "WRFILE:relative.keytab"
        .parse()
        .expect("WRFILE keytab name parses through FromStr");
    assert_eq!(parsed.file_path(), PathBuf::from("relative.keytab"));

    let parsed = KeytabName::parse("C:\\temp\\krb5.keytab").expect("Windows path parses");
    assert_eq!(parsed.file_path(), PathBuf::from("C:\\temp\\krb5.keytab"));
}

#[expect(
    clippy::absolute_paths,
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::tests_outside_test_module,
    unused_qualifications,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
#[test]
fn rejects_unsupported_keytab_names() {
    assert!(matches!(
        Keytab::file_path_from_keytab_name("").expect_err("empty name rejected"),
        rskrb5::keytab::Error::InvalidKeytabName
    ));
    assert!(matches!(
        Keytab::file_path_from_keytab_name("FILE:").expect_err("empty FILE path rejected"),
        rskrb5::keytab::Error::InvalidKeytabName
    ));
    assert!(matches!(
        Keytab::file_path_from_keytab_name("DIR:/tmp/krb5.keytab")
            .expect_err("DIR keytab rejected"),
        rskrb5::keytab::Error::UnsupportedKeytabType { keytab_type } if keytab_type == "DIR"
    ));
    assert!(matches!(
        Keytab::file_path_from_keytab_name("MEMORY:test").expect_err("MEMORY keytab rejected"),
        rskrb5::keytab::Error::UnsupportedKeytabType { keytab_type } if keytab_type == "MEMORY"
    ));
}

#[expect(
    clippy::missing_panics_doc,
    clippy::tests_outside_test_module,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
#[test]
fn encryption_key_debug_redacts_value() {
    let key = EncryptionKey {
        etype: 18,
        value: vec![1, 2, 3, 4],
    };
    let debug = format!("{key:?}");

    assert_eq!(debug, "EncryptionKey { etype: 18, value_len: 4 }");
    assert!(!debug.contains("1, 2, 3, 4"));
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::default_numeric_fallback,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::missing_panics_doc,
        clippy::tests_outside_test_module,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[cfg(feature = "serde")]
#[test]
fn keytab_metadata_json_redacts_key_values() {
    let bytes = decode_hex(KTUTIL_USER_KEYTAB);
    let keytab = Keytab::parse(&bytes).expect("keytab parses");
    let metadata = keytab.entry_metadata();

    assert_eq!(metadata.len(), 3);
    assert_eq!(metadata[0].principal, "user@EXAMPLE.ORG");
    assert_eq!(metadata[0].etype, 18);
    assert_eq!(metadata[0].key_length, 32);

    let json = keytab.entries_json().expect("keytab JSON renders");
    assert!(json.contains(r#""Principal": "user@EXAMPLE.ORG""#));
    assert!(json.contains(r#""KeyLength": 32"#));
    assert!(
        !json.contains("6e88eb2b3931ef17c92e780a4ee421f1411ff5b104e3f75b50dd13f9ed04f9c6"),
        "raw key material is not rendered"
    );
}

#[expect(
    clippy::absolute_paths,
    clippy::expect_used,
    clippy::let_underscore_must_use,
    clippy::let_underscore_untyped,
    clippy::missing_panics_doc,
    clippy::tests_outside_test_module,
    let_underscore_drop,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
#[test]
fn saves_and_loads_file_keytab_name() {
    let bytes = decode_hex(KEYTAB_TESTUSER1_TEST_GOKRB5);
    let keytab = Keytab::parse(&bytes).expect("keytab fixture parses");
    let path = temp_file("save-load-name");
    let name = format!("FILE:{}", path.display());

    keytab.save_name(&name).expect("keytab saves by name");
    let loaded = Keytab::load_name(&name).expect("keytab loads by name");
    let _ = std::fs::remove_file(&path);

    assert_eq!(loaded, keytab);
}

#[expect(
    clippy::assertions_on_result_states,
    clippy::default_numeric_fallback,
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::tests_outside_test_module,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
#[test]
fn finds_matching_key_by_principal_kvno_and_etype() {
    let bytes = decode_hex(KEYTAB_TESTUSER1_TEST_GOKRB5);
    let keytab = Keytab::parse(&bytes).expect("keytab fixture parses");

    let (key, kvno) = keytab
        .find_key(&["testuser1"], "TEST.GOKRB5", 2, 18)
        .expect("matching key exists");
    assert_eq!(kvno, 2);
    assert_eq!(key.etype, 18);
    assert_eq!(
        encode_hex(&key.value),
        "bbdc430aab7e2d4622a0b6951481453b0962e9db8e2f168942ad175cda6d9de9"
    );

    assert!(
        keytab
            .find_key(&["testuser2"], "TEST.GOKRB5", 0, 18)
            .is_err()
    );
}

#[expect(
    clippy::default_numeric_fallback,
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::tests_outside_test_module,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
#[test]
fn finds_rc4_hmac_and_des3_keys_from_gokrb5_fixture() {
    let bytes = decode_hex(KEYTAB_TESTUSER1_TEST_GOKRB5);
    let keytab = Keytab::parse(&bytes).expect("keytab fixture parses");

    let (des3_key, des3_kvno) = keytab
        .find_key(&["testuser1"], "TEST.GOKRB5", 2, 16)
        .expect("DES3 key exists");
    assert_eq!(des3_kvno, 2);
    assert_eq!(des3_key.etype, 16);
    assert_eq!(
        encode_hex(&des3_key.value),
        "4580fb91760dabe6f808c22c26494f644cb35d61d32c79e3"
    );

    let (rc4_key, rc4_kvno) = keytab
        .find_key(&["testuser1"], "TEST.GOKRB5", 2, 23)
        .expect("RC4-HMAC key exists");
    assert_eq!(rc4_kvno, 2);
    assert_eq!(rc4_key.etype, 23);
    assert_eq!(
        encode_hex(&rc4_key.value),
        "084768c373663b3bef1f6385883cf7ff"
    );
}

#[expect(
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::tests_outside_test_module,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
#[test]
fn kvno_zero_selects_newest_matching_key() {
    let mut keytab = Keytab::new();
    keytab.entries_mut().extend([
        synthetic_entry("HTTP", 1, 18, 100),
        synthetic_entry("HTTP", 2, 18, 200),
        synthetic_entry("HTTP", 3, 18, 150),
        synthetic_entry("HTTP", 4, 17, 300),
    ]);

    let (_, kvno) = keytab
        .find_key(&["HTTP"], "TEST.GOKRB5", 0, 18)
        .expect("newest matching key exists");
    assert_eq!(kvno, 2);
}

#[expect(
    clippy::assertions_on_result_states,
    clippy::missing_panics_doc,
    clippy::tests_outside_test_module,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
#[test]
fn rejects_invalid_keytab_inputs() {
    assert!(Keytab::parse(&[]).is_err());
    assert!(Keytab::parse(&[5]).is_err());
    assert!(Keytab::parse(&[4, 2]).is_err());
    assert!(Keytab::parse(&[5, 9]).is_err());
    assert!(Keytab::parse(&[5, 2, 0, 0, 0, 16]).is_err());
}

#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
fn synthetic_entry(component: &str, kvno: u32, etype: i32, timestamp: u32) -> Entry {
    Entry {
        principal: Principal {
            realm: "TEST.GOKRB5".to_owned(),
            components: vec![component.to_owned()],
            name_type: 1,
        },
        timestamp,
        kvno8: kvno as u8,
        key: EncryptionKey {
            etype,
            value: vec![kvno as u8; 4],
        },
        kvno,
    }
}

#[expect(
    clippy::default_numeric_fallback,
    clippy::integer_division_remainder_used,
    clippy::missing_panics_doc,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
fn decode_hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0, "hex input has even length");
    input
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = hex_value(pair[0]);
            let low = hex_value(pair[1]);
            (high << 4) | low
        })
        .collect()
}

#[expect(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::default_numeric_fallback,
    clippy::indexing_slicing,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[expect(
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc,
    clippy::panic,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex byte: {byte}"),
    }
}

#[expect(
    clippy::absolute_paths,
    clippy::expect_used,
    clippy::missing_panics_doc,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
fn temp_file(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("current time is after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "rskrb5-keytab-{name}-{}-{nanos}",
        std::process::id()
    ))
}
