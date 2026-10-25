//! Configuration parsing, loading and realm resolution tests.
use core::{error, time::Duration};
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use pretty_assertions::assert_eq;
use rskrb5::config::{Config, Error, parse_duration};

#[path = "support/env.rs"]
mod env;

/// Error type of the `Result`-returning tests.
type TestError = Box<dyn error::Error>;

#[expect(
    clippy::needless_raw_strings,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
const KRB5_CONF: &str = r#"[libdefaults]
  default_realm = TEST.GOKRB5
  dns_lookup_realm = false
  dns_lookup_kdc = false
  ticket_lifetime = 24h
  forwardable = yes
  default_tkt_enctypes = aes256-cts-hmac-sha1-96
  default_tgs_enctypes = aes256-cts-hmac-sha1-96
  noaddresses = false

[realms]
 TEST.GOKRB5 = {
  kdc = 127.0.0.1:88
  kdc = 127.0.0.2:88
  admin_server = 127.0.0.1:749
  default_domain = test.gokrb5
 }
 RESDOM.GOKRB5 = {
  kdc = 10.80.88.88:188
  admin_server = 127.0.0.1:749
  default_domain = resdom.gokrb5
 }

[domain_realm]
 .test.gokrb5 = TEST.GOKRB5
 test.gokrb5 = TEST.GOKRB5
 .resdom.gokrb5 = RESDOM.GOKRB5
 resdom.gokrb5 = RESDOM.GOKRB5
 "#;

#[expect(
    clippy::needless_raw_strings,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
const COMPLEX_KRB5_CONF: &str = r#"
[logging]
 default = FILE:/var/log/kerberos/krb5libs.log

[libdefaults]
 default_realm = TEST.GOKRB5 ; comment to be ignored
 dns_lookup_realm = false
 dns_lookup_kdc = false
 #dns_lookup_kdc = true
 ;dns_lookup_kdc = true
 ticket_lifetime = 10h ;comment to be ignored
 forwardable = yes #comment to be ignored
 default_ccache_name = DIR:/tmp/krb5cc_dir
 default_keytab_name = FILE:/etc/krb5.keytab
 default_client_keytab_name = FILE:/home/gokrb5/client.keytab
 default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 # comment

[realms]
 TEST.GOKRB5 = {
  kdc = 10.80.88.88:88 #comment to be ignored
  kdc = assume.port.num ;comment to be ignored
  kdc = some.other.port:1234 # comment to be ignored
  kdc = 10.80.88.88*
  kdc = 10.1.2.3.4:88
  admin_server = 10.80.88.88:749 ; comment to be ignored
  default_domain = test.gokrb5
 }
 EXAMPLE.COM = {
        kdc = kerberos.example.com
        kdc = kerberos-1.example.com
        admin_server = kerberos.example.com
        auth_to_local = RULE:[1:$1@$0](.*@EXAMPLE.COM)s/.*//
 }
	lowercase.org = {
		kdc = kerberos.lowercase.org
		admin_server = kerberos.lowercase.org
	}

[domain_realm]
 .test.gokrb5 = TEST.GOKRB5 #comment to be ignored
 test.gokrb5 = TEST.GOKRB5 ;comment to be ignored
 .example.com = EXAMPLE.COM # comment to be ignored
 hostname1.example.com = EXAMPLE.COM ; comment to be ignored
 hostname2.example.com = TEST.GOKRB5
 .testlowercase.org = lowercase.org

[appdefaults]
 pam = {
   debug = false
 }
"#;

/// Property tests for the explicit `permitted_enctypes` serde flag and the
/// `[domain_realm]` DNS case fold.
#[cfg(test)]
mod fork_property_tests {
    use proptest::{collection, prelude::any, prop_assert_eq, proptest, sample};
    #[cfg(feature = "serde")]
    use proptest::{prelude::Strategy, prop_assert};
    use rskrb5::config::Config;
    #[cfg(feature = "serde")]
    use rskrb5::config::LibDefaults;

    /// Every supported enctype name, aliases included, with its enctype ID.
    #[cfg(feature = "serde")]
    const SUPPORTED_ENCTYPES: [(&str, i32); 14] = [
        ("aes128-cts-hmac-sha1-96", 17),
        ("aes128-cts", 17),
        ("aes128-sha1", 17),
        ("aes256-cts-hmac-sha1-96", 18),
        ("aes256-cts", 18),
        ("aes256-sha1", 18),
        ("aes128-cts-hmac-sha256-128", 19),
        ("aes128-sha2", 19),
        ("aes256-cts-hmac-sha384-192", 20),
        ("aes256-sha2", 20),
        ("des3-cbc-sha1-kd", 16),
        ("arcfour-hmac", 23),
        ("rc4-hmac", 23),
        ("arcfour-hmac-md5", 23),
    ];

    /// A `[domain_realm]` section with a leading-dot tag and a bare tag.
    const DOMAIN_REALM_CONF: &str = "[libdefaults]
 default_realm = CLIENT.REALM

[domain_realm]
 .example.com = SUFFIX.REALM
 example.org = BARE.REALM
";

    /// The configured suffixes, each with the realm its subdomains resolve to.
    const CONFIGURED_SUFFIXES: [(&str, &str); 2] = [
        (".example.com", "SUFFIX.REALM"),
        (".example.org", "BARE.REALM"),
    ];

    /// Length of the generated case mask; longer than any generated host.
    const CASE_MASK_LEN: usize = 64;

    /// A non-empty subset of [`SUPPORTED_ENCTYPES`], in arbitrary order.
    #[cfg(feature = "serde")]
    fn enctype_subset() -> impl Strategy<Value = Vec<(&'static str, i32)>> {
        sample::subsequence(SUPPORTED_ENCTYPES.to_vec(), 1..=SUPPORTED_ENCTYPES.len())
            .prop_shuffle()
    }

    proptest! {
        /// Any non-empty explicit `permitted_enctypes` list keeps
        /// `permitted_enctypes_explicit == true` and the same derived IDs
        /// through a serde round trip.
        #[cfg(feature = "serde")]
        #[test]
        fn permitted_enctypes_survive_a_serde_round_trip(enctypes in enctype_subset()) {
            let names: Vec<&str> = enctypes.iter().map(|entry| entry.0).collect();
            let expected_ids: Vec<i32> = enctypes.iter().map(|entry| entry.1).collect();
            let config = Config::parse(&format!(
                "[libdefaults]\n permitted_enctypes = {}\n",
                names.join(" ")
            ))?;
            prop_assert!(config.libdefaults.permitted_enctypes_explicit, "parsed list is explicit");
            prop_assert_eq!(&config.libdefaults.permitted_enctype_ids, &expected_ids);

            let json = serde_json::to_string(&config.libdefaults)?;
            let decoded: LibDefaults = serde_json::from_str(&json)?;

            prop_assert!(decoded.permitted_enctypes_explicit, "explicit flag survives serde");
            prop_assert_eq!(&decoded.permitted_enctype_ids, &expected_ids);
            prop_assert_eq!(decoded, config.libdefaults);
        }

        /// Any ASCII case permutation of a host under a configured
        /// `[domain_realm]` suffix, with or without a trailing root dot,
        /// resolves to that suffix's realm.
        #[test]
        fn resolve_realm_ignores_host_case(
            labels in "[a-z0-9]{1,10}(\\.[a-z0-9]{1,10}){0,3}",
            suffix in sample::select(CONFIGURED_SUFFIXES.to_vec()),
            case_mask in collection::vec(any::<bool>(), CASE_MASK_LEN),
            trailing_dot in any::<bool>(),
        ) {
            let config = Config::parse(DOMAIN_REALM_CONF)?;
            let (domain, realm) = suffix;
            let host = format!("{labels}{domain}");
            let mut permuted: String = host
                .chars()
                .enumerate()
                .map(|(index, character)| {
                    if case_mask.get(index) == Some(&true) {
                        character.to_ascii_uppercase()
                    } else {
                        character
                    }
                })
                .collect();
            if trailing_dot {
                permuted.push('.');
            }

            prop_assert_eq!(config.resolve_realm(&host), Some(realm));
            prop_assert_eq!(config.resolve_realm(&permuted), Some(realm), "{}", permuted);
        }
    }
}

#[expect(
    clippy::missing_panics_doc,
    clippy::tests_outside_test_module,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
#[test]
fn libdefaults_defaults_match_gokrb5() {
    let config = Config::new();

    assert!(!config.libdefaults.dns_lookup_kdc);
    assert!(!config.libdefaults.dns_lookup_realm);
    assert!(config.libdefaults.dns_canonicalize_hostname);
    assert!(config.libdefaults.no_addresses);
}

#[expect(
    clippy::default_numeric_fallback,
    clippy::duration_suboptimal_units,
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::tests_outside_test_module,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
#[test]
fn parses_gokrb5_integration_config_fixture() {
    let config = Config::parse(KRB5_CONF).expect("config parses");

    assert_eq!(config.libdefaults.default_realm, "TEST.GOKRB5");
    assert!(!config.libdefaults.dns_lookup_realm);
    assert!(!config.libdefaults.dns_lookup_kdc);
    assert!(!config.libdefaults.no_addresses);
    assert!(config.libdefaults.forwardable);
    assert_eq!(
        config.libdefaults.ticket_lifetime,
        Duration::from_secs(24 * 60 * 60)
    );
    assert_eq!(config.libdefaults.default_tkt_enctype_ids, [18]);
    assert_eq!(config.libdefaults.default_tgs_enctype_ids, [18]);

    assert_eq!(config.realms.len(), 2);
    assert_eq!(
        config.configured_kdcs("TEST.GOKRB5").expect("KDCs exist"),
        ["127.0.0.1:88", "127.0.0.2:88"]
    );
    assert_eq!(
        config
            .configured_kpasswd_servers("TEST.GOKRB5")
            .expect("kpasswd servers default from admin_server"),
        ["127.0.0.1:464"]
    );
    assert_eq!(
        config.resolve_realm("host.test.gokrb5"),
        Some("TEST.GOKRB5")
    );
    assert_eq!(
        config.resolve_realm("resdom.gokrb5."),
        Some("RESDOM.GOKRB5")
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
fn loads_config_file() {
    let path = temp_file("load");
    std::fs::write(&path, KRB5_CONF).expect("config fixture writes");

    let config = Config::load(&path).expect("config loads");
    let _ = std::fs::remove_file(&path);

    assert_eq!(config.libdefaults.default_realm, "TEST.GOKRB5");
    assert_eq!(
        config.configured_kdcs("TEST.GOKRB5").expect("KDCs exist"),
        ["127.0.0.1:88", "127.0.0.2:88"]
    );
}

#[expect(
    clippy::absolute_paths,
    clippy::expect_used,
    clippy::let_underscore_must_use,
    clippy::let_underscore_untyped,
    clippy::missing_panics_doc,
    clippy::needless_raw_strings,
    clippy::tests_outside_test_module,
    let_underscore_drop,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
#[test]
fn loads_config_path_list_in_order() {
    let first = temp_file("load-list-first");
    let second = temp_file("load-list-second");
    std::fs::write(
        &first,
        r#"
[libdefaults]
 default_realm = FIRST.GOKRB5

[domain_realm]
 .first.gokrb5 = FIRST.GOKRB5
"#,
    )
    .expect("first config writes");
    std::fs::write(
        &second,
        r#"
[libdefaults]
 default_realm = SECOND.GOKRB5

[domain_realm]
 .second.gokrb5 = SECOND.GOKRB5
"#,
    )
    .expect("second config writes");

    let config = Config::load_paths([first.clone(), PathBuf::new(), second.clone()])
        .expect("config path list loads");
    let _ = std::fs::remove_file(&first);
    let _ = std::fs::remove_file(&second);

    assert_eq!(config.libdefaults.default_realm, "SECOND.GOKRB5");
    assert_eq!(
        config.resolve_realm("host.first.gokrb5"),
        Some("FIRST.GOKRB5")
    );
    assert_eq!(
        config.resolve_realm("host.second.gokrb5"),
        Some("SECOND.GOKRB5")
    );
}

/// Child-process tests of `KRB5_CONFIG` loading.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
mod config_env {
    use std::env::{join_paths, split_paths, var_os};

    use pretty_assertions::assert_eq;

    use super::*;

    #[expect(
        clippy::absolute_paths,
        clippy::let_underscore_must_use,
        clippy::let_underscore_untyped,
        clippy::needless_raw_strings,
        let_underscore_drop,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )]
    /// Pins that `KRB5_CONFIG` path lists load with the later file winning.
    #[test]
    fn loads_config_path_list_from_env() -> Result<(), TestError> {
        const TEST_PATH: &str = "config_env::loads_config_path_list_from_env";
        if !env::in_child(TEST_PATH) {
            let paths = join_paths([temp_file("load-env-first"), temp_file("load-env-second")])
                .map_err(|cause| format!("config paths join: {cause}"))?;
            env::run_in_child(TEST_PATH, &[("KRB5_CONFIG", Some(&paths))]);
            return Ok(());
        }
        let paths = var_os("KRB5_CONFIG").ok_or("the parent test sets KRB5_CONFIG")?;
        let [first, second]: [PathBuf; 2] =
            split_paths(&paths).collect::<Vec<_>>().try_into().map_err(
                |listed: Vec<PathBuf>| format!("KRB5_CONFIG lists two paths: {}", listed.len()),
            )?;
        std::fs::write(
            &first,
            r#"
[libdefaults]
 default_realm = FIRST.GOKRB5
"#,
        )
        .map_err(|cause| format!("first config writes: {cause}"))?;
        std::fs::write(
            &second,
            r#"
[libdefaults]
 default_realm = SECOND.GOKRB5
"#,
        )
        .map_err(|cause| format!("second config writes: {cause}"))?;

        let config = Config::load_from_env()
            .map_err(|cause| format!("config loads from KRB5_CONFIG: {cause}"))?;
        let _ = std::fs::remove_file(&first);
        let _ = std::fs::remove_file(&second);

        assert_eq!(config.libdefaults.default_realm, "SECOND.GOKRB5");
        Ok(())
    }

    #[expect(
        clippy::absolute_paths,
        clippy::let_underscore_must_use,
        clippy::let_underscore_untyped,
        clippy::needless_raw_strings,
        let_underscore_drop,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )]
    /// Pins that `load_default` and `load_default_or_parse` prefer `KRB5_CONFIG`.
    #[test]
    fn load_default_prefers_krb5_config_env() -> Result<(), TestError> {
        const TEST_PATH: &str = "config_env::load_default_prefers_krb5_config_env";
        if !env::in_child(TEST_PATH) {
            let path = temp_file("load-default-env");
            env::run_in_child(TEST_PATH, &[("KRB5_CONFIG", Some(path.as_os_str()))]);
            return Ok(());
        }
        let path = PathBuf::from(var_os("KRB5_CONFIG").ok_or("the parent test sets KRB5_CONFIG")?);
        std::fs::write(
            &path,
            r#"
[libdefaults]
 default_realm = ENV.GOKRB5
"#,
        )
        .map_err(|cause| format!("env config writes: {cause}"))?;

        let config = Config::load_default()
            .map_err(|cause| format!("default config loads from env: {cause}"))?;
        let fallback = Config::load_default_or_parse(
            r#"
[libdefaults]
 default_realm = EMBEDDED.GOKRB5
"#,
        )
        .map_err(|cause| format!("default-or-embedded config loads from env: {cause}"))?;
        let _ = std::fs::remove_file(&path);

        assert_eq!(config.libdefaults.default_realm, "ENV.GOKRB5");
        assert_eq!(fallback.libdefaults.default_realm, "ENV.GOKRB5");
        Ok(())
    }
}

#[expect(
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::tests_outside_test_module,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
#[test]
fn rejects_empty_config_path_list() {
    assert!(matches!(
        Config::load_paths(Vec::<PathBuf>::new()).expect_err("empty path list rejected"),
        Error::EmptyConfigPathList
    ));
    assert!(matches!(
        Config::load_paths([PathBuf::new()]).expect_err("empty path rejected"),
        Error::EmptyConfigPathList
    ));
}

/// Child-process test of a missing `KRB5_CONFIG`.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod config_env_missing {
    use super::*;

    #[expect(
        clippy::expect_used,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )]
    /// Pins that loading without `KRB5_CONFIG` reports the missing variable.
    #[test]
    fn rejects_missing_config_env() -> Result<(), TestError> {
        const TEST_PATH: &str = "config_env_missing::rejects_missing_config_env";
        if !env::in_child(TEST_PATH) {
            env::try_run_in_child(TEST_PATH, &[("KRB5_CONFIG", None)])?;
            return Ok(());
        }
        assert!(matches!(
            Config::load_from_env().expect_err("missing KRB5_CONFIG rejected"),
            Error::DefaultConfigName
        ));
        Ok(())
    }
}

#[expect(
    clippy::default_numeric_fallback,
    clippy::duration_suboptimal_units,
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::tests_outside_test_module,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
#[test]
fn parses_complex_gokrb5_config_semantics() {
    let config = Config::parse(COMPLEX_KRB5_CONF).expect("config parses");

    assert_eq!(config.libdefaults.default_realm, "TEST.GOKRB5");
    assert_eq!(
        config.libdefaults.ticket_lifetime,
        Duration::from_secs(10 * 60 * 60)
    );
    assert_eq!(
        config.libdefaults.default_keytab_name,
        "FILE:/etc/krb5.keytab"
    );
    assert_eq!(
        config.libdefaults.default_ccache_name,
        "DIR:/tmp/krb5cc_dir"
    );
    assert_eq!(
        config.libdefaults.default_client_keytab_name,
        "FILE:/home/gokrb5/client.keytab"
    );
    assert_eq!(
        config.libdefaults.default_tkt_enctypes,
        ["aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"]
    );
    assert_eq!(config.libdefaults.default_tkt_enctype_ids, [18, 17]);
    assert_eq!(config.libdefaults.default_tgs_enctype_ids, [18, 17, 23]);

    assert_eq!(config.realms.len(), 3);
    let test_realm = config.realm("TEST.GOKRB5").expect("TEST realm exists");
    assert_eq!(test_realm.realm, "TEST.GOKRB5");
    assert_eq!(test_realm.admin_server, ["10.80.88.88:749"]);
    assert_eq!(test_realm.kpasswd_server, ["10.80.88.88:464"]);
    assert_eq!(test_realm.default_domain, "test.gokrb5");
    assert_eq!(
        test_realm.kdc,
        [
            "10.80.88.88:88",
            "assume.port.num:88",
            "some.other.port:1234",
            "10.80.88.88:88"
        ]
    );

    let example = config.realm("EXAMPLE.COM").expect("example realm exists");
    assert_eq!(
        example.kdc,
        ["kerberos.example.com:88", "kerberos-1.example.com:88"]
    );
    assert_eq!(example.admin_server, ["kerberos.example.com"]);
    assert_eq!(example.kpasswd_server, ["kerberos.example.com:464"]);

    assert_eq!(
        config.domain_realm.get(".test.gokrb5").map(String::as_str),
        Some("TEST.GOKRB5")
    );
    assert_eq!(
        config.domain_realm.get("test.gokrb5").map(String::as_str),
        Some("TEST.GOKRB5")
    );
}

#[expect(
    clippy::default_numeric_fallback,
    clippy::duration_suboptimal_units,
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::needless_raw_strings,
    clippy::tests_outside_test_module,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
#[test]
fn parses_gokrb5_config_without_blank_lines() {
    let config = Config::parse(
        r#"[logging]
 default = FILE:/var/log/kerberos/krb5libs.log
[libdefaults]
 default_realm = TEST.GOKRB5
 dns_lookup_realm = false
 dns_lookup_kdc = false
 ticket_lifetime = 10h
 forwardable = yes
 default_keytab_name = FILE:/etc/krb5.keytab
 default_client_keytab_name = FILE:/home/gokrb5/client.keytab
 default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
[realms]
 TEST.GOKRB5 = {
  kdc = 10.80.88.88:88
  kdc = assume.port.num
  admin_server = 10.80.88.88:749
  default_domain = test.gokrb5
 }
 EXAMPLE.COM = {
  kdc = kerberos.example.com
  admin_server = kerberos.example.com
 }
[domain_realm]
 .test.gokrb5 = TEST.GOKRB5
 test.gokrb5 = TEST.GOKRB5
"#,
    )
    .expect("config parses");

    assert_eq!(config.libdefaults.default_realm, "TEST.GOKRB5");
    assert_eq!(
        config.libdefaults.ticket_lifetime,
        Duration::from_secs(10 * 60 * 60)
    );
    assert_eq!(config.libdefaults.default_tkt_enctype_ids, [18, 17]);
    assert_eq!(config.realms.len(), 2);
    assert_eq!(
        config.realm("TEST.GOKRB5").expect("TEST realm exists").kdc,
        ["10.80.88.88:88", "assume.port.num:88"]
    );
    assert_eq!(
        config.resolve_realm("host.test.gokrb5"),
        Some("TEST.GOKRB5")
    );
}

#[expect(
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::needless_raw_strings,
    clippy::tests_outside_test_module,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
#[test]
fn parses_gokrb5_config_with_tabs_and_reordered_sections() {
    let config = Config::parse(
        r#"[logging]
	default = FILE:/var/log/kerberos/krb5libs.log

[libdefaults]
	default_realm = TEST.GOKRB5
	dns_lookup_realm = false
	dns_lookup_kdc = false
	ticket_lifetime = 10h
	forwardable = yes
	default_keytab_name = FILE:/etc/krb5.keytab
	default_client_keytab_name = FILE:/home/gokrb5/client.keytab
	default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96

[domain_realm]
	.test.gokrb5 = TEST.GOKRB5
	test.gokrb5 = TEST.GOKRB5
	.example.com = EXAMPLE.COM
	hostname1.example.com = EXAMPLE.COM

[appdefaults]
	pam = {
	 debug = false
	}

[realms]
	TEST.GOKRB5 = {
		kdc = 10.80.88.88:88
		kdc = assume.port.num
		admin_server = 10.80.88.88:749
		default_domain = test.gokrb5
	}
	EXAMPLE.COM = {
		kdc = kerberos.example.com
		kdc = kerberos-1.example.com
		admin_server = kerberos.example.com
	}
"#,
    )
    .expect("config parses");

    assert_eq!(config.libdefaults.default_realm, "TEST.GOKRB5");
    assert_eq!(config.realms.len(), 2);
    assert_eq!(
        config
            .realm("EXAMPLE.COM")
            .expect("example realm exists")
            .kdc,
        ["kerberos.example.com:88", "kerberos-1.example.com:88"]
    );
    assert_eq!(
        config.resolve_realm("hostname1.example.com"),
        Some("EXAMPLE.COM")
    );
}

#[expect(
    clippy::duration_suboptimal_units,
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::tests_outside_test_module,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
#[test]
fn duration_formats_match_gokrb5() {
    let cases = [
        ("100", Duration::from_secs(100)),
        ("12:30", Duration::from_secs(12 * 60 * 60 + 30 * 60)),
        ("12:30:15", Duration::from_secs(12 * 60 * 60 + 30 * 60 + 15)),
        (
            "1d12h30m15s",
            Duration::from_secs(24 * 60 * 60 + 12 * 60 * 60 + 30 * 60 + 15),
        ),
        (
            "1d12h30m",
            Duration::from_secs(24 * 60 * 60 + 12 * 60 * 60 + 30 * 60),
        ),
        ("1d12h", Duration::from_secs(24 * 60 * 60 + 12 * 60 * 60)),
        ("1d", Duration::from_secs(24 * 60 * 60)),
    ];

    for (input, expected) in cases {
        assert_eq!(parse_duration(input).expect("duration parses"), expected);
    }
}

#[expect(
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::tests_outside_test_module,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
#[test]
fn resolve_realm_matches_gokrb5_specificity() {
    let config = Config::parse(COMPLEX_KRB5_CONF).expect("config parses");
    assert_eq!(config.resolve_realm("unknown.com"), None);
    assert_eq!(
        config.resolve_realm("hostname1.example.com"),
        Some("EXAMPLE.COM")
    );
    assert_eq!(
        config.resolve_realm("hostname2.example.com"),
        Some("TEST.GOKRB5")
    );
    assert_eq!(
        config.resolve_realm("one.two.three.example.com"),
        Some("EXAMPLE.COM")
    );
    assert_eq!(config.resolve_realm(".test.gokrb5"), Some("TEST.GOKRB5"));
    assert_eq!(
        config.resolve_realm("foo.testlowercase.org"),
        Some("lowercase.org")
    );
}

#[expect(
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::needless_raw_strings,
    clippy::tests_outside_test_module,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
#[test]
fn configured_kdcs_are_used_even_when_dns_lookup_is_enabled() {
    let config = Config::parse(
        r#"
[libdefaults]
 dns_lookup_kdc = true

[realms]
 TEST.GOKRB5 = {
  kdc = kdc2b.test.gokrb5:88
 }
"#,
    )
    .expect("config parses");

    assert!(config.libdefaults.dns_lookup_kdc);
    assert_eq!(
        config.configured_kdcs("TEST.GOKRB5").expect("KDCs exist"),
        ["kdc2b.test.gokrb5:88"]
    );
}

#[expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::needless_raw_strings,
    clippy::tests_outside_test_module,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
#[test]
fn libdefaults_keys_are_case_insensitive_and_extra_addresses_are_comma_separated() {
    let config = Config::parse(
        r#"
[libdefaults]
 DEFAULT_REALM = TEST.GOKRB5
 EXTRA_ADDRESSES = 127.0.0.1, 127.0.0.2, not-an-ip
 FORWARDABLE = TRUE
"#,
    )
    .expect("config parses");

    assert_eq!(config.libdefaults.default_realm, "TEST.GOKRB5");
    assert!(config.libdefaults.forwardable);
    assert_eq!(config.libdefaults.extra_addresses.len(), 2);
    assert_eq!(
        config.libdefaults.extra_addresses[0].to_string(),
        "127.0.0.1"
    );
    assert_eq!(
        config.libdefaults.extra_addresses[1].to_string(),
        "127.0.0.2"
    );
}

#[expect(
    clippy::default_numeric_fallback,
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::needless_raw_strings,
    clippy::tests_outside_test_module,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
#[test]
fn maps_rc4_hmac_enctype_aliases() {
    let config = Config::parse(
        r#"
[libdefaults]
 default_tkt_enctypes = arcfour-hmac rc4-hmac arcfour-hmac-md5
 default_tgs_enctypes = rc4-hmac
"#,
    )
    .expect("config parses");

    assert_eq!(config.libdefaults.default_tkt_enctype_ids, [23, 23, 23]);
    assert_eq!(config.libdefaults.default_tgs_enctype_ids, [23]);
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
        clippy::unseparated_literal_suffix,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[cfg(feature = "serde")]
#[test]
fn config_json_matches_gokrb5_shape() {
    let mut config = Config::parse(COMPLEX_KRB5_CONF).expect("config parses");
    config.libdefaults.k5login_directory = "/home/test".to_owned();

    let json = config.json().expect("config JSON renders");
    let value: serde_json::Value = serde_json::from_str(&json).expect("config JSON parses");

    assert!(json.contains(r#""LibDefaults""#));
    assert!(json.contains(r#""DefaultTGSEnctypes""#));
    assert!(json.contains(r#""DefaultTktEnctypeIDs""#));
    assert_eq!(
        value["LibDefaults"]["Clockskew"],
        serde_json::json!(300_000_000_000u64)
    );
    assert_eq!(
        value["LibDefaults"]["TicketLifetime"],
        serde_json::json!(36_000_000_000_000u64)
    );
    assert_eq!(
        value["LibDefaults"]["KDCDefaultOptions"]["Bytes"],
        serde_json::json!("AAAAEA==")
    );
    assert_eq!(
        value["LibDefaults"]["KDCDefaultOptions"]["BitLength"],
        serde_json::json!(32)
    );
    assert_eq!(
        value["LibDefaults"]["K5LoginDirectory"],
        serde_json::json!("/home/test")
    );
    assert_eq!(
        value["Realms"][0]["KPasswdServer"][0],
        serde_json::json!("10.80.88.88:464")
    );
    assert_eq!(value["Realms"][0]["MasterKDC"], serde_json::Value::Null);
    assert_eq!(
        value["DomainRealm"]["hostname1.example.com"],
        serde_json::json!("EXAMPLE.COM")
    );
}

#[expect(
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::needless_raw_strings,
    clippy::tests_outside_test_module,
    reason = "lint-migration: upstream baseline at ee9cb04"
)]
#[test]
fn rejects_v4_realm_directives() {
    let err = Config::parse(
        r#"
[realms]
 TEST.GOKRB5 = {
  kdc = 10.80.88.88:88
  v4_name_convert = {
   host = {
    rcmd = host
   }
  }
 }
"#,
    )
    .expect_err("v4 directives are rejected");

    assert!(matches!(err, Error::UnsupportedDirective(_)));
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
        "rskrb5-config-{name}-{}-{nanos}",
        std::process::id()
    ))
}

/// Fork-authored config tests: `[domain_realm]` precedence and case folding,
/// the explicit `permitted_enctypes` flag and request-list validation.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod fork_tests {
    use std::fs;

    use pretty_assertions::assert_eq;
    #[cfg(feature = "messages")]
    use rasn::der;
    #[cfg(any(feature = "serde", feature = "messages"))]
    use rskrb5::config::LibDefaults;
    #[cfg(feature = "messages")]
    use rskrb5::{
        Principal,
        client::{AsReqOptions, build_tgt_as_req},
    };

    use super::*;

    /// Pins that `[domain_realm]` lookups fold the DNS case of the host name.
    #[test]
    fn resolve_realm_folds_dns_case() -> Result<(), TestError> {
        let config = Config::parse(
            "
[libdefaults]
 default_realm = CLIENT.REALM

[domain_realm]
 foo.example.com = PARTNER.REALM
 .example.com = SUFFIX.REALM
",
        )
        .map_err(|cause| format!("config parses: {cause}"))?;

        for spelling in [
            "foo.example.com",
            "FOO.EXAMPLE.COM",
            "Foo.Example.com",
            "FOO.EXAMPLE.COM.",
        ] {
            assert_eq!(
                config.resolve_realm(spelling),
                Some("PARTNER.REALM"),
                "{spelling}"
            );
        }
        for spelling in ["bar.example.com", "BAR.EXAMPLE.COM", "Bar.Example.com"] {
            assert_eq!(
                config.resolve_realm(spelling),
                Some("SUFFIX.REALM"),
                "{spelling}"
            );
        }
        Ok(())
    }
    /// Pins MIT's bare-tag precedence: a bare domain tag also covers its subdomains.
    #[test]
    fn resolve_realm_applies_bare_domain_tags_to_subdomains() -> Result<(), TestError> {
        // MIT's own three-tag example; expected values match the MIT 1.22.1
        // reference (`krb5_get_host_realm`, dns_lookup_realm=false).
        let config = Config::parse(
            "
[libdefaults]
 default_realm = CLIENT.REALM

[domain_realm]
 crash.mit.edu = TEST.ATHENA.MIT.EDU
 .dev.mit.edu = TEST.ATHENA.MIT.EDU
 mit.edu = ATHENA.MIT.EDU
",
        )
        .map_err(|cause| format!("config parses: {cause}"))?;

        assert_eq!(config.resolve_realm("mit.edu"), Some("ATHENA.MIT.EDU"));
        assert_eq!(
            config.resolve_realm("crash.mit.edu"),
            Some("TEST.ATHENA.MIT.EDU")
        );
        assert_eq!(
            config.resolve_realm("sub.crash.mit.edu"),
            Some("TEST.ATHENA.MIT.EDU")
        );
        assert_eq!(config.resolve_realm("dev.mit.edu"), Some("ATHENA.MIT.EDU"));
        assert_eq!(
            config.resolve_realm("foo.dev.mit.edu"),
            Some("TEST.ATHENA.MIT.EDU")
        );
        assert_eq!(
            config.resolve_realm("a.b.dev.mit.edu"),
            Some("TEST.ATHENA.MIT.EDU")
        );
        assert_eq!(config.resolve_realm("notmit.edu"), None);
        Ok(())
    }
    /// Pins that a leading-dot tag matches subdomains but not the domain itself.
    #[test]
    fn resolve_realm_dot_tag_does_not_match_the_domain_itself() -> Result<(), TestError> {
        let config = Config::parse(
            "
[libdefaults]
 default_realm = CLIENT.REALM

[domain_realm]
 .mit.edu = ATHENA.MIT.EDU
",
        )
        .map_err(|cause| format!("config parses: {cause}"))?;

        assert_eq!(config.resolve_realm("mit.edu"), None);
        assert_eq!(
            config.resolve_realm("crash.mit.edu"),
            Some("ATHENA.MIT.EDU")
        );
        Ok(())
    }
    /// Pins that a leading-dot tag wins over a bare tag for subdomains at the same level.
    #[test]
    fn resolve_realm_prefers_dot_tag_over_bare_at_the_same_level() -> Result<(), TestError> {
        // Reference precedence: MIT resolves dev.mit.edu from the bare tag and
        // x.dev.mit.edu from the leading-dot tag when both are declared.
        let config = Config::parse(
            "
[libdefaults]
 default_realm = CLIENT.REALM

[domain_realm]
 .dev.mit.edu = DOT.REALM
 dev.mit.edu = BARE.REALM
",
        )
        .map_err(|cause| format!("config parses: {cause}"))?;

        assert_eq!(config.resolve_realm("dev.mit.edu"), Some("BARE.REALM"));
        assert_eq!(config.resolve_realm("x.dev.mit.edu"), Some("DOT.REALM"));
        assert_eq!(config.resolve_realm("a.b.dev.mit.edu"), Some("DOT.REALM"));
        Ok(())
    }
    /// Pins that the explicit `permitted_enctypes` flag survives a serde round trip.
    #[cfg(feature = "serde")]
    #[test]
    fn permitted_enctypes_explicit_survives_a_serde_round_trip() -> Result<(), TestError> {
        let config = Config::parse(
            "
[libdefaults]
 permitted_enctypes = aes256-cts-hmac-sha1-96
",
        )
        .map_err(|cause| format!("config parses: {cause}"))?;
        assert!(config.libdefaults.permitted_enctypes_explicit);

        let json = serde_json::to_string(&config.libdefaults)
            .map_err(|cause| format!("libdefaults serialize: {cause}"))?;
        let decoded: LibDefaults = serde_json::from_str(&json)
            .map_err(|cause| format!("libdefaults deserialize: {cause}"))?;

        assert!(decoded.permitted_enctypes_explicit);
        assert_eq!(decoded, config.libdefaults);
        #[cfg(feature = "messages")]
        assert_eq!(encoded_as_req_etypes(&decoded)?, vec![18_i32]);
        Ok(())
    }
    /// Pins that an implicit permitted list stays implicit across a serde round trip.
    #[cfg(feature = "serde")]
    #[test]
    fn implicit_permitted_enctypes_round_trip_stays_implicit() -> Result<(), TestError> {
        let config = Config::parse(KRB5_CONF).map_err(|cause| format!("config parses: {cause}"))?;
        assert!(!config.libdefaults.permitted_enctypes_explicit);

        let json = serde_json::to_string(&config.libdefaults)
            .map_err(|cause| format!("libdefaults serialize: {cause}"))?;
        let decoded: LibDefaults = serde_json::from_str(&json)
            .map_err(|cause| format!("libdefaults deserialize: {cause}"))?;

        assert!(!decoded.permitted_enctypes_explicit);
        assert_eq!(decoded, config.libdefaults);
        Ok(())
    }
    /// Pins that JSON without the explicit flag deserializes as an implicit permitted list.
    #[cfg(feature = "serde")]
    #[test]
    fn libdefaults_json_without_the_explicit_field_deserializes_as_implicit()
    -> Result<(), TestError> {
        let config = Config::parse(
            "
[libdefaults]
 permitted_enctypes = aes256-cts-hmac-sha1-96
",
        )
        .map_err(|cause| format!("config parses: {cause}"))?;
        let mut value = serde_json::to_value(&config.libdefaults)
            .map_err(|cause| format!("libdefaults serialize: {cause}"))?;
        let removed = value
            .as_object_mut()
            .ok_or("libdefaults serialize as an object")?
            .remove("permitted_enctypes_explicit");
        assert_eq!(removed, Some(serde_json::Value::Bool(true)));

        let decoded: LibDefaults = serde_json::from_value(value)
            .map_err(|cause| format!("libdefaults deserialize: {cause}"))?;

        assert!(!decoded.permitted_enctypes_explicit);
        assert_eq!(decoded.permitted_enctype_ids, vec![18_i32]);
        Ok(())
    }
    /// Pins that an explicit `default_tkt_enctypes` entry outside the permitted list fails parsing.
    #[test]
    fn explicit_tkt_enctypes_outside_permitted_fail_parsing_naming_the_enctype()
    -> Result<(), TestError> {
        let error = Config::parse(
            "
[libdefaults]
 default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
 permitted_enctypes = aes256-cts-hmac-sha1-96
",
        )
        .err()
        .ok_or("an explicit request list outside the allowlist is rejected")?;

        assert!(
            matches!(
                &error,
                Error::EnctypeNotPermitted { key: "default_tkt_enctypes", enctype }
                    if enctype == "aes128-cts-hmac-sha1-96"
            ),
            "unexpected error: {error:?}"
        );
        let message = error.to_string();
        assert!(message.contains("default_tkt_enctypes"), "{message}");
        assert!(message.contains("aes128-cts-hmac-sha1-96"), "{message}");
        Ok(())
    }
    /// Pins that an explicit `default_tgs_enctypes` entry outside the permitted list fails parsing.
    #[test]
    fn explicit_tgs_enctypes_outside_permitted_fail_parsing_naming_the_enctype()
    -> Result<(), TestError> {
        let error = Config::parse(
            "
[libdefaults]
 default_tgs_enctypes = aes128-cts-hmac-sha1-96
 permitted_enctypes = aes256-cts-hmac-sha1-96
",
        )
        .err()
        .ok_or("an explicit request list outside the allowlist is rejected")?;

        assert!(
            matches!(
                &error,
                Error::EnctypeNotPermitted { key: "default_tgs_enctypes", enctype }
                    if enctype == "aes128-cts-hmac-sha1-96"
            ),
            "unexpected error: {error:?}"
        );
        let message = error.to_string();
        assert!(message.contains("default_tgs_enctypes"), "{message}");
        assert!(message.contains("aes128-cts-hmac-sha1-96"), "{message}");
        Ok(())
    }
    /// Pins that the implicit default request list is filtered to the permitted list.
    #[test]
    fn implicit_default_enctypes_are_filtered_to_permitted() -> Result<(), TestError> {
        let config = Config::parse(
            "
[libdefaults]
 permitted_enctypes = aes256-cts-hmac-sha1-96
",
        )
        .map_err(|cause| {
            format!("an implicit request list is not validated at parse time: {cause}")
        })?;

        assert!(config.libdefaults.permitted_enctypes_explicit);
        assert_eq!(
            config.libdefaults.default_tkt_enctype_ids,
            vec![18_i32, 17_i32, 23_i32]
        );
        #[cfg(feature = "messages")]
        assert_eq!(encoded_as_req_etypes(&config.libdefaults)?, vec![18_i32]);
        Ok(())
    }
    /// Pins that an explicit request list in an earlier `[libdefaults]` section is validated.
    #[test]
    fn explicit_tkt_list_in_an_earlier_libdefaults_section_is_still_validated()
    -> Result<(), TestError> {
        let error = Config::parse(
            "
[libdefaults]
 default_tkt_enctypes = aes128-cts-hmac-sha1-96

[domain_realm]
 .test.gokrb5 = TEST.GOKRB5

[libdefaults]
 permitted_enctypes = aes256-cts-hmac-sha1-96
",
        )
        .err()
        .ok_or("the earlier explicit request list is validated")?;

        assert!(
            matches!(
                &error,
                Error::EnctypeNotPermitted { key: "default_tkt_enctypes", enctype }
                    if enctype == "aes128-cts-hmac-sha1-96"
            ),
            "unexpected error: {error:?}"
        );
        Ok(())
    }
    /// Pins that a later `[libdefaults]` section can repair an earlier conflict.
    #[test]
    fn a_later_section_can_repair_an_earlier_conflict() -> Result<(), TestError> {
        let config = Config::parse(
            "
[libdefaults]
 default_tkt_enctypes = aes128-cts-hmac-sha1-96
 permitted_enctypes = aes256-cts-hmac-sha1-96

[libdefaults]
 default_tkt_enctypes = aes256-cts-hmac-sha1-96
",
        )
        .map_err(|cause| format!("the final effective request list is permitted: {cause}"))?;

        assert_eq!(config.libdefaults.default_tkt_enctype_ids, vec![18_i32]);
        #[cfg(feature = "messages")]
        assert_eq!(encoded_as_req_etypes(&config.libdefaults)?, vec![18_i32]);
        Ok(())
    }
    /// Pins that an explicit request list from an included file is validated.
    #[test]
    fn explicit_tkt_list_in_an_included_file_is_validated_against_permitted()
    -> Result<(), TestError> {
        let dir = include_fixture_dir(
            "include-enctype-reject",
            &[(
                "extra.conf",
                "[libdefaults]\n default_tkt_enctypes = aes128-cts-hmac-sha1-96\n",
            )],
        )?;
        let extra = dir.join("extra.conf");
        let main = format!(
            "[libdefaults]\n permitted_enctypes = aes256-cts-hmac-sha1-96\n\ninclude {}\n",
            extra.display()
        );
        let main_path = dir.join("krb5.conf");
        fs::write(&main_path, main).map_err(|cause| format!("main config is written: {cause}"))?;

        let error = Config::load(&main_path)
            .err()
            .ok_or("an included explicit request list outside the allowlist is rejected")?;
        fs::remove_dir_all(&dir)?;

        assert!(
            matches!(
                &error,
                Error::EnctypeNotPermitted { key: "default_tkt_enctypes", enctype }
                    if enctype == "aes128-cts-hmac-sha1-96"
            ),
            "unexpected error: {error:?}"
        );
        Ok(())
    }
    /// Pins that a later included file can repair an earlier conflict.
    #[test]
    fn a_later_included_file_can_repair_an_earlier_conflict() -> Result<(), TestError> {
        let dir = include_fixture_dir(
            "include-enctype-repair",
            &[
                (
                    "a.conf",
                    "[libdefaults]\n default_tkt_enctypes = aes128-cts-hmac-sha1-96\n",
                ),
                (
                    "b.conf",
                    "[libdefaults]\n default_tkt_enctypes = aes256-cts-hmac-sha1-96\n",
                ),
            ],
        )?;
        let main = format!(
            "[libdefaults]\n permitted_enctypes = aes256-cts-hmac-sha1-96\n\ninclude {}\ninclude {}\n",
            dir.join("a.conf").display(),
            dir.join("b.conf").display()
        );
        let main_path = dir.join("krb5.conf");
        fs::write(&main_path, main).map_err(|cause| format!("main config is written: {cause}"))?;

        let loaded = Config::load(&main_path);
        fs::remove_dir_all(&dir)?;
        let config = loaded
            .map_err(|cause| format!("the final effective request list is permitted: {cause}"))?;

        assert_eq!(config.libdefaults.default_tkt_enctype_ids, vec![18_i32]);
        Ok(())
    }
    /// Pins that a bare tag does not match a host that merely ends with its text.
    #[test]
    fn resolve_realm_rejects_bare_prefix_extension() -> Result<(), TestError> {
        let config = Config::parse(
            "
[libdefaults]
 default_realm = CLIENT.REALM

[domain_realm]
 mit.edu = ATHENA.MIT.EDU
",
        )
        .map_err(|cause| format!("config parses: {cause}"))?;

        assert_eq!(config.resolve_realm("notmit.edu"), None);
        assert_eq!(config.resolve_realm("sub.notmit.edu"), None);
        assert_eq!(config.resolve_realm("mit.edu"), Some("ATHENA.MIT.EDU"));
        assert_eq!(config.resolve_realm("sub.mit.edu"), Some("ATHENA.MIT.EDU"));
        Ok(())
    }
    /// Write `files` (name, body) into a fresh directory and return its path.
    fn include_fixture_dir(name: &str, files: &[(&str, &str)]) -> Result<PathBuf, TestError> {
        let dir = temp_file(name);
        fs::create_dir_all(&dir)
            .map_err(|cause| format!("fixture directory is created: {cause}"))?;
        for (file, body) in files {
            fs::write(dir.join(file), body)
                .map_err(|cause| format!("fixture file is written: {cause}"))?;
        }
        Ok(dir)
    }
    /// Encodes an AS-REQ built from `defaults` and returns its decoded etype list.
    #[cfg(feature = "messages")]
    fn encoded_as_req_etypes(defaults: &LibDefaults) -> Result<Vec<i32>, TestError> {
        let now = UNIX_EPOCH
            .checked_add(Duration::from_secs(1_893_553_447))
            .ok_or("the fixed request time fits in SystemTime")?;
        let options = AsReqOptions::from_libdefaults(now, 0x1122_3344, defaults);
        let request = build_tgt_as_req(Principal::user("TEST.GOKRB5", "testuser1"), options)
            .map_err(|cause| format!("AS-REQ builds: {cause}"))?;
        let decoded: rasn_kerberos::AsReq =
            der::decode(&request.der).map_err(|cause| format!("AS-REQ decodes: {cause}"))?;
        Ok(decoded.0.req_body.etype)
    }
}
