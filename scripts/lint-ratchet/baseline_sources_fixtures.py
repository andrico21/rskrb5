#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# How to run: python3 scripts/lint-ratchet/baseline_sources_fixtures.py --self-test
"""Real R2 wrap bodies from ratchet base 473ca10 and todo-20's WIP.

Whitespace is compacted per line, as in baseline_sources.bodies; literal
contents and line boundaries remain significant to the similarity proof.
"""

from __future__ import annotations

import difflib

from baseline_sources import bodies, source_moves


def self_test() -> None:
    env_base = """const TEST_PATH: &str = "saves_and_loads_ccache_from_env";
if !env::in_child(TEST_PATH) {
let path = temp_file("save-load-env");
let name = format!("FILE:{}", path.display());
env::run_in_child(TEST_PATH, &[("KRB5CCNAME", Some(name.as_ref()))]);
return;
}
let bytes = decode_hex(CCACHE_TEST);
let cache = CCache::parse(&bytes).expect("ccache fixture parses");
let name = std::env::var("KRB5CCNAME").expect("the parent test sets KRB5CCNAME");
let path = PathBuf::from(
name.strip_prefix("FILE:")
.expect("KRB5CCNAME names a FILE: path"),
);
cache.save_to_env().expect("ccache saves to env name");
let loaded = CCache::load_from_env().expect("ccache loads from env name");
let _ = std::fs::remove_file(&path);
assert_eq!(loaded, cache);"""
    env_current = """const TEST_PATH: &str = "ccache_env_round_trip::saves_and_loads_ccache_from_env";
if !env::in_child(TEST_PATH) {
let path = temp_file("save-load-env");
let name = format!("FILE:{}", path.display());
env::run_in_child(TEST_PATH, &[("KRB5CCNAME", Some(name.as_ref()))]);
return Ok(());
}
let bytes = decode_hex(CCACHE_TEST);
let cache =
CCache::parse(&bytes).map_err(|cause| format!("ccache fixture parses: {cause}"))?;
let name = var("KRB5CCNAME")
.map_err(|cause| format!("the parent test sets KRB5CCNAME: {cause}"))?;
let path = PathBuf::from(
name.strip_prefix("FILE:")
.ok_or("KRB5CCNAME names a FILE: path")?,
);
cache
.save_to_env()
.map_err(|cause| format!("ccache saves to env name: {cause}"))?;
let loaded = CCache::load_from_env()
.map_err(|cause| format!("ccache loads from env name: {cause}"))?;
let _ = std::fs::remove_file(&path);
assert_eq!(loaded, cache);
Ok(())"""
    config_base = """const TEST_PATH: &str = "loads_config_path_list_from_env";
if !env::in_child(TEST_PATH) {
let paths =
std::env::join_paths([temp_file("load-env-first"), temp_file("load-env-second")])
.expect("config paths join");
env::run_in_child(TEST_PATH, &[("KRB5_CONFIG", Some(&paths))]);
return;
}
let paths = std::env::var_os("KRB5_CONFIG").expect("the parent test sets KRB5_CONFIG");
let [first, second]: [PathBuf; 2] = std::env::split_paths(&paths)
.collect::<Vec<_>>()
.try_into()
.expect("KRB5_CONFIG lists two paths");
std::fs::write(
&first,
r#"
[libdefaults]
default_realm = FIRST.GOKRB5
"#,
)
.expect("first config writes");
std::fs::write(
&second,
r#"
[libdefaults]
default_realm = SECOND.GOKRB5
"#,
)
.expect("second config writes");
let config = Config::load_from_env().expect("config loads from KRB5_CONFIG");
let _ = std::fs::remove_file(&first);
let _ = std::fs::remove_file(&second);
assert_eq!(config.libdefaults.default_realm, "SECOND.GOKRB5");"""
    config_current = """const TEST_PATH: &str = "config_env::loads_config_path_list_from_env";
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
Ok(())"""
    missing_base = """const TEST_PATH: &str = "rejects_missing_config_env";
if !env::in_child(TEST_PATH) {
env::run_in_child(TEST_PATH, &[("KRB5_CONFIG", None)]);
return;
}
assert!(matches!(
Config::load_from_env().expect_err("missing KRB5_CONFIG rejected"),
Error::DefaultConfigName
));"""
    missing_current = (
        missing_base.replace(
            '"rejects_missing_config_env"',
            '"config_env_missing::rejects_missing_config_env"',
        )
        .replace(
            'env::run_in_child(TEST_PATH, &[("KRB5_CONFIG", None)]);',
            'env::try_run_in_child(TEST_PATH, &[("KRB5_CONFIG", None)])?;',
        )
        .replace("return;", "return Ok(());")
        + "\nOk(())"
    )
    http_base = """const TEST_PATH: &str = "tower_service_loads_keytab_env";
if !env::in_child(TEST_PATH) {
let path = temp_file("http-keytab-env");
let name = format!("FILE:{}", path.display());
env::run_in_child(TEST_PATH, &[("KRB5_KTNAME", Some(name.as_ref()))]);
return;
}
let name = std::env::var("KRB5_KTNAME").expect("the parent test sets KRB5_KTNAME");
let path = std::path::PathBuf::from(
name.strip_prefix("FILE:")
.expect("KRB5_KTNAME names a FILE: path"),
);
keytab().save(&path).expect("keytab saves");
let mut service = krb_http::NegotiateService::from_keytab_env(AssertAcceptedService)
.expect("service loads keytab env")
.with_now(timestamp(1_893_553_447))
.with_ap_rep(false);
let _ = std::fs::remove_file(&path);
let mut request = Request::new(());
krb_http::set_authorization_header(&mut request, &valid_authorization_header())
.expect("authorization header sets");
let response = run_ready(service.call(request)).expect("inner response succeeds");
assert_eq!(response.status(), StatusCode::OK);
assert!(
response.headers().get(WWW_AUTHENTICATE).is_none(),
"AP-REP header is disabled"
);"""
    http_current = """const TEST_PATH: &str = "tower_keytab_env::tower_service_loads_keytab_env";
if !env::in_child(TEST_PATH) {
let path = temp_file("http-keytab-env");
let name = format!("FILE:{}", path.display());
env::run_in_child(TEST_PATH, &[("KRB5_KTNAME", Some(name.as_ref()))]);
return Ok(());
}
let name = var("KRB5_KTNAME")
.map_err(|cause| format!("the parent test sets KRB5_KTNAME: {cause}"))?;
let path = PathBuf::from(
name.strip_prefix("FILE:")
.ok_or("KRB5_KTNAME names a FILE: path")?,
);
keytab()
.save(&path)
.map_err(|cause| format!("keytab saves: {cause}"))?;
let mut service = krb_http::NegotiateService::from_keytab_env(AssertAcceptedService)
.map_err(|cause| format!("service loads keytab env: {cause}"))?
.with_now(timestamp(1_893_553_447))
.with_ap_rep(false);
let _ = std::fs::remove_file(&path);
let mut request = Request::new(());
krb_http::set_authorization_header(&mut request, &valid_authorization_header())
.map_err(|cause| format!("authorization header sets: {cause}"))?;
let response = run_ready(service.call(request))
.map_err(|cause| format!("inner response succeeds: {cause}"))?;
assert_eq!(response.status(), StatusCode::OK);
assert!(
response.headers().get(WWW_AUTHENTICATE).is_none(),
"AP-REP header is disabled"
);
Ok(())"""
    pac_base = """let pac = Pac::parse(&decode_hex(pac_ad_win2k::PAC_AD_WIN2K)).expect("PAC header parses");
let client_buffer = pac
.buffer(INFO_TYPE_PAC_CLIENT_INFO)
.expect("client buffer exists");
let client =
ClientInfo::parse(pac.buffer_bytes(client_buffer).expect("client bytes")).expect("client");
assert_client_info(&client);
let upn_buffer = pac
.buffer(INFO_TYPE_UPN_DNS_INFO)
.expect("UPN/DNS buffer exists");
let upn =
UpnDnsInfo::parse(pac.buffer_bytes(upn_buffer).expect("UPN/DNS bytes")).expect("UPN/DNS");
assert_upn_dns_info(&upn);
let signature_buffer = pac
.buffer(INFO_TYPE_PAC_SERVER_SIGNATURE_DATA)
.expect("server checksum buffer exists");
let signature = SignatureData::parse(
pac.buffer_bytes(signature_buffer)
.expect("server checksum bytes"),
)
.expect("signature parses");
assert_eq!(signature.signature_type, CHECKSUM_HMAC_SHA1_96_AES256);"""
    pac_current = """let pac = Pac::parse(&decode_hex(pac_ad_win2k::PAC_AD_WIN2K))
.map_err(|cause| format!("PAC header parses: {cause}"))?;
let client_buffer = pac
.buffer(INFO_TYPE_PAC_CLIENT_INFO)
.expect("client buffer exists");
let client = ClientInfo::parse(
pac.buffer_bytes(client_buffer)
.map_err(|cause| format!("client bytes: {cause}"))?,
)
.map_err(|cause| format!("client: {cause}"))?;
assert_client_info(&client);
let upn_buffer = pac
.buffer(INFO_TYPE_UPN_DNS_INFO)
.expect("UPN/DNS buffer exists");
let upn = UpnDnsInfo::parse(
pac.buffer_bytes(upn_buffer)
.map_err(|cause| format!("UPN/DNS bytes: {cause}"))?,
)
.map_err(|cause| format!("UPN/DNS: {cause}"))?;
assert_upn_dns_info(&upn);
let signature_buffer = pac
.buffer(INFO_TYPE_PAC_SERVER_SIGNATURE_DATA)
.expect("server checksum buffer exists");
let signature = SignatureData::parse(
pac.buffer_bytes(signature_buffer)
.map_err(|cause| format!("server checksum bytes: {cause}"))?,
)
.map_err(|cause| format!("signature parses: {cause}"))?;
assert_eq!(signature.signature_type, CHECKSUM_HMAC_SHA1_96_AES256);
Ok(())"""
    fixtures = (
        (
            "ccache_env_round_trip",
            "saves_and_loads_ccache_from_env",
            env_base,
            env_current,
            0.500,
        ),
        (
            "config_env",
            "loads_config_path_list_from_env",
            config_base,
            config_current,
            0.585,
        ),
        (
            "config_env_missing",
            "rejects_missing_config_env",
            missing_base,
            missing_current,
            0.588,
        ),
        (
            "tower_keytab_env",
            "tower_service_loads_keytab_env",
            http_base,
            http_current,
            0.596,
        ),
        (
            "keytab_env_round_trip",
            "saves_and_loads_keytab_from_env",
            env_base.replace("ccache", "keytab")
            .replace("CCache", "Keytab")
            .replace("CCACHE_TEST", "KEYTAB_TESTUSER1_TEST_GOKRB5")
            .replace("KRB5CCNAME", "KRB5_KTNAME")
            .replace("cache", "keytab"),
            env_current.replace("ccache", "keytab")
            .replace("CCache", "Keytab")
            .replace("CCACHE_TEST", "KEYTAB_TESTUSER1_TEST_GOKRB5")
            .replace("KRB5CCNAME", "KRB5_KTNAME")
            .replace("cache", "keytab"),
            0.500,
        ),
        (
            "component_buffers",
            "parses_component_buffers_directly",
            pac_base,
            pac_current,
            0.577,
        ),
    )
    for module, name, before, after, expected in fixtures:
        base = f"fn {name}() {{\n{before}\n}}\n"
        current = f"mod {module} {{\nfn {name}() {{\n{after}\n}}\n}}\n"
        old, new = f"fn {name}", f"mod {module}::fn {name}"
        ratio = difflib.SequenceMatcher(
            None, bodies(base)[old], bodies(current)[new], autojunk=False
        ).ratio()
        assert round(ratio, 3) == expected, (name, ratio)
        assert (old, new) in source_moves(base, current), name
        print(
            f"baseline_sources fixture: {module}::{name} similarity={ratio:.3f} accepted"
        )


if __name__ == "__main__":
    self_test()
