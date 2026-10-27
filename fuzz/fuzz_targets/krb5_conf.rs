//! Fuzz the `krb5.conf` parser: `Config::parse_without_env` over the
//! UTF-8-lossy input must return `Ok`/`Err` for every input and never panic.
//! The environment-free entry point keeps runs independent of the host's
//! `KRB5_*` variables; the environment-seeded `Config::parse` runs as well.
//! An accepted configuration has its enctype lists resolved.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::{Config, config};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    if let Ok(config) = Config::parse_without_env(&text) {
        let defaults = &config.libdefaults;
        for list in [
            &defaults.default_tkt_enctypes,
            &defaults.default_tgs_enctypes,
            &defaults.permitted_enctypes,
        ] {
            drop(config::parse_supported_enctype_ids(
                list,
                defaults.allow_weak_crypto.is_enabled(),
            ));
        }
    }
    drop(Config::parse(&text));
});
