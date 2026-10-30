//! Fuzz the `krb5.conf` parser: `Config::parse` over the
//! UTF-8-lossy input must return `Ok`/`Err` for every input and never panic.
//! The environment-free entry point keeps runs independent of the host's
//! `KRB5_*` variables.
//! An accepted configuration has its enctype lists resolved.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::{
    Config,
    config::{EnctypeExpr, ParseMode, Toggle},
};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    for mode in [ParseMode::Compatible, ParseMode::Strict] {
        drop(Config::parse_with_mode(&text, mode));
        if let Ok(expression) = EnctypeExpr::parse(&text) {
            drop(expression.resolve(Toggle::Disabled, Toggle::Disabled, mode));
            drop(expression.resolve(Toggle::Enabled, Toggle::Enabled, mode));
        }
    }
    if let Ok(config) = Config::parse(&text) {
        let defaults = &config.libdefaults;
        drop(defaults.default_tkt_enctype_ids());
        drop(defaults.default_tgs_enctype_ids());
        drop(defaults.permitted_enctype_ids());
    }
});
