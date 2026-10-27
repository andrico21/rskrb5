//! Fuzz the parsers of names and values that arrive as text from the
//! configuration, the environment or the caller.
//!
//! The first input byte selects the parser and the rest, read as UTF-8-lossy
//! text, is its input: user and service principal names, credential-cache
//! and keytab names, a KDC `host[:port]` endpoint, a DNS server override,
//! the `krb5.conf` duration and boolean values, and RFC 3962 `s2kparams`.
//! None may panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::{
    Principal,
    ccache::CacheName,
    client::transport::{KdcEndpoint, KdcProtocol, Tokio},
    config, crypto, keytab,
};

fuzz_target!(|data: &[u8]| {
    let Some((selector, input)) = data.split_first() else {
        return;
    };
    let text = String::from_utf8_lossy(input);
    match selector & 0x07 {
        0 => drop(Principal::parse_user(&text)),
        1 => drop(Principal::parse_service(&text)),
        2 => drop(CacheName::parse(&text)),
        3 => drop(keytab::Name::parse(&text)),
        4 => {
            drop(KdcEndpoint::configured(KdcProtocol::Tcp, &text));
            drop(KdcEndpoint::configured_with_default_port(
                KdcProtocol::Udp,
                &text,
                464,
            ));
        }
        5 => drop(Tokio::new().with_dns_server(&text)),
        6 => {
            drop(config::parse_duration(&text));
            drop(config::parse_boolean(&text));
        }
        _ => drop(crypto::s2kparams_to_iterations(&text)),
    }
});
