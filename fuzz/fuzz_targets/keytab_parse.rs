//! Fuzz the keytab parser on arbitrary input: `Keytab::parse` must return
//! `Ok`/`Err` for every input, never panic, and never allocate from an
//! unbounded length or count field. An accepted keytab is serialized again so
//! the writer sees every shape the parser admits.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::keytab::Keytab;

fuzz_target!(|data: &[u8]| {
    if let Ok(keytab) = Keytab::parse(data) {
        drop(keytab.to_bytes());
    }
});
