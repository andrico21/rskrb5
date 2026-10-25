//! Fuzz the ccache parser on arbitrary input: `CCache::parse` must return
//! `Ok`/`Err` for every input, never panic, and never allocate from an
//! unbounded length or count field.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rskrb5::ccache::CCache;

fuzz_target!(|data: &[u8]| {
    drop(CCache::parse(data));
});
