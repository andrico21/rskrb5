//! Fuzz the ccache parser on arbitrary input: `CCache::parse` must return
//! `Ok`/`Err` for every input, never panic, and never allocate from an
//! unbounded length or count field. An accepted cache has its configuration
//! entries read and is serialized again. The same input, read as UTF-8 text,
//! goes through the credential-cache name parser.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::ccache::{CCache, CacheName};

fuzz_target!(|data: &[u8]| {
    if let Ok(cache) = CCache::parse(data) {
        drop(cache.config_entries());
        drop(cache.to_bytes());
    }
    drop(CacheName::parse(String::from_utf8_lossy(data)));
});
