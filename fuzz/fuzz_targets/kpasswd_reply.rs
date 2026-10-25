//! Fuzz the kadmin frame parsers on arbitrary input: `Reply`,
//! `ChangePasswordResult` (the field patch 0002 adds carries the bytes these
//! parse) and `Request`. None may panic; every input must return `Ok`/`Err`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rskrb5_ng::kadmin::{ChangePasswordResult, Reply, Request};

fuzz_target!(|data: &[u8]| {
    // Only returning matters: a rejected input is the `Err` arm, and an
    // accepted one is dropped unused.
    if let Ok(reply) = Reply::parse(data) {
        drop(reply);
    }
    if let Ok(result) = ChangePasswordResult::parse(data) {
        drop(result);
    }
    if let Ok(request) = Request::parse(data) {
        drop(request);
    }
});
