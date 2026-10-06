//! Fuzz the kadmin frame parsers on arbitrary input: `Reply`,
//! `ChangePasswordResult` (the field patch 0002 adds carries the bytes these
//! parse) and `Request`. None may panic; every input must return `Ok`/`Err`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = rskrb5::kadmin::Reply::parse(data);
    let _ = rskrb5::kadmin::ChangePasswordResult::parse(data);
    let _ = rskrb5::kadmin::Request::parse(data);
});
