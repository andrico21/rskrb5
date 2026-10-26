//! DER scalar boundary regressions, including the public SPNEGO decoder.

use super::{Error, decode_oid_value, decode_u32, encode_u32};
use crate::spnego::{NegState, NegTokenResp};

/// A state above `u32::MAX` must not alias accept-completed through the public decoder.
#[test]
fn der_state_overflow_cannot_alias_accept_completed() {
    let encoded = [
        0xa1, 0x0b, 0x30, 0x09, 0xa0, 0x07, 0x0a, 0x05, 1, 0, 0, 0, 0,
    ];
    assert!(matches!(
        NegTokenResp::decode(&encoded),
        Err(Error::InvalidInteger)
    ));
}

/// Positive integers use one sign octet only when their highest value bit is set.
#[test]
fn der_integer_rejects_nonminimal_and_negative_values() {
    for bytes in [
        &[0, 0][..],
        &[0, 0x7f],
        &[0, 0, 0x80],
        &[0x80],
        &[],
        &[1, 0, 0, 0, 0],
    ] {
        assert!(matches!(decode_u32(bytes), Err(Error::InvalidInteger)));
    }
}

/// Sign-octet transitions and the largest supported integer remain lossless.
#[test]
fn der_integer_preserves_unsigned_boundaries() -> Result<(), Error> {
    for value in [0, 1, 127, 128, 255, 256, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
        assert_eq!(decode_u32(&encode_u32(value))?, value);
    }
    for (wire, expected) in [
        (0, NegState::AcceptCompleted),
        (1, NegState::AcceptIncomplete),
        (2, NegState::Reject),
        (3, NegState::RequestMic),
    ] {
        let encoded = [0xa1, 7, 0x30, 5, 0xa0, 3, 0x0a, 1, wire];
        assert_eq!(NegTokenResp::decode(&encoded)?.neg_state, Some(expected));
    }
    Ok(())
}

/// An oversized later arc must not alias 840 in the Kerberos mechanism OID.
#[test]
fn der_oid_overflow_cannot_alias_kerberos() {
    let encoded = [
        0xa1, 0x12, 0x30, 0x10, 0xa1, 0x0e, 6, 0x0c, 0x2a, 0x90, 0x80, 0x80, 0x86, 0x48, 0x86,
        0xf7, 0x12, 1, 2, 2,
    ];
    assert!(matches!(
        NegTokenResp::decode(&encoded),
        Err(Error::InvalidOidEncoding)
    ));
}

/// Zero leading base-128 groups and unterminated arcs are malformed, not aliases.
#[test]
fn der_oid_rejects_nonminimal_and_truncated_arcs() {
    for bytes in [&[0x2a, 0x80, 0][..], &[0x2a, 0x80, 1], &[0x2a, 0x81], &[]] {
        assert!(matches!(
            decode_oid_value(bytes),
            Err(Error::InvalidOidEncoding)
        ));
    }
}

/// Canonical zero and maximum later arcs stay in the supported u32 domain.
#[test]
fn der_oid_preserves_later_arc_boundaries() -> Result<(), Error> {
    let decoded = decode_oid_value(&[0x2a, 0, 0x8f, 0xff, 0xff, 0xff, 0x7f])?;
    assert_eq!(decoded.arcs(), &[1, 2, 0, u32::MAX]);
    Ok(())
}
