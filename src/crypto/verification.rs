//! MAC verification boundary.

use super::KerberosEtype;

/// Verify a family's keyed checksum at the common authentication boundary.
pub(super) fn verify_checksum(
    etype: KerberosEtype,
    protocol_key: &[u8],
    data: &[u8],
    checksum: &[u8],
    usage: u32,
) -> bool {
    etype
        .checksum(protocol_key, data, usage)
        .is_ok_and(|expected| constant_time_eq(&expected, checksum))
}

/// Compare two byte strings without stopping at the first difference.
pub(super) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0;
    for (left_byte, right_byte) in left.iter().zip(right) {
        diff |= left_byte ^ right_byte;
    }
    diff == 0
}
