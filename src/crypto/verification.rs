//! MAC verification boundary.

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
