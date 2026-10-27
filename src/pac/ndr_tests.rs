//! Wire-level regressions for private NDR decoding boundaries.

use super::{Reader, read_deferred_bool_array};
use crate::error::Pac as Error;

/// Pins ULONG64 Boolean arrays with both possible pre-element padding widths.
#[test]
fn boolean_claims_decode_aligned_u64_values() -> Result<(), Error> {
    for prefix in [0_usize, 4] {
        // Given: a conformant count followed by aligned ULONG64 false/true values.
        let mut bytes = vec![0; prefix];
        bytes.extend_from_slice(&2_u32.to_le_bytes());
        bytes.resize(bytes.len().next_multiple_of(8), 0);
        bytes.extend_from_slice(&0_u64.to_le_bytes());
        bytes.extend_from_slice(&1_u64.to_le_bytes());
        let mut reader = Reader::new(&bytes);
        let _prefix_bytes = reader.read_bytes(prefix)?;
        // When: the Boolean arm decodes the array.
        let values = read_deferred_bool_array(&mut reader, 1, 2, "BooleanValues")?;
        // Then: both values and the complete wire extent are consumed.
        assert_eq!(values, vec![false, true]);
        assert_eq!(reader.remaining(), 0);
    }
    Ok(())
}

/// Pins rejection of non-Boolean ULONG64 values rather than truthy conversion.
#[test]
fn boolean_claims_reject_non_binary_u64() -> Result<(), Error> {
    // Given: a conformant Boolean array whose value is two.
    let mut bytes = 1_u32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&[0; 4]);
    bytes.extend_from_slice(&2_u64.to_le_bytes());
    let mut reader = Reader::new(&bytes);
    // When: the Boolean arm decodes the array.
    let result = read_deferred_bool_array(&mut reader, 1, 1, "BooleanValues");
    // Then: non-binary data is rejected.
    assert!(matches!(result, Err(Error::InvalidBooleanClaim(2))));
    let _remaining_bytes = reader.read_bytes(reader.remaining())?;
    Ok(())
}
