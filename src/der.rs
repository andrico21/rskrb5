/// Strip zero padding that follows one complete top-level DER value.
///
/// Decrypted Kerberos parts can carry zero bytes up to the cipher block size.
/// When `bytes` starts with a complete DER value followed only by zero bytes,
/// this returns just that value. Any other input, including malformed DER and
/// non-zero trailing bytes, is returned unchanged so the strict decoder
/// reports the real error.
pub(crate) fn trim_zero_padded_der(bytes: &[u8]) -> &[u8] {
    let Some(end) = top_level_der_end(bytes) else {
        return bytes;
    };
    if let Some((value, padding)) = bytes.split_at_checked(end)
        && padding.iter().all(|byte| *byte == 0)
    {
        value
    } else {
        bytes
    }
}

/// Return the end offset of the first top-level DER value in `bytes`.
///
/// Returns `None` when `bytes` is empty, the identifier or length octets are
/// truncated, the length is indefinite or wider than `usize`, or the value
/// runs past the end of the input.
fn top_level_der_end(bytes: &[u8]) -> Option<usize> {
    let (identifier, _) = bytes.split_first()?;

    let mut offset: usize = 1;
    if identifier & 0x1f == 0x1f {
        loop {
            let byte = *bytes.get(offset)?;
            offset = offset.checked_add(1)?;
            if byte & 0x80 == 0 {
                break;
            }
        }
    }

    let first_len = *bytes.get(offset)?;
    offset = offset.checked_add(1)?;
    let len = if first_len & 0x80 == 0 {
        usize::from(first_len)
    } else {
        let count = usize::from(first_len & 0x7f);
        if count == 0 || count > size_of::<usize>() {
            return None;
        }
        let len_end = offset.checked_add(count)?;
        let len_bytes = bytes.get(offset..len_end)?;
        offset = len_end;
        let mut len = 0_usize;
        for byte in len_bytes {
            len = (len << 8_u32) | usize::from(*byte);
        }
        len
    };

    let end = offset.checked_add(len)?;
    (end <= bytes.len()).then_some(end)
}

/// Decode exactly one DER value at a complete-message boundary.
///
/// # Errors
///
/// Returns the decoder diagnostic or a trailing-data diagnostic. Raw convenience
/// codecs use rasn directly and retain their prefix-decoding contract.
pub(crate) fn decode_complete<T>(bytes: &[u8]) -> Result<T, String>
where
    T: rasn::Decode,
{
    let (value, remainder) =
        der::decode_with_remainder(bytes).map_err(|error| error.to_string())?;
    if !remainder.is_empty() {
        return Err("trailing bytes after complete DER message".to_owned());
    }
    Ok(value)
}
use rasn::der;

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use super::trim_zero_padded_der;

    /// A value with no trailing bytes is returned unchanged.
    #[test]
    fn leaves_exact_der_unchanged() {
        let bytes = [0x30, 0x03, 0x04, 0x01, 0x00];
        assert_eq!(trim_zero_padded_der(&bytes), bytes);
    }

    /// Zero bytes after a complete top-level value are stripped.
    #[test]
    fn trims_only_zero_bytes_after_top_level_der_value() {
        let bytes = [0x30, 0x03, 0x04, 0x01, 0x00, 0x00, 0x00];
        assert_eq!(trim_zero_padded_der(&bytes), [0x30, 0x03, 0x04, 0x01, 0x00]);
    }

    /// Non-zero trailing bytes are kept so the strict decoder rejects them.
    #[test]
    fn leaves_nonzero_trailing_bytes_for_strict_decoder_errors() {
        let bytes = [0x30, 0x03, 0x04, 0x01, 0x00, 0x01];
        assert_eq!(trim_zero_padded_der(&bytes), bytes);
    }

    /// Truncated DER is returned unchanged.
    #[test]
    fn leaves_malformed_der_unchanged() {
        let bytes = [0x30, 0x81];
        assert_eq!(trim_zero_padded_der(&bytes), bytes);
    }
}
