//! Service-specific TCP record length validation.

use super::{Error, TcpFraming};

/// Validate the reserved bit only for RFC 4120 KDC records.
///
/// # Errors
/// Returns the named reserved-bit error for KDC frames.
pub(super) const fn validate_tcp_length(length: u32, framing: TcpFraming) -> Result<(), Error> {
    match framing {
        TcpFraming::Kdc if length & 0x8000_0000 != 0 => Err(Error::TcpReservedBitSet),
        TcpFraming::Kdc | TcpFraming::Kpasswd => Ok(()),
    }
}

/// Convert an outgoing length according to the service's framing rules.
///
/// # Errors
/// Returns a request-size error if the service's record mark cannot represent it.
pub(super) fn tcp_request_length(length: usize, framing: TcpFraming) -> Result<u32, Error> {
    let value =
        u32::try_from(length).map_err(|_overflow| Error::TcpRequestTooLarge { actual: length })?;
    validate_tcp_length(value, framing)
        .map_err(|_reserved| Error::TcpRequestTooLarge { actual: length })?;
    Ok(value)
}

/// Bound an incoming record before allocating its body.
///
/// # Errors
/// Returns reserved-bit and response-size errors under the service's framing rules.
pub(super) fn response_length(
    header: [u8; 4],
    framing: TcpFraming,
    max: usize,
) -> Result<usize, Error> {
    match framing {
        TcpFraming::Kdc => super::kdc_tcp_record_length(header, max),
        TcpFraming::Kpasswd => bounded_length(header, max),
    }
}

/// Apply KDC-specific record rules before returning a bounded allocation size.
///
/// # Errors
/// Returns reserved-bit, size-limit and empty-response errors.
pub(super) fn kdc_record_length(header: [u8; 4], max: usize) -> Result<usize, Error> {
    validate_tcp_length(u32::from_be_bytes(header), TcpFraming::Kdc)?;
    let length = bounded_length(header, max)?;
    if length == 0 {
        return Err(Error::EmptyKdcResponse);
    }
    Ok(length)
}

/// Convert and cap a record's unsigned length without allocating a body.
///
/// # Errors
/// Returns a response-size error above the cap or platform address space.
fn bounded_length(header: [u8; 4], max: usize) -> Result<usize, Error> {
    let response_len = u32::from_be_bytes(header);
    let Some(response_len_usize) = usize::try_from(response_len).ok().filter(|len| *len <= max)
    else {
        return Err(Error::TcpResponseTooLarge {
            actual: response_len,
            limit: max,
        });
    };
    Ok(response_len_usize)
}

/// Public record-mark boundary regressions.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use crate::{client::transport::kdc_tcp_record_length, error::Client};

    /// A reserved bit is rejected independently of the configured cap.
    #[test]
    fn reserved_record_bit_is_rejected() {
        // Given a reserved-bit record mark, when parsed, then reject its framing.
        assert!(matches!(
            kdc_tcp_record_length(0x8000_0001_u32.to_be_bytes(), usize::MAX),
            Err(Client::TcpReservedBitSet)
        ));
    }

    /// Empty records cannot represent a KDC response.
    #[test]
    fn empty_record_is_rejected() {
        // Given a zero mark, when parsed, then reject the empty response.
        assert!(matches!(
            kdc_tcp_record_length([0; 4], 16),
            Err(Client::EmptyKdcResponse)
        ));
    }

    /// The configured cap is inclusive and enforced before allocation.
    #[test]
    fn record_cap_is_inclusive() -> Result<(), Client> {
        // Given marks at and beyond a small cap, when parsed, then only the boundary fits.
        assert_eq!(kdc_tcp_record_length(16_u32.to_be_bytes(), 16)?, 16);
        assert!(matches!(
            kdc_tcp_record_length(17_u32.to_be_bytes(), 16),
            Err(Client::TcpResponseTooLarge {
                actual: 17,
                limit: 16
            })
        ));
        Ok(())
    }
}
