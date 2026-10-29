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
    let response_len = u32::from_be_bytes(header);
    validate_tcp_length(response_len, framing)?;
    let Some(response_len_usize) = usize::try_from(response_len).ok().filter(|len| *len <= max)
    else {
        return Err(Error::TcpResponseTooLarge {
            actual: response_len,
            limit: max,
        });
    };
    Ok(response_len_usize)
}
