//! Regressions for the allocation boundary of HTTP Negotiate decoding.

use super::{Error, NegTokenResp, Token, negotiate_header, parse_negotiate_header};

/// Oversized valid base64 is rejected before DER decoding can consume its allocation.
#[test]
fn negotiate_header_limit_rejects_base64_before_der() -> Result<(), Error> {
    let header = format!("Negotiate {}", "AAAA".repeat(0x4000));

    let result = parse_negotiate_header(&header);

    assert!(matches!(
        result.err().ok_or(Error::EmptyInput)?,
        Error::NegotiateHeaderTooLong { maximum: 0x0001_0000, actual }
            if actual == header.len()
    ));
    Ok(())
}

/// An oversized malformed token returns the size error rather than a base64 error.
#[test]
fn negotiate_header_limit_precedes_base64_validation() -> Result<(), Error> {
    let header = format!("Negotiate {}", "%".repeat(0xfff7));

    let result = parse_negotiate_header(&header);

    assert!(matches!(
        result.err().ok_or(Error::EmptyInput)?,
        Error::NegotiateHeaderTooLong {
            maximum: 0x0001_0000,
            actual: 0x0001_0001
        }
    ));
    Ok(())
}

/// Whitespace around a valid token cannot bypass the whole-header byte cap.
#[test]
fn negotiate_header_limit_counts_whitespace() -> Result<(), Error> {
    let token = Token::Resp(NegTokenResp::accept_completed());
    let encoded = negotiate_header(&token)?;
    let header = format!(
        "{encoded}{:padding$}",
        "",
        padding = 0x0001_0001 - encoded.len()
    );

    let result = parse_negotiate_header(&header);

    assert!(matches!(
        result,
        Err(Error::NegotiateHeaderTooLong {
            maximum: 0x0001_0000,
            actual: 0x0001_0001
        })
    ));
    Ok(())
}

/// A large valid SPNEGO token remains accepted at the inclusive header boundary.
#[test]
fn negotiate_header_limit_accepts_boundary() -> Result<(), Error> {
    let token =
        Token::Resp(NegTokenResp::accept_completed().with_response_token(vec![0x42; 48_000]));
    let encoded = negotiate_header(&token)?;
    let header = format!(
        "{encoded}{:padding$}",
        "",
        padding = 0x0001_0000 - encoded.len()
    );

    let result = parse_negotiate_header(&header)?;

    assert_eq!(result, token);
    Ok(())
}

/// Small malformed base64 keeps its existing error classification.
#[test]
fn negotiate_header_limit_preserves_base64_error() -> Result<(), Error> {
    let result = parse_negotiate_header("Negotiate %");

    assert!(matches!(
        result.err().ok_or(Error::EmptyInput)?,
        Error::Base64(_)
    ));
    Ok(())
}

/// Missing tokens keep their existing error classification.
#[test]
fn negotiate_header_limit_preserves_missing_token_error() -> Result<(), Error> {
    let result = parse_negotiate_header("Negotiate");

    assert!(matches!(
        result.err().ok_or(Error::EmptyInput)?,
        Error::InvalidNegotiateHeader
    ));
    Ok(())
}
