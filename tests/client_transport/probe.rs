//! Live KDC probe exchange implementation.

use super::*;

/// Send one bare AS-REQ on an existing stream and classify the outcome.
pub(super) async fn probe_exchange(
    stream: &mut TcpStream,
    realm: &str,
    user: &str,
    nonce: u32,
) -> Result<ProbeOutcome, TestError> {
    let client = Principal::user(realm, user);
    let request = build_tgt_as_req(client, AsReq::new(SystemTime::now(), nonce))?;

    let mut framed = Vec::with_capacity(request.der.len().saturating_add(4));
    framed.extend_from_slice(&u32::try_from(request.der.len())?.to_be_bytes());
    framed.extend_from_slice(&request.der);
    if let Err(error) = stream.write_all(&framed).await {
        return Ok(ProbeOutcome::Closed(format!("write failed: {error}")));
    }

    let mut header = [0; 4];
    if let Err(error) = stream.read_exact(&mut header).await {
        return Ok(ProbeOutcome::Closed(format!(
            "no response length: {} ({error})",
            error.kind()
        )));
    }

    let mut response = vec![0; usize::try_from(u32::from_be_bytes(header))?];
    if let Err(error) = stream.read_exact(&mut response).await {
        return Ok(ProbeOutcome::Closed(format!(
            "truncated response: {} ({error})",
            error.kind()
        )));
    }

    Ok(ProbeOutcome::Answered {
        len: response.len(),
        error_code: krb_error_code(&response),
    })
}
