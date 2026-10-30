//! Configured realm protocol preference.

use super::{
    Config, Error, KRB_ERR_RESPONSE_TOO_BIG, KdcProtocol, Tokio, auto_uses_udp_first,
    kdc_error_code,
};

/// Try configured transports in their preferred order.
///
/// # Errors
/// Returns the final discovery or exchange error.
///
/// # Cancel safety
/// cancel-safe: requests change no local state and sockets close on cancellation.
pub(super) async fn send(
    transport: &Tokio,
    config: &Config,
    realm: &str,
    request: &[u8],
) -> Result<Vec<u8>, Error> {
    let udp_first = auto_uses_udp_first(config, request.len());
    let (first, second) = if udp_first {
        (KdcProtocol::Udp, KdcProtocol::Tcp)
    } else {
        (KdcProtocol::Tcp, KdcProtocol::Udp)
    };
    match transport
        .send_to_realm_explicit(config, first, realm, request)
        .await
    {
        Ok(response)
            if first == KdcProtocol::Udp
                && kdc_error_code(&response) == Some(KRB_ERR_RESPONSE_TOO_BIG) =>
        {
            transport
                .send_to_realm_explicit(config, second, realm, request)
                .await
        }
        Ok(response) => Ok(response),
        Err(_) => {
            transport
                .send_to_realm_explicit(config, second, realm, request)
                .await
        }
    }
}
