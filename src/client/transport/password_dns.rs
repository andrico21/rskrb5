//! DNS password-service fallback.

use super::{Error, KdcEndpoint, KdcProtocol, Tokio};

/// Discover password servers, falling back to administrative service hosts.
///
/// # Errors
/// Returns DNS lookup, unavailable-service or empty-endpoint errors.
///
/// # Cancel safety
/// cancel-safe: abandoning DNS lookups changes no credential state.
pub(super) async fn discover(
    transport: &Tokio,
    realm: &str,
    protocol: KdcProtocol,
) -> Result<Vec<KdcEndpoint>, Error> {
    match transport
        .discover_srv_endpoints("_kpasswd", realm, protocol)
        .await
    {
        Ok(endpoints) if !endpoints.is_empty() => return Ok(endpoints),
        Err(
            error @ Error::DnsServiceUnavailable {
                service: _,
                realm: _,
            },
        ) => return Err(error),
        Ok(_) | Err(_) => {}
    }
    let mut endpoints = transport
        .discover_srv_endpoints("_kerberos-adm", realm, KdcProtocol::Tcp)
        .await?;
    for endpoint in &mut endpoints {
        endpoint.port = 464;
        endpoint.protocol = protocol;
    }
    if endpoints.is_empty() {
        Err(Error::NoKdcEndpoints {
            realm: realm.to_owned(),
            protocol,
        })
    } else {
        Ok(endpoints)
    }
}
