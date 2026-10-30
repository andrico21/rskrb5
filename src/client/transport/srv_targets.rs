//! Ordered SRV target address resolution.

use super::{
    Error, KdcEndpoint, KdcEndpointSource, KdcProtocol, TokioResolver, resolve_dns_endpoint_host,
};

/// Resolve selected SRV targets while preserving their service order.
///
/// # Errors
/// Returns target address lookup errors.
///
/// # Cancel safety
/// cancel-safe: DNS lookups change no credential state.
pub(super) async fn resolve(
    resolver: &TokioResolver,
    realm: &str,
    protocol: KdcProtocol,
    records: Vec<(u16, u16, String, u16)>,
    resolve_targets: bool,
) -> Result<Vec<KdcEndpoint>, Error> {
    let mut endpoints = Vec::with_capacity(records.len());
    let mut failures = Vec::new();
    for (_, _, target, port) in records {
        let hosts = if resolve_targets {
            match resolve_dns_endpoint_host(resolver, realm, protocol, &target).await {
                Ok(hosts) => hosts,
                Err(error) => {
                    failures.push(error.to_string());
                    continue;
                }
            }
        } else {
            vec![target]
        };
        endpoints.extend(hosts.into_iter().map(|host| KdcEndpoint {
            protocol,
            host,
            port,
            source: KdcEndpointSource::DnsSrv,
        }));
    }
    if endpoints.is_empty() && !failures.is_empty() {
        return Err(Error::DnsSrvLookup {
            realm: realm.to_owned(),
            protocol,
            message: failures.join("; "),
        });
    }
    Ok(endpoints)
}
