//! Configured password endpoint selection.

use super::{Config, Error, KdcEndpoint, KdcProtocol, Tokio};

/// Prefer configured password servers, using DNS only when enabled.
///
/// # Errors
/// Returns configuration, endpoint parsing or DNS discovery errors.
///
/// # Cancel safety
/// cancel-safe: discovery reads configuration and DNS without mutating credentials.
pub(super) async fn discover(
    transport: &Tokio,
    config: &Config,
    realm: &str,
    protocol: KdcProtocol,
) -> Result<Vec<KdcEndpoint>, Error> {
    if let Some(realm_entry) = config.realm(realm)
        && !realm_entry.kpasswd_server.is_empty()
    {
        return realm_entry
            .kpasswd_server
            .iter()
            .map(|value| KdcEndpoint::configured_with_default_port(protocol, value, 464))
            .collect();
    }

    if config.libdefaults.dns_lookup_kdc.is_enabled() {
        return transport
            .discover_kpasswd_servers_with_dns(realm, protocol)
            .await;
    }

    config
        .configured_kpasswd_servers(realm)?
        .iter()
        .map(|value| KdcEndpoint::configured_with_default_port(protocol, value, 464))
        .collect()
}
