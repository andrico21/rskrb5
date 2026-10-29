//! Service endpoint selection for live fixtures.

use core::net::IpAddr;
use std::env;

/// Returns the primary KDC endpoint from `TEST_KDC_ADDR`/`TEST_KDC_PORT`.
pub(super) fn kdc_addr() -> String {
    let host = env::var("TEST_KDC_ADDR").unwrap_or_else(|_| "127.0.0.1".to_owned());
    let port = env::var("TEST_KDC_PORT").unwrap_or_else(|_| "88".to_owned());
    authority(&host, &port)
}

/// Returns the short-ticket KDC endpoint.
pub(super) fn short_kdc_addr() -> String {
    let host = env::var("TEST_SHORT_KDC_ADDR")
        .or_else(|_| env::var("TEST_KDC_ADDR"))
        .unwrap_or_else(|_| "127.0.0.1".to_owned());
    let port = env::var("TEST_SHORT_KDC_PORT").unwrap_or_else(|_| "58".to_owned());
    authority(&host, &port)
}

/// Returns the legacy KDC endpoint.
pub(super) fn old_kdc_addr() -> String {
    let host = env::var("TEST_OLD_KDC_ADDR")
        .or_else(|_| env::var("TEST_KDC_ADDR"))
        .unwrap_or_else(|_| "127.0.0.1".to_owned());
    let port = env::var("TEST_OLD_KDC_PORT").unwrap_or_else(|_| "78".to_owned());
    authority(&host, &port)
}

/// Returns the latest (AES-SHA2) KDC endpoint.
pub(super) fn latest_kdc_addr() -> String {
    let host = env::var("TEST_LATEST_KDC_ADDR")
        .or_else(|_| env::var("TEST_KDC_ADDR"))
        .unwrap_or_else(|_| "127.0.0.1".to_owned());
    let port = env::var("TEST_LATEST_KDC_PORT").unwrap_or_else(|_| "98".to_owned());
    authority(&host, &port)
}

/// Returns the resource-realm KDC endpoint.
pub(super) fn resdom_kdc_addr() -> String {
    let host = env::var("TEST_RESDOM_KDC_ADDR")
        .or_else(|_| env::var("TEST_KDC_ADDR"))
        .unwrap_or_else(|_| "127.0.0.1".to_owned());
    let port = env::var("TEST_RESDOM_KDC_PORT").unwrap_or_else(|_| "188".to_owned());
    authority(&host, &port)
}

/// Returns the kpasswd endpoint from `TEST_KPASSWD_ADDR`/`TEST_KPASSWD_PORT`.
pub(super) fn kpasswd_addr() -> String {
    let host = env::var("TEST_KPASSWD_ADDR").unwrap_or_else(|_| "127.0.0.1".to_owned());
    let port = env::var("TEST_KPASSWD_PORT").unwrap_or_else(|_| "464".to_owned());
    authority(&host, &port)
}

/// Preserve a full IP literal before deciding whether a colon introduces a port.
fn authority(host: &str, port: &str) -> String {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => format!("[{host}]:{port}"),
        Ok(IpAddr::V4(_)) => format!("{host}:{port}"),
        Err(_) => {
            if host
                .rsplit_once(':')
                .is_some_and(|(_, value)| value.parse::<u16>().is_ok())
            {
                host.to_owned()
            } else {
                format!("{host}:{port}")
            }
        }
    }
}

/// Isolated environment checks for each service authority.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "endpoint_tests.rs"]
mod tests;
