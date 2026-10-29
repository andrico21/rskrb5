//! Service endpoint selection for live fixtures.

use std::env;

/// Returns the primary KDC endpoint from `TEST_KDC_ADDR`/`TEST_KDC_PORT`.
pub(super) fn kdc_addr() -> String {
    let host = env::var("TEST_KDC_ADDR").unwrap_or_else(|_| "127.0.0.1".to_owned());
    if host
        .rsplit_once(':')
        .is_some_and(|(_, port)| port.parse::<u16>().is_ok())
    {
        return host;
    }

    let port = env::var("TEST_KDC_PORT").unwrap_or_else(|_| "88".to_owned());
    format!("{host}:{port}")
}

/// Returns the short-ticket KDC endpoint.
pub(super) fn short_kdc_addr() -> String {
    let host = env::var("TEST_SHORT_KDC_ADDR")
        .or_else(|_| env::var("TEST_KDC_ADDR"))
        .unwrap_or_else(|_| "127.0.0.1".to_owned());
    if host
        .rsplit_once(':')
        .is_some_and(|(_, port)| port.parse::<u16>().is_ok())
    {
        return host;
    }

    let port = env::var("TEST_SHORT_KDC_PORT").unwrap_or_else(|_| "58".to_owned());
    format!("{host}:{port}")
}

/// Returns the legacy KDC endpoint.
pub(super) fn old_kdc_addr() -> String {
    let host = env::var("TEST_OLD_KDC_ADDR")
        .or_else(|_| env::var("TEST_KDC_ADDR"))
        .unwrap_or_else(|_| "127.0.0.1".to_owned());
    if host
        .rsplit_once(':')
        .is_some_and(|(_, port)| port.parse::<u16>().is_ok())
    {
        return host;
    }

    let port = env::var("TEST_OLD_KDC_PORT").unwrap_or_else(|_| "78".to_owned());
    format!("{host}:{port}")
}

/// Returns the latest (AES-SHA2) KDC endpoint.
pub(super) fn latest_kdc_addr() -> String {
    let host = env::var("TEST_LATEST_KDC_ADDR")
        .or_else(|_| env::var("TEST_KDC_ADDR"))
        .unwrap_or_else(|_| "127.0.0.1".to_owned());
    if host
        .rsplit_once(':')
        .is_some_and(|(_, port)| port.parse::<u16>().is_ok())
    {
        return host;
    }

    let port = env::var("TEST_LATEST_KDC_PORT").unwrap_or_else(|_| "98".to_owned());
    format!("{host}:{port}")
}

/// Returns the resource-realm KDC endpoint.
pub(super) fn resdom_kdc_addr() -> String {
    let host = env::var("TEST_RESDOM_KDC_ADDR")
        .or_else(|_| env::var("TEST_KDC_ADDR"))
        .unwrap_or_else(|_| "127.0.0.1".to_owned());
    if host
        .rsplit_once(':')
        .is_some_and(|(_, port)| port.parse::<u16>().is_ok())
    {
        return host;
    }

    let port = env::var("TEST_RESDOM_KDC_PORT").unwrap_or_else(|_| "188".to_owned());
    format!("{host}:{port}")
}

/// Returns the kpasswd endpoint from `TEST_KPASSWD_ADDR`/`TEST_KPASSWD_PORT`.
pub(super) fn kpasswd_addr() -> String {
    let host = env::var("TEST_KPASSWD_ADDR").unwrap_or_else(|_| "127.0.0.1".to_owned());
    if host
        .rsplit_once(':')
        .is_some_and(|(_, port)| port.parse::<u16>().is_ok())
    {
        return host;
    }

    let port = env::var("TEST_KPASSWD_PORT").unwrap_or_else(|_| "464".to_owned());
    format!("{host}:{port}")
}
