//! DNS server literal boundary tests.

use core::net::IpAddr;

use super::parse_dns_server;

/// Brackets distinguish an explicit port from the final IPv6 address component.
#[test]
fn ipv6_dns_port_requires_brackets() -> Result<(), String> {
    // Given two similar-looking literals with different authority semantics.
    let explicit = parse_dns_server("[fd00::1]:5353")?;
    let bare = parse_dns_server("fd00::1:5353")?;
    // Then only the bracketed authority selects a nondefault DNS port.
    assert_eq!(
        explicit,
        (
            "fd00::1"
                .parse::<IpAddr>()
                .map_err(|error| error.to_string())?,
            5353
        )
    );
    assert_eq!(
        bare,
        (
            "fd00::1:5353"
                .parse::<IpAddr>()
                .map_err(|error| error.to_string())?,
            53
        )
    );
    Ok(())
}
