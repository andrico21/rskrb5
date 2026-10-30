//! Construction of observed peer addresses.

use super::HostAddress;

impl HostAddress {
    /// Construct an opaque Kerberos address, preserving its type and bytes.
    ///
    /// The caller supplies the encoding appropriate for the address type.
    /// Validation compares both type and bytes exactly with the ticket's addresses.
    #[must_use]
    #[inline]
    pub const fn new(addr_type: i32, address: Vec<u8>) -> Self {
        Self { addr_type, address }
    }

    #[must_use]
    /// Construct an IPv4 host address.
    #[inline]
    pub fn ipv4(address: [u8; 4]) -> Self {
        Self::new(2, address.to_vec())
    }

    /// Construct an IPv6 host address (Kerberos address type 24).
    #[must_use]
    #[inline]
    pub fn ipv6(address: [u8; 16]) -> Self {
        Self::new(24, address.to_vec())
    }
}
