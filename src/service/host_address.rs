//! Construction of observed peer addresses.

use super::HostAddress;

impl HostAddress {
    #[must_use]
    /// Construct an IPv4 host address.
    #[inline]
    pub fn ipv4(address: [u8; 4]) -> Self {
        Self {
            addr_type: 2,
            address: address.to_vec(),
        }
    }
}
