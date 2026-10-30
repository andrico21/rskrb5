//! Bounded UDP socket primitives.

use std::io;

use tokio::net::{ToSocketAddrs, UdpSocket, lookup_host};

use super::Error;

/// Connect a datagram socket matching the selected address family.
///
/// # Errors
/// Returns resolution, bind or connection errors.
///
/// # Cancel safety
/// cancel-safe: dropping preparation closes sockets before any request is sent.
pub(super) async fn connect<A>(addr: A) -> Result<UdpSocket, Error>
where
    A: ToSocketAddrs,
{
    let mut last_error = io::Error::from(io::ErrorKind::AddrNotAvailable);
    let mut connected = None;
    for candidate in lookup_host(addr).await? {
        let wildcard = if candidate.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let attempt = async {
            let socket = UdpSocket::bind(wildcard).await?;
            socket.connect(candidate).await?;
            Ok::<_, io::Error>(socket)
        }
        .await;
        match attempt {
            Ok(socket) => {
                connected = Some(socket);
                break;
            }
            Err(error) => last_error = error,
        }
    }
    Ok(connected.ok_or(last_error)?)
}

/// Receive with one extra byte to detect datagrams exceeding the configured cap.
///
/// # Errors
/// Returns socket errors or `UdpResponseTooLarge` for an oversized datagram.
///
/// # Cancel safety
/// cancel-safe: Tokio recv leaves no partially consumed datagram on cancellation.
pub(super) async fn receive(socket: &UdpSocket, max: usize) -> Result<Vec<u8>, Error> {
    let capacity = max.min(usize::from(u16::MAX)).saturating_add(1);
    let mut response = vec![0; capacity];
    let length = socket
        .recv(&mut response)
        .await
        .map_err(|error| receive_error(error, max, cfg!(windows)))?;
    if length > max {
        return Err(Error::UdpResponseTooLarge { limit: max });
    }
    response.truncate(length);
    Ok(response)
}

/// Map Windows WSAEMSGSIZE without reclassifying unrelated platform errors.
fn receive_error(error: io::Error, max: usize, windows: bool) -> Error {
    if windows && error.raw_os_error() == Some(10_040) {
        Error::UdpResponseTooLarge { limit: max }
    } else {
        Error::Io(error)
    }
}

/// Platform receive-error classification.
#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use std::io;

    use super::{Error, receive_error};

    /// Windows WSAEMSGSIZE must retain the advertised size-error taxonomy.
    #[test]
    fn windows_message_size_is_typed() {
        // Given an oversized Windows datagram, when mapped, then preserve the cap.
        assert!(matches!(
            receive_error(io::Error::from_raw_os_error(10_040), 16, true),
            Error::UdpResponseTooLarge { limit: 16 }
        ));
    }
}
