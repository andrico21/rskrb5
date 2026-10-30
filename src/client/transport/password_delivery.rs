//! Single-delivery password mutation transport.

use std::io;

use tokio::net::{ToSocketAddrs, UdpSocket, lookup_host};

use super::{
    Error, KdcEndpoint, KdcProtocol, MAX_UDP_DATAGRAM, TcpFraming, Tokio, non_empty_kdc_response,
    tcp_request_length,
};

/// Try password endpoints only while delivery is definitely unattempted.
///
/// # Errors
/// Returns endpoint failures or the first uncertain mutation outcome.
///
/// # Cancel safety
/// NOT cancel-safe: a delivered password request may already have committed.
pub(super) async fn send_to_endpoints(
    transport: &Tokio,
    realm: &str,
    protocol: KdcProtocol,
    endpoints: Vec<KdcEndpoint>,
    request: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut failures = Vec::new();
    for endpoint in endpoints {
        let result = transport
            .send_password_once(
                endpoint.protocol,
                (endpoint.host.as_str(), endpoint.port),
                request,
            )
            .await;
        match result {
            Ok(response) => return Ok(response),
            Err(error @ Error::KpasswdOutcomeUnknown(_)) => return Err(error),
            Err(error) => failures.push(error.to_string()),
        }
    }
    Err(Error::KdcEndpointFailures {
        realm: realm.to_owned(),
        protocol,
        failures,
    })
}

/// Send one password mutation with separate preparation and delivery budgets.
///
/// # Errors
/// Returns preparation errors before a send, or `KpasswdOutcomeUnknown` afterward.
///
/// # Cancel safety
/// NOT cancel-safe: a cancelled send or reply wait may already have committed.
pub(super) async fn send<A>(
    transport: &Tokio,
    protocol: KdcProtocol,
    addr: A,
    request: &[u8],
) -> Result<Vec<u8>, Error>
where
    A: ToSocketAddrs,
{
    match protocol {
        KdcProtocol::Tcp => {
            let _length = tcp_request_length(request.len(), TcpFraming::Kpasswd)?;
            let mut stream = transport
                .with_transport_timeout(Tokio::connect_tcp(addr))
                .await?;
            transport
                .with_transport_timeout(transport.exchange_tcp_framed(
                    &mut stream,
                    request,
                    TcpFraming::Kpasswd,
                ))
                .await
                .map_err(|error| Error::KpasswdOutcomeUnknown(Box::new(error)))
        }
        KdcProtocol::Udp | KdcProtocol::Auto => {
            if request.len() > MAX_UDP_DATAGRAM {
                return Err(Error::UdpRequestTooLarge {
                    actual: request.len(),
                    limit: MAX_UDP_DATAGRAM,
                });
            }
            let socket = transport
                .with_transport_timeout(async {
                    let mut last_error = io::Error::from(io::ErrorKind::AddrNotAvailable);
                    for candidate in lookup_host(addr).await? {
                        let wildcard = if candidate.is_ipv4() {
                            "0.0.0.0:0"
                        } else {
                            "[::]:0"
                        };
                        let result = async {
                            let socket = UdpSocket::bind(wildcard).await?;
                            socket.connect(candidate).await?;
                            Ok::<_, io::Error>(socket)
                        }
                        .await;
                        match result {
                            Ok(socket) => return Ok(socket),
                            Err(error) => last_error = error,
                        }
                    }
                    Err(Error::Io(last_error))
                })
                .await?;
            transport
                .with_transport_timeout(async {
                    let _: usize = socket.send(request).await?;
                    let mut response = vec![
                        0;
                        transport
                            .udp_response_limit
                            .min(usize::from(u16::MAX))
                            .saturating_add(1)
                    ];
                    let length = socket.recv(&mut response).await?;
                    if length > transport.udp_response_limit {
                        return Err(Error::UdpResponseTooLarge {
                            limit: transport.udp_response_limit,
                        });
                    }
                    response.truncate(length);
                    non_empty_kdc_response(response)
                })
                .await
                .map_err(|error| Error::KpasswdOutcomeUnknown(Box::new(error)))
        }
    }
}
