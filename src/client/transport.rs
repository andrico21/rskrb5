//! Tokio-backed KDC transport, endpoint discovery, and network exchanges.

use core::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use std::io;

/// Service-specific TCP record length validation.
mod framing;

/// Validate a KDC TCP record mark before allocating its response body.
///
/// # Errors
/// Returns [`Error::TcpReservedBitSet`] for the RFC 4120 reserved high bit,
/// [`Error::TcpResponseTooLarge`] above `max`, and [`Error::EmptyKdcResponse`]
/// for a zero-length record. This validator does not apply to kpasswd framing.
#[inline]
pub fn kdc_tcp_record_length(header: [u8; 4], max: usize) -> Result<usize, Error> {
    framing::kdc_record_length(header, max)
}
/// Password result consumption after a transport exchange.
mod password_result;
use framing::tcp_request_length;
#[cfg(test)]
use framing::validate_tcp_length;
use hickory_resolver::{
    TokioResolver,
    config::{ConnectionConfig, NameServerConfig, ResolverConfig},
    net::runtime::TokioRuntimeProvider,
    proto::rr::RData,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpStream, ToSocketAddrs, UdpSocket, lookup_host},
    time::timeout,
};

use super::{
    AsRepSession, AsReq, BuiltAsReq, BuiltTgsReq, Error, KRB_ERR_RESPONSE_TOO_BIG, KRB_NT_SRV_INST,
    Principal, ReferralTgsResult, TgsRepSession, TgsReq, build_s4u2proxy_req, build_s4u2self_req,
    build_tgs_req_for_realm, build_tgt_renewal_req, build_ticket_renewal_req,
    keytab_initial_as_rep_session, keytab_initial_as_req, keytab_preauth_request,
    password_initial_as_rep_session, password_initial_as_req, password_preauth_request,
    principal_matches, process_as_rep, process_tgs_rep, process_tgs_rep_with_referral,
    service_realm, tgt_realm,
};
use crate::{
    config::Config,
    error::Config as ConfigError,
    kadmin,
    keytab::{EncryptionKey, Keytab},
    krb_error::decode as decode_krb_error,
};

/// Default timeout applied to each KDC exchange.
#[cfg(feature = "tokio")]
const DEFAULT_KDC_TIMEOUT: Duration = Duration::from_secs(5);
/// Default maximum accepted TCP response body size, 16 MiB.
#[cfg(feature = "tokio")]
const DEFAULT_TCP_RESPONSE_LIMIT: usize = 16 * 1024 * 1024;
/// Largest UDP payload over IPv4: 65,535 minus the 8-byte UDP and 20-byte IP
/// headers.
#[cfg(feature = "tokio")]
const MAX_UDP_DATAGRAM: usize = 65_507;
/// Default maximum number of cross-realm referrals followed for one ticket.
#[cfg(feature = "tokio")]
const DEFAULT_MAX_REFERRALS: usize = 5;
/// Byte length of the RFC 4120 section 7.2.2 record mark prefixing each TCP message.
#[cfg(feature = "tokio")]
const TCP_RECORD_MARK_LEN: usize = 4;

/// TCP length rules belong to the service, not to the underlying stream.
#[derive(Clone, Copy)]
enum TcpFraming {
    /// RFC 4120 reserves the high bit for KDC messages.
    Kdc,
    /// RFC 3244 uses its own unsigned length field.
    Kpasswd,
}

/// KDC wire protocol for Tokio transport operations.
#[cfg(feature = "tokio")]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum KdcProtocol {
    /// RFC 4120 UDP transport with raw DER request and response datagrams.
    Udp,
    /// RFC 4120 TCP transport with a four-byte big-endian length prefix.
    Tcp,
    /// gokrb5-style transport preference using UDP/TCP fallback.
    Auto,
}

/// Source used to discover a KDC endpoint.
#[cfg(feature = "tokio")]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum KdcEndpointSource {
    /// Endpoint came from a `[realms]` `kdc = ...` entry.
    Config,
    /// Endpoint came from `_kerberos._udp` or `_kerberos._tcp` DNS SRV lookup.
    DnsSrv,
}

/// One KDC endpoint discovered for a realm.
#[cfg(feature = "tokio")]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct KdcEndpoint {
    /// Wire protocol to use for this endpoint.
    pub protocol: KdcProtocol,
    /// Host name or IP literal.
    pub host: String,
    /// Kerberos service port.
    pub port: u16,
    /// How this endpoint was discovered.
    pub source: KdcEndpointSource,
}

#[cfg(feature = "tokio")]
impl KdcEndpoint {
    /// Create a configured endpoint from a `host[:port]` value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKdcEndpoint`] when `value` is empty, has an
    /// unterminated or empty `[...]` IPv6 host, has a port that is not a `u16`, or
    /// has a single `:` without a valid port.
    #[inline]
    pub fn configured(protocol: KdcProtocol, value: &str) -> Result<Self, Error> {
        Self::configured_with_default_port(protocol, value, 88)
    }

    /// Create a configured endpoint from a `host[:port]` value and default port.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKdcEndpoint`] when `value` is empty, has an
    /// unterminated or empty `[...]` IPv6 host, has a port that is not a `u16`, or
    /// has a single `:` without a valid port.
    #[inline]
    pub fn configured_with_default_port(
        protocol: KdcProtocol,
        value: &str,
        default_port: u16,
    ) -> Result<Self, Error> {
        let (host, port) = parse_kdc_endpoint(value, default_port)?;
        Ok(Self {
            protocol,
            host,
            port,
            source: KdcEndpointSource::Config,
        })
    }

    #[must_use]
    /// Return a display-friendly `host:port` authority.
    #[inline]
    pub fn authority(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// Tokio-backed KDC transport for explicit TCP or UDP exchanges.
#[cfg(feature = "tokio")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Tokio {
    /// Explicit DNS server; otherwise use the system resolver.
    dns_server: Option<(IpAddr, u16)>,
    /// Timeout applied to each KDC exchange.
    timeout: Duration,
    /// Maximum accepted UDP response size.
    udp_response_limit: usize,
    /// Maximum accepted TCP response body size.
    tcp_response_limit: usize,
}

#[cfg(feature = "tokio")]
impl Default for Tokio {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "tokio")]
impl Tokio {
    #[must_use]
    /// Create a transport with conservative gokrb5-compatible defaults.
    #[inline]
    pub const fn new() -> Self {
        Self {
            dns_server: None,
            timeout: DEFAULT_KDC_TIMEOUT,
            udp_response_limit: MAX_UDP_DATAGRAM + 1,
            tcp_response_limit: DEFAULT_TCP_RESPONSE_LIMIT,
        }
    }

    #[must_use]
    /// Override the timeout applied to each KDC exchange.
    #[inline]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Select an explicit DNS server using an IP literal and optional port.
    ///
    /// Blank input selects the system resolver. Bare IP literals use port 53.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DnsResolverConfig`] for malformed server literals.
    #[inline]
    pub fn with_dns_server(mut self, value: &str) -> Result<Self, Error> {
        self.dns_server = if value.trim().is_empty() {
            None
        } else {
            Some(parse_dns_server(value).map_err(Error::DnsResolverConfig)?)
        };
        Ok(self)
    }

    #[must_use]
    /// Override the maximum accepted UDP response size.
    #[inline]
    pub const fn with_udp_response_limit(mut self, udp_response_limit: usize) -> Self {
        self.udp_response_limit = udp_response_limit;
        self
    }

    #[must_use]
    /// Override the maximum accepted TCP response body size.
    #[inline]
    pub const fn with_tcp_response_limit(mut self, tcp_response_limit: usize) -> Self {
        self.tcp_response_limit = tcp_response_limit;
        self
    }

    /// Send an encoded KDC request over UDP.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UdpRequestTooLarge`] when `request` exceeds the largest
    /// UDP datagram, [`Error::Io`] when the socket fails,
    /// [`Error::TransportTimeout`] when the exchange exceeds the transport
    /// timeout, and [`Error::EmptyKdcResponse`] for an empty reply.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future closes any socket it opened and abandons the request, which the
    /// caller can send again.
    #[inline]
    pub async fn send_udp<A>(&self, addr: A, request: &[u8]) -> Result<Vec<u8>, Error>
    where
        A: ToSocketAddrs,
    {
        if request.len() > MAX_UDP_DATAGRAM {
            return Err(Error::UdpRequestTooLarge {
                actual: request.len(),
                limit: MAX_UDP_DATAGRAM,
            });
        }

        self.with_transport_timeout(async {
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
            let socket = connected.ok_or(last_error)?;
            let _: usize = socket.send(request).await?;

            let capacity = self
                .udp_response_limit
                .min(usize::from(u16::MAX))
                .saturating_add(1);
            let mut response = vec![0; capacity];
            let len = socket.recv(&mut response).await?;
            if len > self.udp_response_limit {
                return Err(Error::UdpResponseTooLarge {
                    limit: self.udp_response_limit,
                });
            }
            response.truncate(len);
            Ok(response)
        })
        .await
        .and_then(non_empty_kdc_response)
    }

    /// Send an encoded KDC request over RFC 4120 TCP framing.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] when the connection or the stream fails,
    /// [`Error::TransportTimeout`] when the exchange exceeds the transport
    /// timeout, [`Error::TcpRequestTooLarge`] or [`Error::TcpResponseTooLarge`]
    /// when a message exceeds its limit, and [`Error::EmptyKdcResponse`] for an
    /// empty reply.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future closes any socket it opened and abandons the request, which the
    /// caller can send again.
    #[inline]
    pub async fn send_tcp<A>(&self, addr: A, request: &[u8]) -> Result<Vec<u8>, Error>
    where
        A: ToSocketAddrs,
    {
        self.send_tcp_pinned(addr, request)
            .await
            .map(|(response, _)| response)
    }

    /// Perform a TCP exchange and keep the stream open for a follow-up request.
    ///
    /// RFC 4120 section 7.2.2 permits the KDC to leave the stream open when it
    /// expects a follow-up, which lets a two-phase AS exchange avoid a second
    /// connect.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] when the connection or the stream fails,
    /// [`Error::TransportTimeout`] when the exchange exceeds the transport
    /// timeout, and the framing errors of [`Self::exchange_tcp`].
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future closes any socket it opened and abandons the request, which the
    /// caller can send again.
    async fn send_tcp_pinned<A>(
        &self,
        addr: A,
        request: &[u8],
    ) -> Result<(Vec<u8>, TcpStream), Error>
    where
        A: ToSocketAddrs,
    {
        self.with_transport_timeout(async {
            let mut stream = Self::connect_tcp(addr).await?;
            let response = self.exchange_tcp(&mut stream, request).await?;
            Ok((response, stream))
        })
        .await
    }

    /// Open a KDC stream with Nagle disabled.
    ///
    /// Applies no timeout of its own; callers wrap this in
    /// [`Self::with_transport_timeout`] together with the exchanges they intend
    /// to perform, so one logical request keeps one timeout budget.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] when the connection or `TCP_NODELAY` cannot be
    /// set up.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: dropping the future drops the half-open socket and changes no
    /// state.
    async fn connect_tcp<A>(addr: A) -> Result<TcpStream, Error>
    where
        A: ToSocketAddrs,
    {
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;
        Ok(stream)
    }

    /// Perform one RFC 4120 framed request/response exchange on an open stream.
    ///
    /// The record mark and the request body are written as a single segment:
    /// splitting them leaves the body waiting on the peer's delayed-ACK timer
    /// before Nagle will release it. Applies no timeout of its own; see
    /// [`Self::connect_tcp`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::TcpRequestTooLarge`] when `request` does not fit a record
    /// mark, [`Error::Io`] when the stream fails, [`Error::TcpResponseTooLarge`]
    /// when the reply exceeds the configured limit, and
    /// [`Error::EmptyKdcResponse`] for an empty reply.
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe for `stream`: dropping the future mid-exchange can leave a
    /// partial record written to or unread from the stream. Discard the stream
    /// then instead of reusing it.
    async fn exchange_tcp(&self, stream: &mut TcpStream, request: &[u8]) -> Result<Vec<u8>, Error> {
        self.exchange_tcp_framed(stream, request, TcpFraming::Kdc)
            .await
    }

    /// Exchange one bounded TCP record using the service's length rules.
    ///
    /// # Errors
    /// Returns I/O, length, reserved-bit or empty-response errors.
    ///
    /// # Cancel safety
    /// NOT cancel-safe for the stream: discard it after a cancelled exchange.
    async fn exchange_tcp_framed(
        &self,
        stream: &mut TcpStream,
        request: &[u8],
        framing: TcpFraming,
    ) -> Result<Vec<u8>, Error> {
        let request_len = tcp_request_length(request.len(), framing)?;
        let mut framed = Vec::with_capacity(request.len().saturating_add(TCP_RECORD_MARK_LEN));
        framed.extend_from_slice(&request_len.to_be_bytes());
        framed.extend_from_slice(request);
        stream.write_all(&framed).await?;

        let mut header = [0; TCP_RECORD_MARK_LEN];
        let _: usize = stream.read_exact(&mut header).await?;
        let response_len_usize =
            framing::response_length(header, framing, self.tcp_response_limit)?;

        let mut response = vec![0; response_len_usize];
        let _: usize = stream.read_exact(&mut response).await?;
        non_empty_kdc_response(response)
    }

    /// Send an encoded KDC request and keep a TCP stream open for a follow-up.
    ///
    /// Returns no stream for [`KdcProtocol::Udp`], which has none. For
    /// [`KdcProtocol::Auto`] a stream exists exactly when the request fell back
    /// to TCP, so a follow-up reuses the connection that answered instead of
    /// probing UDP again and opening a second connection.
    ///
    /// # Errors
    ///
    /// Returns the errors of the transport that carried the request: those of
    /// [`Self::send_udp`] for [`KdcProtocol::Udp`], and those of the TCP exchange
    /// for [`KdcProtocol::Tcp`] and for an [`KdcProtocol::Auto`] fallback.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future closes any socket it opened and abandons the request, which the
    /// caller can send again.
    async fn send_pinned<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        request: &[u8],
    ) -> Result<(Vec<u8>, Option<TcpStream>), Error>
    where
        A: ToSocketAddrs + Clone,
    {
        match protocol {
            KdcProtocol::Tcp => self
                .send_tcp_pinned(addr, request)
                .await
                .map(|(response, stream)| (response, Some(stream))),
            KdcProtocol::Udp => self
                .send_udp(addr, request)
                .await
                .map(|response| (response, None)),
            KdcProtocol::Auto => match self.send_udp(addr.clone(), request).await {
                Ok(response) if kdc_error_code(&response) == Some(KRB_ERR_RESPONSE_TOO_BIG) => self
                    .send_tcp_pinned(addr, request)
                    .await
                    .map(|(tcp_response, stream)| (tcp_response, Some(stream))),
                Ok(response) => Ok((response, None)),
                Err(_) => self
                    .send_tcp_pinned(addr, request)
                    .await
                    .map(|(response, stream)| (response, Some(stream))),
            },
        }
    }

    /// Send a follow-up request on a stream pinned by an earlier exchange.
    ///
    /// Returns `Ok(None)` when there is no pinned stream, or when the KDC closed
    /// the one we had: RFC 4120 section 7.2.2 permits the KDC to close the
    /// stream at any time after a response and requires that closure not be
    /// treated as fatal, so the caller retries on a fresh connection. Protocol
    /// errors would recur on a new connection, so they propagate instead of
    /// spending another round trip.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TransportTimeout`] when the follow-up exceeds the
    /// transport timeout, and the framing errors of [`Self::exchange_tcp`]; a
    /// closed stream is `Ok(None)` instead.
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe for the pinned stream: dropping the future mid-exchange can leave a
    /// partial record written to or unread from the stream. Discard the stream
    /// then instead of reusing it.
    async fn send_follow_up(
        &self,
        pinned: Option<&mut TcpStream>,
        request: &[u8],
    ) -> Result<Option<Vec<u8>>, Error> {
        let Some(stream) = pinned else {
            return Ok(None);
        };
        match self
            .with_transport_timeout(self.exchange_tcp(stream, request))
            .await
        {
            Ok(response) => Ok(Some(response)),
            Err(Error::Io(_)) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Send an encoded KDC request over the selected protocol.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::send_udp`] for [`KdcProtocol::Udp`] and of
    /// [`Self::send_tcp`] for [`KdcProtocol::Tcp`]. [`KdcProtocol::Auto`] retries
    /// over TCP after a failed or `KRB_ERR_RESPONSE_TOO_BIG` UDP attempt and
    /// returns the TCP errors.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future closes any socket it opened and abandons the request, which the
    /// caller can send again.
    #[inline]
    pub async fn send<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        request: &[u8],
    ) -> Result<Vec<u8>, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        match protocol {
            KdcProtocol::Udp => self.send_udp(addr, request).await,
            KdcProtocol::Tcp => self.send_tcp(addr, request).await,
            KdcProtocol::Auto => {
                let udp = self.send_udp(addr.clone(), request).await;
                match udp {
                    Ok(response) if kdc_error_code(&response) == Some(KRB_ERR_RESPONSE_TOO_BIG) => {
                        self.send_tcp(addr, request).await
                    }
                    Ok(response) => Ok(response),
                    Err(_) => self.send_tcp(addr, request).await,
                }
            }
        }
    }

    /// Discover KDC endpoints for a realm using `krb5.conf` semantics.
    ///
    /// Configured `[realms]` KDCs are preferred. DNS SRV lookup is attempted
    /// only when no KDCs are configured and `dns_lookup_kdc = true`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKdcEndpoint`] for a malformed configured KDC
    /// entry, [`Error::DnsResolverConfig`] or [`Error::DnsSrvLookup`] when DNS SRV
    /// discovery fails, [`Error::NoKdcEndpoints`] when the realm is configured
    /// without KDCs or DNS finds none, and a configuration error when the realm is
    /// unknown and DNS lookup is disabled.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and only reads `config` and DNS. Dropping
    /// the future abandons the lookup and changes no state.
    #[inline]
    pub async fn discover_kdcs(
        &self,
        config: &Config,
        realm: &str,
        protocol: KdcProtocol,
    ) -> Result<Vec<KdcEndpoint>, Error> {
        if let Some(realm_entry) = config.realm(realm)
            && !realm_entry.kdc.is_empty()
        {
            return realm_entry
                .kdc
                .iter()
                .map(|value| KdcEndpoint::configured(protocol, value))
                .collect();
        }

        if config.libdefaults.dns_lookup_kdc.is_enabled() {
            return self.discover_kdcs_with_dns(realm, protocol).await;
        }

        if config.realm(realm).is_some() {
            Err(Error::NoKdcEndpoints {
                realm: realm.to_owned(),
                protocol,
            })
        } else {
            Err(ConfigError::NoRealm(realm.to_owned()).into())
        }
    }

    /// Discover kpasswd endpoints for a realm.
    ///
    /// Configured `[realms]` kpasswd servers are preferred. DNS SRV lookup is
    /// attempted only when no password-change servers are configured and
    /// `dns_lookup_kdc = true`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKdcEndpoint`] for a malformed server entry,
    /// [`Error::DnsResolverConfig`], [`Error::DnsSrvLookup`] or
    /// [`Error::NoKdcEndpoints`] when DNS SRV discovery fails or finds nothing,
    /// and a configuration error when no kpasswd server can be derived from the
    /// realm's configuration.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and only reads `config` and DNS. Dropping
    /// the future abandons the lookup and changes no state.
    #[inline]
    pub async fn discover_kpasswd_servers(
        &self,
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
            return self
                .discover_kpasswd_servers_with_dns(realm, protocol)
                .await;
        }

        config
            .configured_kpasswd_servers(realm)?
            .iter()
            .map(|value| KdcEndpoint::configured_with_default_port(protocol, value, 464))
            .collect()
    }

    /// Send an encoded request to the first reachable KDC discovered from config.
    ///
    /// # Errors
    ///
    /// Returns the discovery errors of [`Self::discover_kdcs`],
    /// [`Error::NoKdcEndpoints`] when no endpoint is available, and
    /// [`Error::KdcEndpointFailures`] when every endpoint fails.
    /// [`KdcProtocol::Auto`] retries over the other protocol after a failure of
    /// the first and returns the errors of that retry.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future closes any socket it opened and abandons the request, which the
    /// caller can send again.
    #[inline]
    pub async fn send_to_realm(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        realm: &str,
        request: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.send_to_realm_pinned(config, protocol, realm, request)
            .await
            .map(|(response, _)| response)
    }

    /// Send to a realm's KDC and keep a TCP stream open for a follow-up request.
    ///
    /// Discovery runs once here rather than once per request, so a two-phase AS
    /// exchange no longer repeats the DNS SRV lookup.
    ///
    /// # Errors
    ///
    /// Returns the discovery errors of [`Self::discover_kdcs`] and the errors of
    /// [`Self::send_to_endpoints_pinned`].
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future closes any socket it opened and abandons the request, which the
    /// caller can send again.
    async fn send_to_realm_pinned(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        realm: &str,
        request: &[u8],
    ) -> Result<(Vec<u8>, Option<TcpStream>), Error> {
        if protocol == KdcProtocol::Auto {
            return self
                .send_to_realm_auto(config, realm, request)
                .await
                .map(|response| (response, None));
        }
        let endpoints = self.discover_kdcs(config, realm, protocol).await?;
        self.send_to_endpoints_pinned(realm, protocol, endpoints, request)
            .await
    }

    /// Send to password endpoints with RFC 3244 framing.
    ///
    /// # Errors
    /// Returns endpoint failures when no exchange succeeds.
    ///
    /// # Cancel safety
    /// NOT cancel-safe: a delivered password request may already have committed.
    async fn send_to_password_endpoints(
        &self,
        realm: &str,
        protocol: KdcProtocol,
        endpoints: Vec<KdcEndpoint>,
        request: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut failures = Vec::new();
        for endpoint in endpoints {
            let result = self
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

    /// Send one password mutation, marking the outcome unknown before possible delivery.
    ///
    /// # Errors
    /// Returns preparation errors before a send, or `KpasswdOutcomeUnknown` afterward.
    ///
    /// # Cancel safety
    /// NOT cancel-safe: a cancelled send or reply wait may already have committed.
    async fn send_password_once<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        request: &[u8],
    ) -> Result<Vec<u8>, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        match protocol {
            KdcProtocol::Tcp => {
                let _length = tcp_request_length(request.len(), TcpFraming::Kpasswd)?;
                let mut stream = self.with_transport_timeout(Self::connect_tcp(addr)).await?;
                self.with_transport_timeout(self.exchange_tcp_framed(
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
                let socket = self
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
                self.with_transport_timeout(async {
                    let _: usize = socket.send(request).await?;
                    let mut response = vec![
                        0;
                        self.udp_response_limit
                            .min(usize::from(u16::MAX))
                            .saturating_add(1)
                    ];
                    let length = socket.recv(&mut response).await?;
                    if length > self.udp_response_limit {
                        return Err(Error::UdpResponseTooLarge {
                            limit: self.udp_response_limit,
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

    /// Send to configured KDC endpoints using KDC framing.
    ///
    /// # Errors
    /// Returns discovery errors or failures from all endpoints.
    ///
    /// # Cancel safety
    /// cancel-safe: no client state is changed and sockets close on cancellation.
    async fn send_to_realm_explicit(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        realm: &str,
        request: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let endpoints = self.discover_kdcs(config, realm, protocol).await?;
        self.send_to_endpoints(realm, protocol, endpoints, request)
            .await
    }

    /// Send an encoded kpasswd request to the first reachable configured server.
    ///
    /// # Errors
    ///
    /// Returns the discovery errors of [`Self::discover_kpasswd_servers`],
    /// [`Error::NoKdcEndpoints`] when no endpoint is available, and
    /// [`Error::KdcEndpointFailures`] when every endpoint fails.
    /// Failover is permitted only before possible delivery. Later failures return
    /// [`Error::KpasswdOutcomeUnknown`] without resending the mutation.
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe: this mutates credentials on the KDC. Dropping the future
    /// after the kpasswd request is sent does not roll the server back, so the
    /// password may or may not have changed; treat the outcome as unknown and
    /// verify it (for example with a fresh login) before retrying.
    #[inline]
    pub async fn send_to_kpasswd_realm(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        realm: &str,
        request: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if protocol == KdcProtocol::Auto {
            return self
                .send_to_kpasswd_realm_auto(config, realm, request)
                .await;
        }
        self.send_to_kpasswd_realm_explicit(config, protocol, realm, request)
            .await
    }

    /// Send an encoded kpasswd request over one explicit protocol to the first
    /// reachable configured server.
    ///
    /// # Errors
    ///
    /// Returns the discovery errors of [`Self::discover_kpasswd_servers`],
    /// [`Error::NoKdcEndpoints`] when no endpoint is available, and
    /// [`Error::KdcEndpointFailures`] when every endpoint fails.
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe: this mutates credentials on the KDC. Dropping the future
    /// after the kpasswd request is sent does not roll the server back, so the
    /// password may or may not have changed; treat the outcome as unknown and
    /// verify it (for example with a fresh login) before retrying.
    async fn send_to_kpasswd_realm_explicit(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        realm: &str,
        request: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let endpoints = self
            .discover_kpasswd_servers(config, realm, protocol)
            .await?;
        self.send_to_password_endpoints(realm, protocol, endpoints, request)
            .await
    }

    /// Send a framed kpasswd request through Tokio transport and parse the reply.
    ///
    /// # Errors
    ///
    /// Returns an error when the request cannot be encoded, the errors of
    /// the password transport, and [`Error::KpasswdOutcomeUnknown`] wrapping
    /// [`Error::Kadmin`] when a delivered request receives a malformed reply.
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe: this mutates credentials on the KDC. Dropping the future
    /// after the kpasswd request is sent does not roll the server back, so the
    /// password may or may not have changed; treat the outcome as unknown and
    /// verify it (for example with a fresh login) before retrying.
    #[inline]
    pub async fn exchange_kpasswd_request<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        request: &kadmin::Request,
    ) -> Result<kadmin::Reply, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        let frame = request.encode()?;
        let response = self.send_password_once(protocol, addr, &frame).await?;
        kadmin::Reply::parse(&response)
            .map_err(|source| Error::KpasswdOutcomeUnknown(Box::new(Error::from(source))))
    }

    /// Send a framed kpasswd request to a configured kpasswd server and parse the reply.
    ///
    /// # Errors
    ///
    /// Returns an error when the request cannot be encoded, the errors of
    /// [`Self::send_to_kpasswd_realm`], and [`Error::KpasswdOutcomeUnknown`]
    /// wrapping [`Error::Kadmin`] when a delivered request receives a malformed reply.
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe: this mutates credentials on the KDC. Dropping the future
    /// after the kpasswd request is sent does not roll the server back, so the
    /// password may or may not have changed; treat the outcome as unknown and
    /// verify it (for example with a fresh login) before retrying.
    #[inline]
    pub async fn exchange_kpasswd_request_with_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        realm: &str,
        request: &kadmin::Request,
    ) -> Result<kadmin::Reply, Error> {
        let frame = request.encode()?;
        let response = self
            .send_to_kpasswd_realm(config, protocol, realm, &frame)
            .await?;
        kadmin::Reply::parse(&response)
            .map_err(|source| Error::KpasswdOutcomeUnknown(Box::new(Error::from(source))))
    }

    /// Send a framed kpasswd request and return a checked password-change result.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::exchange_kpasswd_request`], an error when
    /// the result cannot be decrypted with `reply_key`, and an error when the
    /// server reports a non-success result code.
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe: this mutates credentials on the KDC. Dropping the future
    /// after the kpasswd request is sent does not roll the server back, so the
    /// password may or may not have changed; treat the outcome as unknown and
    /// verify it (for example with a fresh login) before retrying.
    #[inline]
    pub async fn exchange_kpasswd_result<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        request: &kadmin::Request,
        reply_key: &EncryptionKey,
    ) -> Result<kadmin::ChangePasswordResult, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        let reply = self
            .exchange_kpasswd_request(protocol, addr, request)
            .await?;
        password_result::checked(&reply, reply_key)
    }

    /// Send a framed kpasswd request to a configured server and return a checked result.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::exchange_kpasswd_request_with_config`], an
    /// error when the result cannot be decrypted with `reply_key`, and an error
    /// when the server reports a non-success result code.
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe: this mutates credentials on the KDC. Dropping the future
    /// after the kpasswd request is sent does not roll the server back, so the
    /// password may or may not have changed; treat the outcome as unknown and
    /// verify it (for example with a fresh login) before retrying.
    #[inline]
    pub async fn exchange_kpasswd_result_with_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        realm: &str,
        request: &kadmin::Request,
        reply_key: &EncryptionKey,
    ) -> Result<kadmin::ChangePasswordResult, Error> {
        let reply = self
            .exchange_kpasswd_request_with_config(config, protocol, realm, request)
            .await?;
        password_result::checked(&reply, reply_key)
    }

    /// Send an AS-REQ through Tokio transport and process the returned AS-REP.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::send`], [`Error::Kdc`] when the KDC answers
    /// with a KRB-ERROR, and an error when the AS-REP cannot be decoded,
    /// decrypted with `reply_key` or matched to `request`.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn exchange_as_req<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        request: &BuiltAsReq,
        reply_key: &EncryptionKey,
    ) -> Result<AsRepSession, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        let response = self.send(protocol, addr, &request.der).await?;
        process_as_rep(request, &response, reply_key)
    }

    /// Send an AS-REQ through a config-discovered KDC and process the AS-REP.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::send_to_realm`], [`Error::Kdc`] when the KDC
    /// answers with a KRB-ERROR, an error when the AS-REP cannot be decoded,
    /// decrypted with `reply_key` or matched to `request`, and
    /// [`Error::EnctypeNotPermitted`] when an explicit `permitted_enctypes`
    /// excludes the session-key enctype.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn exchange_as_req_with_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        request: &BuiltAsReq,
        reply_key: &EncryptionKey,
    ) -> Result<AsRepSession, Error> {
        let response = self
            .send_to_realm(config, protocol, &request.client.realm, &request.der)
            .await?;
        let session = process_as_rep(request, &response, reply_key)?;
        if config.libdefaults.permitted_enctypes_explicit.is_enabled() {
            super::ensure_permitted_enctype(
                &config.libdefaults.permitted_enctype_ids(),
                session.session_key.etype,
            )?;
        }
        Ok(session)
    }

    /// Send a TGS-REQ through Tokio transport and process the returned TGS-REP.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::send`], [`Error::Kdc`] when the KDC answers
    /// with a KRB-ERROR, and an error when the TGS-REP cannot be decoded,
    /// decrypted with `tgs_session_key` or matched to `request`.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn exchange_tgs_req<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        request: &BuiltTgsReq,
        tgs_session_key: &EncryptionKey,
    ) -> Result<TgsRepSession, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        let response = self.send(protocol, addr, &request.der).await?;
        process_tgs_rep(request, &response, tgs_session_key)
    }

    /// Send a TGS-REQ through a config-discovered KDC and process the TGS-REP.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::send_to_realm`], [`Error::Kdc`] when the KDC
    /// answers with a KRB-ERROR, an error when the TGS-REP cannot be decoded,
    /// decrypted with `tgs_session_key` or matched to `request`, and
    /// [`Error::EnctypeNotPermitted`] when an explicit `permitted_enctypes`
    /// excludes the session-key enctype.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn exchange_tgs_req_with_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        request: &BuiltTgsReq,
        tgs_session_key: &EncryptionKey,
    ) -> Result<TgsRepSession, Error> {
        let response = self
            .send_to_realm(config, protocol, &request.kdc_realm, &request.der)
            .await?;
        let session = process_tgs_rep(request, &response, tgs_session_key)?;
        if config.libdefaults.permitted_enctypes_explicit.is_enabled() {
            super::ensure_permitted_enctype(
                &config.libdefaults.permitted_enctype_ids(),
                session.session_key.etype,
            )?;
        }
        Ok(session)
    }

    /// Perform `S4U2Self` through an explicit KDC endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error when the `S4U2Self` TGS-REQ cannot be built from the
    /// given tickets and options, and the errors of [`Self::exchange_tgs_req`].
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn s4u2self<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        service_tgt: &AsRepSession,
        user: Principal,
        options: TgsReq,
    ) -> Result<TgsRepSession, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        let request = build_s4u2self_req(service_tgt, user, options)?;
        self.exchange_tgs_req(protocol, addr, &request, &service_tgt.session_key)
            .await
    }

    /// Perform `S4U2Self` through a config-discovered KDC.
    ///
    /// # Errors
    ///
    /// Returns an error when the `S4U2Self` TGS-REQ cannot be built from the
    /// given tickets and options, and the errors of [`Self::exchange_tgs_req_with_config`].
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn s4u2self_with_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        service_tgt: &AsRepSession,
        user: Principal,
        options: TgsReq,
    ) -> Result<TgsRepSession, Error> {
        let request = build_s4u2self_req(service_tgt, user, options)?;
        self.exchange_tgs_req_with_config(config, protocol, &request, &service_tgt.session_key)
            .await
    }

    /// Perform `S4U2Proxy` through an explicit KDC endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error when the `S4U2Proxy` TGS-REQ cannot be built from the
    /// given tickets and options, and the errors of [`Self::exchange_tgs_req`].
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn s4u2proxy<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        service_tgt: &AsRepSession,
        evidence_ticket: &TgsRepSession,
        target_service: Principal,
        options: TgsReq,
    ) -> Result<TgsRepSession, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        let request = build_s4u2proxy_req(service_tgt, evidence_ticket, target_service, options)?;
        self.exchange_tgs_req(protocol, addr, &request, &service_tgt.session_key)
            .await
    }

    /// Perform `S4U2Proxy` through a config-discovered KDC.
    ///
    /// # Errors
    ///
    /// Returns an error when the `S4U2Proxy` TGS-REQ cannot be built from the
    /// given tickets and options, and the errors of [`Self::exchange_tgs_req_with_config`].
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn s4u2proxy_with_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        service_tgt: &AsRepSession,
        evidence_ticket: &TgsRepSession,
        target_service: Principal,
        options: TgsReq,
    ) -> Result<TgsRepSession, Error> {
        let request = build_s4u2proxy_req(service_tgt, evidence_ticket, target_service, options)?;
        self.exchange_tgs_req_with_config(config, protocol, &request, &service_tgt.session_key)
            .await
    }

    /// Renew an existing TGT through an explicit KDC endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error when the renewal TGS-REQ cannot be built from the
    /// given tickets and options, and the errors of [`Self::exchange_tgs_req`].
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn renew_tgt<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        tgt: &AsRepSession,
        options: TgsReq,
    ) -> Result<TgsRepSession, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        let request = build_tgt_renewal_req(tgt, options)?;
        self.exchange_tgs_req(protocol, addr, &request, &tgt.session_key)
            .await
    }

    /// Renew an existing TGT through a config-discovered KDC.
    ///
    /// # Errors
    ///
    /// Returns an error when the renewal TGS-REQ cannot be built from the
    /// given tickets and options, and the errors of [`Self::exchange_tgs_req_with_config`].
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn renew_tgt_with_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        tgt: &AsRepSession,
        options: TgsReq,
    ) -> Result<TgsRepSession, Error> {
        let request = build_tgt_renewal_req(tgt, options)?;
        self.exchange_tgs_req_with_config(config, protocol, &request, &tgt.session_key)
            .await
    }

    /// Renew an existing service ticket through an explicit KDC endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error when the renewal TGS-REQ cannot be built from the
    /// given tickets and options, and the errors of [`Self::exchange_tgs_req`].
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn renew_ticket<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        ticket: &AsRepSession,
        options: TgsReq,
    ) -> Result<TgsRepSession, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        let request = build_ticket_renewal_req(ticket, options)?;
        self.exchange_tgs_req(protocol, addr, &request, &ticket.session_key)
            .await
    }

    /// Renew an existing service ticket through a config-discovered KDC.
    ///
    /// # Errors
    ///
    /// Returns an error when the renewal TGS-REQ cannot be built from the
    /// given tickets and options, and the errors of [`Self::exchange_tgs_req_with_config`].
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn renew_ticket_with_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        ticket: &AsRepSession,
        options: TgsReq,
    ) -> Result<TgsRepSession, Error> {
        let request = build_ticket_renewal_req(ticket, options)?;
        self.exchange_tgs_req_with_config(config, protocol, &request, &ticket.session_key)
            .await
    }

    /// Acquire a service ticket, following cross-realm TGS referrals.
    ///
    /// The supplied `tgt` is used as the starting TGT. If the service belongs
    /// to a different realm, this first obtains referral TGTs until it can ask
    /// the target realm for the final service ticket.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidReferralTicket`] when `tgt` or a returned
    /// referral is not a usable cross-realm TGT, [`Error::ServicePrincipalMismatch`]
    /// when the KDC returns neither the requested ticket nor a referral,
    /// [`Error::MaxReferralDepth`] when more referrals are needed than allowed, and
    /// the errors of building each TGS-REQ, of [`Self::send_to_realm`] and of
    /// processing each TGS-REP.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn get_service_ticket_with_referrals(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        tgt: &AsRepSession,
        service: Principal,
        options: TgsReq,
    ) -> Result<TgsRepSession, Error> {
        Ok(self
            .get_service_ticket_with_referral_trace(config, protocol, tgt, service, options)
            .await?
            .ticket)
    }

    /// Acquire a service ticket and return intermediate referral TGTs.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidReferralTicket`] when `tgt` or a returned
    /// referral is not a usable cross-realm TGT, [`Error::ServicePrincipalMismatch`]
    /// when the KDC returns neither the requested ticket nor a referral,
    /// [`Error::MaxReferralDepth`] when more referrals are needed than allowed, and
    /// the errors of building each TGS-REQ, of [`Self::send_to_realm`] and of
    /// processing each TGS-REP.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn get_service_ticket_with_referral_trace(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        tgt: &AsRepSession,
        service: Principal,
        options: TgsReq,
    ) -> Result<ReferralTgsResult, Error> {
        self.get_service_ticket_with_referral_trace_limit(
            config,
            protocol,
            tgt,
            service,
            options,
            DEFAULT_MAX_REFERRALS,
        )
        .await
    }

    /// Acquire a service ticket with an explicit referral limit.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidReferralTicket`] when `tgt` or a returned
    /// referral is not a usable cross-realm TGT, [`Error::ServicePrincipalMismatch`]
    /// when the KDC returns neither the requested ticket nor a referral,
    /// [`Error::MaxReferralDepth`] when more referrals are needed than allowed, and
    /// the errors of building each TGS-REQ, of [`Self::send_to_realm`] and of
    /// processing each TGS-REP.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn get_service_ticket_with_referrals_limit(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        tgt: &AsRepSession,
        service: Principal,
        options: TgsReq,
        max_referrals: usize,
    ) -> Result<TgsRepSession, Error> {
        Ok(self
            .get_service_ticket_with_referral_trace_limit(
                config,
                protocol,
                tgt,
                service,
                options,
                max_referrals,
            )
            .await?
            .ticket)
    }

    /// Acquire a service ticket with an explicit referral limit, returning the referral trace.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidReferralTicket`] when `tgt` or a returned
    /// referral is not a usable cross-realm TGT, [`Error::ServicePrincipalMismatch`]
    /// when the KDC returns neither the requested ticket nor a referral,
    /// [`Error::MaxReferralDepth`] when more referrals are needed than allowed, and
    /// the errors of building each TGS-REQ, of [`Self::send_to_realm`] and of
    /// processing each TGS-REP.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn get_service_ticket_with_referral_trace_limit(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        tgt: &AsRepSession,
        mut service: Principal,
        options: TgsReq,
        max_referrals: usize,
    ) -> Result<ReferralTgsResult, Error> {
        let mut current_tgt = tgt.clone();
        let mut current_realm =
            tgt_realm(&current_tgt).ok_or_else(|| Error::InvalidReferralTicket {
                service: current_tgt.service.name(),
            })?;
        if service.realm.is_empty() {
            service.realm =
                service_realm(config, &service).unwrap_or_else(|| current_realm.clone());
        }
        let target_realm = service.realm.clone();
        let mut referral_tgts = Vec::new();

        for referrals in 0..=max_referrals {
            let requested_service = if current_realm == target_realm {
                service.clone()
            } else {
                Principal::new(
                    current_realm.clone(),
                    KRB_NT_SRV_INST,
                    ["krbtgt".to_owned(), target_realm.clone()],
                )
            };
            let request = build_tgs_req_for_realm(
                &current_tgt,
                current_realm.clone(),
                requested_service,
                options.clone(),
            )?;
            let response = self
                .send_to_realm(config, protocol, &request.kdc_realm, &request.der)
                .await?;
            let ticket =
                process_tgs_rep_with_referral(&request, &response, &current_tgt.session_key)?;

            if principal_matches(&ticket.service, &service) {
                return Ok(ReferralTgsResult {
                    ticket,
                    referral_tgts,
                });
            }

            let referred_realm =
                tgt_realm(&ticket).ok_or_else(|| Error::ServicePrincipalMismatch {
                    expected: service.name(),
                    actual: ticket.service.name(),
                })?;
            if referred_realm == current_realm {
                return Err(Error::InvalidReferralTicket {
                    service: ticket.service.name(),
                });
            }

            current_realm = referred_realm;
            referral_tgts.push(ticket.clone());
            current_tgt = ticket;

            if referrals == max_referrals {
                return Err(Error::MaxReferralDepth { max: max_referrals });
            }
        }

        Err(Error::MaxReferralDepth { max: max_referrals })
    }

    /// Perform a TGT AS login using password credentials and KDC preauth hints.
    ///
    /// # Errors
    ///
    /// Returns an error when the AS-REQ cannot be built from the password, the
    /// errors of [`Self::send`], [`Error::Kdc`] when the KDC rejects the login,
    /// and an error when the AS-REP cannot be decrypted with the password-derived
    /// key or matched to the request.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn login_tgt_with_password<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        client: Principal,
        password: &[u8],
        options: AsReq,
    ) -> Result<AsRepSession, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        let service = Principal::tgt_service(client.realm.clone());
        self.login_as_service_with_password(protocol, addr, client, service, password, options)
            .await
    }

    /// Perform an AS login for an explicit service using password credentials and KDC preauth hints.
    ///
    /// # Errors
    ///
    /// Returns an error when the AS-REQ cannot be built from the password, the
    /// errors of [`Self::send`], [`Error::Kdc`] when the KDC rejects the login,
    /// and an error when the AS-REP cannot be decrypted with the password-derived
    /// key or matched to the request.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn login_as_service_with_password<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        client: Principal,
        service: Principal,
        password: &[u8],
        options: AsReq,
    ) -> Result<AsRepSession, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        let initial_request =
            password_initial_as_req(client.clone(), service.clone(), password, options.clone())?;
        let (initial_response, mut pinned) = self
            .send_pinned(protocol, addr.clone(), &initial_request.der)
            .await?;
        if let Some(session) =
            password_initial_as_rep_session(&initial_request, &initial_response, &client, password)?
        {
            return Ok(session);
        }
        let (request, reply_key) =
            password_preauth_request(client, service, password, options, &initial_response)?;
        let response = match self.send_follow_up(pinned.as_mut(), &request.der).await? {
            Some(response) => response,
            None => self.send(protocol, addr, &request.der).await?,
        };
        process_as_rep(&request, &response, &reply_key)
    }

    /// Perform a password TGT AS login using KDCs discovered from `krb5.conf`.
    ///
    /// # Errors
    ///
    /// Returns an error when the AS-REQ cannot be built from the password, the
    /// errors of [`Self::send_to_realm`], [`Error::Kdc`] when the KDC rejects the login,
    /// and an error when the AS-REP cannot be decrypted with the password-derived
    /// key or matched to the request.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn login_tgt_with_password_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        client: Principal,
        password: &[u8],
        options: AsReq,
    ) -> Result<AsRepSession, Error> {
        let service = Principal::tgt_service(client.realm.clone());
        self.login_as_service_with_password_config(
            config, protocol, client, service, password, options,
        )
        .await
    }

    /// Perform a password AS login for an explicit service using KDCs discovered from `krb5.conf`.
    ///
    /// # Errors
    ///
    /// Returns an error when the AS-REQ cannot be built from the password, the
    /// errors of [`Self::send_to_realm`], [`Error::Kdc`] when the KDC rejects the login,
    /// and an error when the AS-REP cannot be decrypted with the password-derived
    /// key or matched to the request.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn login_as_service_with_password_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        client: Principal,
        service: Principal,
        password: &[u8],
        options: AsReq,
    ) -> Result<AsRepSession, Error> {
        let initial_request =
            password_initial_as_req(client.clone(), service.clone(), password, options.clone())?;
        let (initial_response, mut pinned) = self
            .send_to_realm_pinned(config, protocol, &client.realm, &initial_request.der)
            .await?;
        if let Some(session) =
            password_initial_as_rep_session(&initial_request, &initial_response, &client, password)?
        {
            return Ok(session);
        }
        let (request, reply_key) =
            password_preauth_request(client, service, password, options, &initial_response)?;
        let response = match self.send_follow_up(pinned.as_mut(), &request.der).await? {
            Some(response) => response,
            None => {
                self.send_to_realm(config, protocol, &request.client.realm, &request.der)
                    .await?
            }
        };
        process_as_rep(&request, &response, &reply_key)
    }

    /// Perform a TGT AS login using keytab credentials and KDC preauth hints.
    ///
    /// # Errors
    ///
    /// Returns an error when the AS-REQ cannot be built from the keytab, the
    /// errors of [`Self::send`], [`Error::Kdc`] when the KDC rejects the login,
    /// and an error when the AS-REP cannot be decrypted with the keytab-derived
    /// key or matched to the request.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn login_tgt_with_keytab<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        client: Principal,
        keytab: &Keytab,
        options: AsReq,
    ) -> Result<AsRepSession, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        let service = Principal::tgt_service(client.realm.clone());
        self.login_as_service_with_keytab(protocol, addr, client, service, keytab, options)
            .await
    }

    /// Perform an AS login for an explicit service using keytab credentials and KDC preauth hints.
    ///
    /// # Errors
    ///
    /// Returns an error when the AS-REQ cannot be built from the keytab, the
    /// errors of [`Self::send`], [`Error::Kdc`] when the KDC rejects the login,
    /// and an error when the AS-REP cannot be decrypted with the keytab-derived
    /// key or matched to the request.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn login_as_service_with_keytab<A>(
        &self,
        protocol: KdcProtocol,
        addr: A,
        client: Principal,
        service: Principal,
        keytab: &Keytab,
        options: AsReq,
    ) -> Result<AsRepSession, Error>
    where
        A: ToSocketAddrs + Clone,
    {
        let initial_request =
            keytab_initial_as_req(client.clone(), service.clone(), keytab, options.clone())?;
        let (initial_response, mut pinned) = self
            .send_pinned(protocol, addr.clone(), &initial_request.der)
            .await?;
        if let Some(session) =
            keytab_initial_as_rep_session(&initial_request, &initial_response, &client, keytab)?
        {
            return Ok(session);
        }
        let (request, reply_key) =
            keytab_preauth_request(client, service, keytab, options, &initial_response)?;
        let response = match self.send_follow_up(pinned.as_mut(), &request.der).await? {
            Some(response) => response,
            None => self.send(protocol, addr, &request.der).await?,
        };
        process_as_rep(&request, &response, &reply_key)
    }

    /// Perform a keytab TGT AS login using KDCs discovered from `krb5.conf`.
    ///
    /// # Errors
    ///
    /// Returns an error when the AS-REQ cannot be built from the keytab, the
    /// errors of [`Self::send_to_realm`], [`Error::Kdc`] when the KDC rejects the login,
    /// and an error when the AS-REP cannot be decrypted with the keytab-derived
    /// key or matched to the request.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn login_tgt_with_keytab_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        client: Principal,
        keytab: &Keytab,
        options: AsReq,
    ) -> Result<AsRepSession, Error> {
        let service = Principal::tgt_service(client.realm.clone());
        self.login_as_service_with_keytab_config(config, protocol, client, service, keytab, options)
            .await
    }

    /// Perform a keytab AS login for an explicit service using KDCs discovered from `krb5.conf`.
    ///
    /// # Errors
    ///
    /// Returns an error when the AS-REQ cannot be built from the keytab, the
    /// errors of [`Self::send_to_realm`], [`Error::Kdc`] when the KDC rejects the login,
    /// and an error when the AS-REP cannot be decrypted with the keytab-derived
    /// key or matched to the request.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future abandons the exchange and closes its sockets; a KDC that already
    /// answered keeps no state the caller depends on, so the exchange can be
    /// repeated.
    #[inline]
    pub async fn login_as_service_with_keytab_config(
        &self,
        config: &Config,
        protocol: KdcProtocol,
        client: Principal,
        service: Principal,
        keytab: &Keytab,
        options: AsReq,
    ) -> Result<AsRepSession, Error> {
        let initial_request =
            keytab_initial_as_req(client.clone(), service.clone(), keytab, options.clone())?;
        let (initial_response, mut pinned) = self
            .send_to_realm_pinned(config, protocol, &client.realm, &initial_request.der)
            .await?;
        if let Some(session) =
            keytab_initial_as_rep_session(&initial_request, &initial_response, &client, keytab)?
        {
            return Ok(session);
        }
        let (request, reply_key) =
            keytab_preauth_request(client, service, keytab, options, &initial_response)?;
        let response = match self.send_follow_up(pinned.as_mut(), &request.der).await? {
            Some(response) => response,
            None => {
                self.send_to_realm(config, protocol, &request.client.realm, &request.der)
                    .await?
            }
        };
        process_as_rep(&request, &response, &reply_key)
    }

    /// Discover KDC endpoints through `_kerberos` DNS SRV records.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DnsResolverConfig`] or [`Error::DnsSrvLookup`] when the
    /// lookup fails, and [`Error::NoKdcEndpoints`] when it finds no KDC.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: DNS lookups change no state. Dropping the future abandons
    /// the lookup, which the caller can repeat.
    async fn discover_kdcs_with_dns(
        &self,
        realm: &str,
        protocol: KdcProtocol,
    ) -> Result<Vec<KdcEndpoint>, Error> {
        let endpoints = self
            .discover_srv_endpoints("_kerberos", realm, protocol)
            .await?;
        if endpoints.is_empty() {
            Err(Error::NoKdcEndpoints {
                realm: realm.to_owned(),
                protocol,
            })
        } else {
            Ok(endpoints)
        }
    }

    /// Discover kpasswd endpoints through `_kpasswd` DNS SRV records, falling
    /// back to `_kerberos-adm` when that lookup fails or finds nothing.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DnsResolverConfig`] or [`Error::DnsSrvLookup`] when the
    /// `_kerberos-adm` fallback lookup fails, and [`Error::NoKdcEndpoints`] when
    /// it finds no server.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: DNS lookups change no state. Dropping the future abandons
    /// the lookup, which the caller can repeat.
    async fn discover_kpasswd_servers_with_dns(
        &self,
        realm: &str,
        protocol: KdcProtocol,
    ) -> Result<Vec<KdcEndpoint>, Error> {
        match self
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

        let mut endpoints = self
            .discover_srv_endpoints("_kerberos-adm", realm, protocol)
            .await?;
        for endpoint in &mut endpoints {
            endpoint.port = 464;
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

    /// Look up the `<service>._udp` or `._tcp` SRV records of `realm` and order
    /// them by priority, then weighted selection without replacement.
    ///
    /// With an explicit DNS server set, each target is also resolved
    /// to an IP address through the same resolver.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DnsResolverConfig`] when the resolver or the
    /// DNS server option is invalid, and [`Error::DnsSrvLookup`] when
    /// the SRV lookup or the resolution of a target fails.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: DNS lookups change no state. Dropping the future abandons
    /// the lookup, which the caller can repeat.
    async fn discover_srv_endpoints(
        &self,
        service: &str,
        realm: &str,
        protocol: KdcProtocol,
    ) -> Result<Vec<KdcEndpoint>, Error> {
        let transport = match protocol {
            KdcProtocol::Udp | KdcProtocol::Auto => "_udp",
            KdcProtocol::Tcp => "_tcp",
        };
        let query = format!("{service}.{transport}.{realm}.");
        let resolver = dns_resolver(self.dns_server)?;
        let lookup = resolver
            .srv_lookup(query.as_str())
            .await
            .map_err(|source| Error::DnsSrvLookup {
                realm: realm.to_owned(),
                protocol,
                message: source.to_string(),
            })?;

        if lookup
            .answers()
            .iter()
            .any(|record| matches!(&record.data, RData::SRV(srv) if srv.target.is_root()))
        {
            return Err(Error::DnsServiceUnavailable {
                service: service.to_owned(),
                realm: realm.to_owned(),
            });
        }
        let mut records = lookup
            .answers()
            .iter()
            .filter_map(|record| {
                if let RData::SRV(srv) = &record.data {
                    Some(srv)
                } else {
                    None
                }
            })
            .map(|srv| {
                (
                    srv.priority,
                    srv.weight,
                    srv.target.to_utf8().trim_end_matches('.').to_owned(),
                    srv.port,
                )
            })
            .filter(|(_, _, target, _)| !target.is_empty() && target != ".")
            .collect::<Vec<_>>();
        order_srv_records(&mut records, srv_draw)?;

        let resolve_targets = self.dns_server.is_some();
        let mut endpoints = Vec::with_capacity(records.len());
        for (_, _, target, port) in records {
            let hosts = if resolve_targets {
                resolve_dns_endpoint_host(&resolver, realm, protocol, &target).await?
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

        Ok(endpoints)
    }

    /// Try each endpoint in turn and return the first response.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoKdcEndpoints`] when `endpoints` is empty, and
    /// [`Error::KdcEndpointFailures`] when every endpoint fails.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future closes any socket it opened and abandons the request, which the
    /// caller can send again.
    async fn send_to_endpoints(
        &self,
        realm: &str,
        protocol: KdcProtocol,
        endpoints: Vec<KdcEndpoint>,
        request: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.send_to_endpoints_pinned(realm, protocol, endpoints, request)
            .await
            .map(|(response, _)| response)
    }

    /// Try each endpoint in turn, keeping the winning TCP stream open.
    ///
    /// Failover still triggers on a failed exchange rather than on a failed
    /// connect, so the endpoint that answers is the one that gets pinned.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoKdcEndpoints`] when `endpoints` is empty, and
    /// [`Error::KdcEndpointFailures`] when every endpoint fails.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future closes any socket it opened and abandons the request, which the
    /// caller can send again.
    async fn send_to_endpoints_pinned(
        &self,
        realm: &str,
        protocol: KdcProtocol,
        endpoints: Vec<KdcEndpoint>,
        request: &[u8],
    ) -> Result<(Vec<u8>, Option<TcpStream>), Error> {
        if endpoints.is_empty() {
            return Err(Error::NoKdcEndpoints {
                realm: realm.to_owned(),
                protocol,
            });
        }

        let mut failures = Vec::new();
        for endpoint in endpoints {
            match self
                .send_pinned(
                    endpoint.protocol,
                    (endpoint.host.as_str(), endpoint.port),
                    request,
                )
                .await
            {
                Ok(outcome) => return Ok(outcome),
                Err(error) => failures.push(format!("{}: {error}", endpoint.authority())),
            }
        }

        Err(Error::KdcEndpointFailures {
            realm: realm.to_owned(),
            protocol,
            failures,
        })
    }

    /// Send to a realm's KDCs over the protocol `udp_preference_limit` selects,
    /// retrying over the other one after a failure or, from UDP, after
    /// `KRB_ERR_RESPONSE_TOO_BIG`.
    ///
    /// # Errors
    ///
    /// Returns the errors of the retry over the second protocol, those of
    /// [`Self::send_to_realm_explicit`].
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: it takes `&self` and changes no client state. Dropping the
    /// future closes any socket it opened and abandons the request, which the
    /// caller can send again.
    async fn send_to_realm_auto(
        &self,
        config: &Config,
        realm: &str,
        request: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let udp_first = auto_uses_udp_first(config, request.len());
        let (first, second) = if udp_first {
            (KdcProtocol::Udp, KdcProtocol::Tcp)
        } else {
            (KdcProtocol::Tcp, KdcProtocol::Udp)
        };

        match self
            .send_to_realm_explicit(config, first, realm, request)
            .await
        {
            Ok(response)
                if first == KdcProtocol::Udp
                    && kdc_error_code(&response) == Some(KRB_ERR_RESPONSE_TOO_BIG) =>
            {
                self.send_to_realm_explicit(config, second, realm, request)
                    .await
            }
            Ok(response) => Ok(response),
            Err(_) => {
                self.send_to_realm_explicit(config, second, realm, request)
                    .await
            }
        }
    }

    /// Send to a realm's kpasswd servers over the protocol
    /// `udp_preference_limit` selects, retrying only before possible delivery.
    ///
    /// # Errors
    ///
    /// Returns the errors of the retry over the second protocol, those of
    /// [`Self::send_to_kpasswd_realm_explicit`].
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe: this mutates credentials on the KDC. Dropping the future
    /// after the kpasswd request is sent does not roll the server back, so the
    /// password may or may not have changed; treat the outcome as unknown and
    /// verify it (for example with a fresh login) before retrying.
    async fn send_to_kpasswd_realm_auto(
        &self,
        config: &Config,
        realm: &str,
        request: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let udp_first = auto_uses_udp_first(config, request.len());
        let (first, second) = if udp_first {
            (KdcProtocol::Udp, KdcProtocol::Tcp)
        } else {
            (KdcProtocol::Tcp, KdcProtocol::Udp)
        };

        match self
            .send_to_kpasswd_realm_explicit(config, first, realm, request)
            .await
        {
            Ok(response) => Ok(response),
            Err(error @ Error::KpasswdOutcomeUnknown(_)) => Err(error),
            Err(_) => {
                self.send_to_kpasswd_realm_explicit(config, second, realm, request)
                    .await
            }
        }
    }

    /// Run `operation` under the transport timeout.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TransportTimeout`] when `operation` does not finish within
    /// the timeout, and otherwise the error of `operation`.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe exactly when `operation` is: dropping the future drops
    /// `operation` and the timer and changes no state of its own.
    async fn with_transport_timeout<F, T>(&self, operation: F) -> Result<T, Error>
    where
        F: Future<Output = Result<T, Error>>,
    {
        match timeout(self.timeout, operation).await {
            Ok(result) => result,
            Err(_elapsed) => Err(Error::TransportTimeout(self.timeout)),
        }
    }
}

/// Select without replacement within ascending priorities using RFC 2782 draws.
///
/// # Errors
/// Returns the draw error or a transport error for an invalid draw.
fn order_srv_records<F>(records: &mut [(u16, u16, String, u16)], mut draw: F) -> Result<(), Error>
where
    F: FnMut(u64) -> Result<u64, Error>,
{
    records.sort_by_key(|record| record.0);
    for offset in 0..records.len() {
        let remaining = records
            .get_mut(offset..)
            .ok_or_else(|| Error::Transport("SRV selection offset".to_owned()))?;
        let Some(first) = remaining.first() else {
            break;
        };
        let priority = first.0;
        let count = remaining
            .iter()
            .take_while(|record| record.0 == priority)
            .count();
        let group = remaining
            .get_mut(..count)
            .ok_or_else(|| Error::Transport("SRV priority group".to_owned()))?;
        group.sort_by_key(|record| record.1 != 0);
        let total = group.iter().map(|record| u64::from(record.1)).sum::<u64>();
        let selected = if total == 0 {
            usize::try_from(draw(
                u64::try_from(count.saturating_sub(1))
                    .map_err(|error| Error::Transport(error.to_string()))?,
            )?)
            .map_err(|error| Error::Transport(error.to_string()))?
        } else {
            let ticket = draw(total)?;
            let mut cumulative = 0_u64;
            group
                .iter()
                .position(|record| {
                    cumulative = cumulative.saturating_add(u64::from(record.1));
                    cumulative >= ticket
                })
                .ok_or_else(|| Error::Transport("SRV draw outside weight range".to_owned()))?
        };
        group
            .get_mut(..=selected)
            .ok_or_else(|| Error::Transport("SRV draw outside group".to_owned()))?
            .rotate_right(1);
    }
    Ok(())
}

/// Draw uniformly from the inclusive range, rejecting the biased remainder.
///
/// # Errors
/// Returns a transport error if entropy acquisition or range construction fails.
fn srv_draw(maximum: u64) -> Result<u64, Error> {
    let range = maximum
        .checked_add(1)
        .ok_or_else(|| Error::Transport("SRV weight overflow".to_owned()))?;
    let threshold = range
        .wrapping_neg()
        .checked_rem(range)
        .ok_or_else(|| Error::Transport("empty SRV range".to_owned()))?;
    loop {
        let value = getrandom::u64()?;
        if value >= threshold {
            return value
                .checked_rem(range)
                .ok_or_else(|| Error::Transport("empty SRV range".to_owned()));
        }
    }
}

/// Reject an empty KDC reply.
///
/// # Errors
///
/// Returns [`Error::EmptyKdcResponse`] when `response` is empty.
#[cfg(feature = "tokio")]
fn non_empty_kdc_response(response: Vec<u8>) -> Result<Vec<u8>, Error> {
    if response.is_empty() {
        return Err(Error::EmptyKdcResponse);
    }
    Ok(response)
}

/// Split a `host[:port]` or `[ipv6][:port]` KDC entry into host and port.
///
/// # Errors
///
/// Returns [`Error::InvalidKdcEndpoint`] when `value` is empty, has an
/// unterminated or empty `[...]` IPv6 host, has a port that is not a `u16`, or
/// has a single `:` without a valid port.
#[cfg(feature = "tokio")]
fn parse_kdc_endpoint(value: &str, default_port: u16) -> Result<(String, u16), Error> {
    let endpoint = value.trim();
    if endpoint.is_empty() {
        return Err(Error::InvalidKdcEndpoint(endpoint.to_owned()));
    }

    if endpoint.parse::<IpAddr>().is_ok() {
        return Ok((endpoint.to_owned(), default_port));
    }

    if let Some(rest) = endpoint.strip_prefix('[') {
        let Some((host, suffix)) = rest.split_once(']') else {
            return Err(Error::InvalidKdcEndpoint(endpoint.to_owned()));
        };
        if host.is_empty() {
            return Err(Error::InvalidKdcEndpoint(endpoint.to_owned()));
        }
        let port = if let Some(port) = suffix.strip_prefix(':') {
            parse_kdc_port(endpoint, port)?
        } else if suffix.is_empty() {
            default_port
        } else {
            return Err(Error::InvalidKdcEndpoint(endpoint.to_owned()));
        };
        return Ok((host.to_owned(), port));
    }

    if let Some((host, port)) = endpoint.rsplit_once(':')
        && !host.is_empty()
        && !port.is_empty()
        && port.chars().all(|ch| ch.is_ascii_digit())
        && !host.ends_with(':')
    {
        return Ok((host.to_owned(), parse_kdc_port(endpoint, port)?));
    }

    if endpoint.matches(':').count() == 1 {
        return Err(Error::InvalidKdcEndpoint(endpoint.to_owned()));
    }

    Ok((endpoint.to_owned(), default_port))
}

/// Parse a KDC port, quoting `endpoint` in the error.
///
/// # Errors
///
/// Returns [`Error::InvalidKdcEndpoint`] for `endpoint` when `port` is not a
/// `u16`.
#[cfg(feature = "tokio")]
fn parse_kdc_port(endpoint: &str, port: &str) -> Result<u16, Error> {
    port.parse::<u16>()
        .ok()
        .ok_or_else(|| Error::InvalidKdcEndpoint(endpoint.to_owned()))
}

/// Build the DNS resolver using the explicitly selected server, if any.
///
/// # Errors
///
/// Returns [`Error::DnsResolverConfig`] when the override is invalid or the
/// resolver cannot be built.
#[cfg(feature = "tokio")]
fn dns_resolver(server: Option<(IpAddr, u16)>) -> Result<TokioResolver, Error> {
    if let Some((ip, port)) = server {
        let mut udp = ConnectionConfig::udp();
        udp.port = port;
        let mut tcp = ConnectionConfig::tcp();
        tcp.port = port;

        let mut config = ResolverConfig::default();
        config.name_servers = vec![NameServerConfig::new(ip, true, vec![udp, tcp])];

        return TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
            .build()
            .map_err(|source| Error::DnsResolverConfig(source.to_string()));
    }

    TokioResolver::builder_tokio()
        .map_err(|source| Error::DnsResolverConfig(source.to_string()))?
        .build()
        .map_err(|source| Error::DnsResolverConfig(source.to_string()))
}

/// Resolve every address of an SRV target; IP literals pass through.
///
/// # Errors
///
/// Returns [`Error::DnsSrvLookup`] when the address lookup fails or finds no
/// address record.
///
/// # Cancel safety
///
/// cancel-safe: DNS lookups change no state. Dropping the future abandons
/// the lookup, which the caller can repeat.
#[cfg(feature = "tokio")]
async fn resolve_dns_endpoint_host(
    resolver: &TokioResolver,
    realm: &str,
    protocol: KdcProtocol,
    target: &str,
) -> Result<Vec<String>, Error> {
    if target.parse::<IpAddr>().is_ok() {
        return Ok(vec![target.to_owned()]);
    }

    let lookup_name = if target.ends_with('.') {
        target.to_owned()
    } else {
        format!("{target}.")
    };
    let lookup = resolver
        .lookup_ip(lookup_name.as_str())
        .await
        .map_err(|source| Error::DnsSrvLookup {
            realm: realm.to_owned(),
            protocol,
            message: format!("target {target}: {source}"),
        })?;
    let hosts: Vec<_> = lookup.iter().map(|ip| ip.to_string()).collect();
    if hosts.is_empty() {
        return Err(Error::DnsSrvLookup {
            realm: realm.to_owned(),
            protocol,
            message: format!("target {target}: no address records found"),
        });
    }
    Ok(hosts)
}

/// Parse an `ip` or `ip:port` DNS server literal, defaulting to port 53.
///
/// # Errors
///
/// Returns a description of the problem when `value` is blank or not an IP
/// literal.
#[cfg(feature = "tokio")]
fn parse_dns_server(value: &str) -> Result<(IpAddr, u16), String> {
    let server = value.trim();
    if server.is_empty() {
        return Err("empty DNS server override".to_owned());
    }

    if let Ok(addr) = server.parse::<SocketAddr>() {
        return Ok((addr.ip(), addr.port()));
    }

    if let Ok(ip) = server.parse::<IpAddr>() {
        return Ok((ip, 53));
    }

    Err(format!("expected IP literal or IP:port, got {server:?}"))
}

/// The KRB-ERROR code of `bytes`, if they decode as a KRB-ERROR.
#[cfg(feature = "tokio")]
fn kdc_error_code(bytes: &[u8]) -> Option<i32> {
    decode_krb_error(bytes).ok().map(|error| error.error_code)
}

/// Whether [`KdcProtocol::Auto`] tries UDP first for a request of
/// `request_len` bytes under `udp_preference_limit`.
#[cfg(feature = "tokio")]
fn auto_uses_udp_first(config: &Config, request_len: usize) -> bool {
    let limit = config.libdefaults.udp_preference_limit;
    limit != 1 && usize::try_from(limit).is_ok_and(|max| request_len <= max)
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::net::IpAddr;

    use super::parse_dns_server;

    /// Numeric framing boundaries are tested without allocating multi-gigabyte requests.
    #[test]
    fn tcp_lengths_are_service_specific() -> Result<(), super::Error> {
        assert_eq!(
            super::tcp_request_length(0x7FFF_FFFF, super::TcpFraming::Kdc)?,
            0x7FFF_FFFF
        );
        assert!(
            super::tcp_request_length(0x8000_0000, super::TcpFraming::Kdc)
                .err()
                .is_some()
        );
        assert_eq!(
            super::tcp_request_length(0x8000_0000, super::TcpFraming::Kpasswd)?,
            0x8000_0000
        );
        super::validate_tcp_length(u32::MAX, super::TcpFraming::Kpasswd)?;
        Ok(())
    }

    /// A zero draw selects zero-weight records before weighted peers at equal priority.
    #[test]
    fn srv_zero_draw_selects_zero_weight() -> Result<(), super::Error> {
        let mut records = vec![
            (1, 3, "heavy".to_owned(), 88),
            (1, 0, "zero".to_owned(), 88),
            (2, 8, "later".to_owned(), 88),
        ];
        super::order_srv_records(&mut records, |_| Ok(0))?;
        assert_eq!(
            records.first().map(|record| record.2.as_str()),
            Some("zero")
        );
        assert_eq!(
            records.last().map(|record| record.2.as_str()),
            Some("later")
        );
        Ok(())
    }

    /// Inclusive draws cover both weighted boundaries without replacing selected records.
    #[test]
    fn srv_weight_boundaries_select_each_peer() -> Result<(), super::Error> {
        for (ticket, expected) in [(0, "light"), (1, "light"), (2, "heavy"), (4, "heavy")] {
            let mut records = vec![
                (1, 1, "light".to_owned(), 88),
                (1, 3, "heavy".to_owned(), 88),
            ];
            let mut first = true;
            super::order_srv_records(&mut records, |_| {
                let value = if first { ticket } else { 0 };
                first = false;
                Ok(value)
            })?;
            assert_eq!(
                records.first().map(|record| record.2.as_str()),
                Some(expected)
            );
            assert_ne!(records.first(), records.last());
        }
        Ok(())
    }

    /// All-zero groups use the injected index draw rather than a fixed ordering.
    #[test]
    fn srv_all_zero_weights_use_uniform_index() -> Result<(), super::Error> {
        let mut records = vec![
            (1, 0, "first".to_owned(), 88),
            (1, 0, "second".to_owned(), 88),
        ];
        super::order_srv_records(&mut records, Ok)?;
        assert_eq!(
            records.first().map(|record| record.2.as_str()),
            Some("second")
        );
        Ok(())
    }

    /// A bare IP literal selects the standard DNS port 53.
    #[test]
    fn parses_dns_server_override_ip_and_default_port() -> Result<(), String> {
        assert_eq!(
            parse_dns_server("127.0.0.1")?,
            (IpAddr::from([127, 0, 0, 1]), 53),
            "a bare IP literal must use port 53"
        );
        Ok(())
    }

    /// An `ip:port` literal keeps its explicit port.
    #[test]
    fn parses_dns_server_override_ip_and_explicit_port() -> Result<(), String> {
        assert_eq!(
            parse_dns_server("127.0.88.53:5353")?,
            (IpAddr::from([127, 0, 88, 53]), 5353),
            "an explicit port must be kept"
        );
        Ok(())
    }

    /// A host name is rejected: the override must be an IP literal.
    #[test]
    fn rejects_dns_server_override_hostname() -> Result<(), String> {
        let Err(error) = parse_dns_server("dns.test.gokrb5:53") else {
            return Err("a host name must be rejected".to_owned());
        };
        assert!(
            error.contains("expected IP literal"),
            "unexpected error message: {error}"
        );
        Ok(())
    }
}
