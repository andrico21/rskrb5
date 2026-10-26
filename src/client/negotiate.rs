use alloc::fmt;

use tokio::runtime::{Builder, Runtime};

use super::{Error, KdcProtocol, KpasswdRequestOptions, Principal, TokioClient};
use crate::{
    config::Config,
    kadmin::ChangePasswordResult,
    keytab::Keytab,
    spnego::{InitiatorContext, InitiatorContextOptions},
};

/// Small client API for HTTP Negotiate/SPNEGO initiator headers.
///
/// This wrapper keeps the stable HTTP-Negotiate surface narrow while reusing
/// [`TokioClient`] for ticket acquisition, cache reuse, and SPNEGO token
/// construction. Advanced Kerberos flows remain available on `TokioClient`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegotiateClient {
    /// High-level client that acquires tickets and builds tokens.
    inner: TokioClient,
}

impl NegotiateClient {
    #[must_use]
    /// Wrap an existing high-level Tokio client.
    #[inline]
    pub const fn from_tokio_client(client: TokioClient) -> Self {
        Self { inner: client }
    }

    /// Create a password-backed Negotiate client using automatic UDP/TCP KDC transport.
    #[inline]
    pub fn with_password<P>(config: Config, client: Principal, password: P) -> Self
    where
        P: Into<Vec<u8>>,
    {
        Self::from_tokio_client(TokioClient::with_password(
            config,
            KdcProtocol::Auto,
            client,
            password,
        ))
    }

    #[must_use]
    /// Create a keytab-backed Negotiate client using automatic UDP/TCP KDC transport.
    #[inline]
    pub const fn with_keytab(config: Config, client: Principal, keytab: Keytab) -> Self {
        Self::from_tokio_client(TokioClient::with_keytab(
            config,
            KdcProtocol::Auto,
            client,
            keytab,
        ))
    }

    /// Create a keytab-backed Negotiate client by loading a file-backed keytab name.
    ///
    /// # Errors
    ///
    /// Returns an error when the keytab name selects an unsupported keytab store
    /// or the keytab file cannot be read or parsed.
    #[inline]
    pub fn with_keytab_name<P>(
        config: Config,
        client: Principal,
        keytab_name: P,
    ) -> Result<Self, Error>
    where
        P: AsRef<str>,
    {
        Ok(Self::from_tokio_client(TokioClient::with_keytab_name(
            config,
            KdcProtocol::Auto,
            client,
            keytab_name,
        )?))
    }

    /// Create a cache-only Negotiate client by loading a ccache name.
    ///
    /// # Errors
    ///
    /// Returns an error when the cache name selects an unsupported credential
    /// cache store or the cache cannot be read or parsed.
    #[inline]
    pub fn from_ccache_name<P>(config: Config, cache_name: P) -> Result<Self, Error>
    where
        P: AsRef<str>,
    {
        Ok(Self::from_tokio_client(TokioClient::from_ccache_name(
            config,
            KdcProtocol::Auto,
            cache_name,
        )?))
    }

    /// Create a cache-only Negotiate client from the default credential cache.
    ///
    /// `KRB5CCNAME` takes precedence when set. Otherwise this falls back to
    /// `config.libdefaults.default_ccache_name`.
    ///
    /// # Errors
    ///
    /// Returns an error when `KRB5CCNAME` is set but not valid Unicode, when no
    /// default cache name is configured, or when the selected cache cannot be
    /// read or parsed.
    #[inline]
    pub fn from_default_ccache(config: Config) -> Result<Self, Error> {
        Ok(Self::from_tokio_client(TokioClient::from_default_ccache(
            config,
            KdcProtocol::Auto,
        )?))
    }

    /// Create a cache-only Negotiate client by loading the cache named by `KRB5CCNAME`.
    ///
    /// # Errors
    ///
    /// Returns an error when `KRB5CCNAME` is unset or not valid Unicode, or when
    /// the cache it names cannot be read or parsed.
    #[inline]
    pub fn from_ccache_env(config: Config) -> Result<Self, Error> {
        Ok(Self::from_tokio_client(TokioClient::from_ccache_env(
            config,
            KdcProtocol::Auto,
        )?))
    }

    #[must_use]
    /// Borrow the wrapped `TokioClient`.
    #[inline]
    pub const fn inner(&self) -> &TokioClient {
        &self.inner
    }

    /// Mutably borrow the wrapped `TokioClient`.
    #[inline]
    pub const fn inner_mut(&mut self) -> &mut TokioClient {
        &mut self.inner
    }

    #[must_use]
    /// Consume this wrapper and return the wrapped `TokioClient`.
    #[inline]
    pub fn into_inner(self) -> TokioClient {
        self.inner
    }

    /// Build an HTTP `Authorization` header for a Kerberos service principal.
    ///
    /// # Errors
    ///
    /// Returns an error when a TGT or service ticket for `service` cannot be
    /// obtained from the cache or the KDC, or when the AP-REQ or SPNEGO token
    /// cannot be built.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: a service ticket is cached only after its exchange completes,
    /// so dropping the future leaves the client's caches consistent and the call
    /// can be repeated.
    #[inline]
    pub async fn authorization_header(&mut self, service: Principal) -> Result<String, Error> {
        Ok(self.authorization_context(service).await?.header)
    }

    /// Build an HTTP `Authorization` header for a host-based service.
    ///
    /// The service realm is left empty so `TokioClient` can resolve it from
    /// `[domain_realm]` or fall back to the client realm.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPrincipalName`] when the service or host name is
    /// empty, and otherwise the errors of obtaining a service ticket for the
    /// host-based principal or building its token.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: a service ticket is cached only after its exchange completes,
    /// so dropping the future leaves the client's caches consistent and the call
    /// can be repeated.
    #[inline]
    pub async fn authorization_header_for_host<P, Q>(
        &mut self,
        service: P,
        host: Q,
    ) -> Result<String, Error>
    where
        P: AsRef<str>,
        Q: AsRef<str>,
    {
        Ok(self
            .authorization_context_for_host(service, host)
            .await?
            .header)
    }

    /// Build a SPNEGO initiator context for a Kerberos service principal.
    ///
    /// # Errors
    ///
    /// Returns an error when a TGT or service ticket for `service` cannot be
    /// obtained from the cache or the KDC, or when the AP-REQ or SPNEGO token
    /// cannot be built.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: a service ticket is cached only after its exchange completes,
    /// so dropping the future leaves the client's caches consistent and the call
    /// can be repeated.
    #[inline]
    pub async fn authorization_context(
        &mut self,
        service: Principal,
    ) -> Result<InitiatorContext, Error> {
        self.inner.spnego_context(service).await
    }

    /// Build a SPNEGO initiator context with explicit initiator options.
    ///
    /// # Errors
    ///
    /// Returns an error when a TGT or service ticket for `service` cannot be
    /// obtained from the cache or the KDC, or when the AP-REQ or SPNEGO token
    /// cannot be built.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: a service ticket is cached only after its exchange completes,
    /// so dropping the future leaves the client's caches consistent and the call
    /// can be repeated.
    #[inline]
    pub async fn authorization_context_with_options(
        &mut self,
        service: Principal,
        options: InitiatorContextOptions,
    ) -> Result<InitiatorContext, Error> {
        self.inner
            .spnego_context_with_options(service, options)
            .await
    }

    /// Build a SPNEGO initiator context for a host-based service.
    ///
    /// The service realm is left empty so `TokioClient` can resolve it from
    /// `[domain_realm]` or fall back to the client realm.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPrincipalName`] when the service or host name is
    /// empty, and otherwise the errors of obtaining a service ticket for the
    /// host-based principal or building its token.
    ///
    /// # Cancel safety
    ///
    /// cancel-safe: a service ticket is cached only after its exchange completes,
    /// so dropping the future leaves the client's caches consistent and the call
    /// can be repeated.
    #[inline]
    pub async fn authorization_context_for_host<P, Q>(
        &mut self,
        service: P,
        host: Q,
    ) -> Result<InitiatorContext, Error>
    where
        P: AsRef<str>,
        Q: AsRef<str>,
    {
        self.authorization_context(Principal::host_based_service(service, host)?)
            .await
    }

    /// Change this client's password using generated timestamp and sequence metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when reading the clock or the random source fails, when
    /// the `kadmin/changepw` service ticket cannot be obtained, when the request
    /// cannot be built or exchanged with a kpasswd server, when the reply fails
    /// verification or decryption, or when the server reports a non-success
    /// result code.
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe: this mutates credentials on the KDC. Dropping the future
    /// after the kpasswd request is sent does not roll the server back, so the
    /// password may or may not have changed; treat the outcome as unknown and
    /// verify it (for example with a fresh login) before retrying.
    #[inline]
    pub async fn change_password<P>(
        &mut self,
        new_password: P,
        sender_address: rasn_kerberos::HostAddress,
    ) -> Result<ChangePasswordResult, Error>
    where
        P: AsRef<[u8]>,
    {
        self.inner
            .change_password(new_password, sender_address)
            .await
    }

    /// Change the given target principal's password using generated timestamp and
    /// sequence metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when reading the clock or the random source fails, when
    /// the `kadmin/changepw` service ticket cannot be obtained, when the request
    /// cannot be built or exchanged with a kpasswd server, when the reply fails
    /// verification or decryption, or when the server reports a non-success
    /// result code.
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe: this mutates credentials on the KDC. Dropping the future
    /// after the kpasswd request is sent does not roll the server back, so the
    /// password may or may not have changed; treat the outcome as unknown and
    /// verify it (for example with a fresh login) before retrying.
    #[inline]
    pub async fn change_password_for<P>(
        &mut self,
        target: Principal,
        new_password: P,
        sender_address: rasn_kerberos::HostAddress,
    ) -> Result<ChangePasswordResult, Error>
    where
        P: AsRef<[u8]>,
    {
        self.inner
            .change_password_for(target, new_password, sender_address)
            .await
    }

    /// Change this client's password using explicit kpasswd request metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when the `kadmin/changepw` service ticket cannot be
    /// obtained, when the request cannot be built or exchanged with a kpasswd
    /// server, when the reply fails verification or decryption, or when the
    /// server reports a non-success result code.
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe: this mutates credentials on the KDC. Dropping the future
    /// after the kpasswd request is sent does not roll the server back, so the
    /// password may or may not have changed; treat the outcome as unknown and
    /// verify it (for example with a fresh login) before retrying.
    #[inline]
    pub async fn change_password_with_options<P>(
        &mut self,
        new_password: P,
        options: KpasswdRequestOptions,
    ) -> Result<ChangePasswordResult, Error>
    where
        P: AsRef<[u8]>,
    {
        self.inner
            .change_password_with_options(new_password, options)
            .await
    }

    /// Change the given target principal's password using explicit kpasswd
    /// request metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when the `kadmin/changepw` service ticket cannot be
    /// obtained, when the request cannot be built or exchanged with a kpasswd
    /// server, when the reply fails verification or decryption, or when the
    /// server reports a non-success result code.
    ///
    /// # Cancel safety
    ///
    /// NOT cancel-safe: this mutates credentials on the KDC. Dropping the future
    /// after the kpasswd request is sent does not roll the server back, so the
    /// password may or may not have changed; treat the outcome as unknown and
    /// verify it (for example with a fresh login) before retrying.
    #[inline]
    pub async fn change_password_for_with_options<P>(
        &mut self,
        target: Principal,
        new_password: P,
        options: KpasswdRequestOptions,
    ) -> Result<ChangePasswordResult, Error>
    where
        P: AsRef<[u8]>,
    {
        self.inner
            .change_password_for_with_options(target, new_password, options)
            .await
    }
}

/// Blocking wrapper for synchronous CLI consumers of HTTP Negotiate.
///
/// Async applications should use [`NegotiateClient`] directly. This type owns a
/// small current-thread Tokio runtime so callers can generate headers without
/// managing a runtime.
pub struct BlockingNegotiateClient {
    /// Current-thread runtime that drives the async client.
    runtime: Runtime,
    /// Async client whose futures `runtime` blocks on.
    client: NegotiateClient,
}

impl fmt::Debug for BlockingNegotiateClient {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockingNegotiateClient")
            .field("client", &self.client)
            .finish_non_exhaustive()
    }
}

impl BlockingNegotiateClient {
    /// Wrap an existing Negotiate client.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the blocking runtime cannot be created.
    #[inline]
    pub fn new(client: NegotiateClient) -> Result<Self, Error> {
        Ok(Self {
            runtime: blocking_runtime()?,
            client,
        })
    }

    /// Create a password-backed blocking Negotiate client.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the blocking runtime cannot be created.
    #[inline]
    pub fn with_password<P>(config: Config, client: Principal, password: P) -> Result<Self, Error>
    where
        P: Into<Vec<u8>>,
    {
        Self::new(NegotiateClient::with_password(config, client, password))
    }

    /// Create a keytab-backed blocking Negotiate client.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the blocking runtime cannot be created.
    #[inline]
    pub fn with_keytab(config: Config, client: Principal, keytab: Keytab) -> Result<Self, Error> {
        Self::new(NegotiateClient::with_keytab(config, client, keytab))
    }

    /// Create a keytab-backed blocking Negotiate client by loading a file-backed keytab name.
    ///
    /// # Errors
    ///
    /// Returns an error when the keytab name selects an unsupported keytab store
    /// or the keytab file cannot be read or parsed.
    /// Returns an I/O error when the blocking runtime cannot be created.
    #[inline]
    pub fn with_keytab_name<P>(
        config: Config,
        client: Principal,
        keytab_name: P,
    ) -> Result<Self, Error>
    where
        P: AsRef<str>,
    {
        Self::new(NegotiateClient::with_keytab_name(
            config,
            client,
            keytab_name,
        )?)
    }

    /// Create a cache-only blocking Negotiate client by loading a ccache name.
    ///
    /// # Errors
    ///
    /// Returns an error when the cache name selects an unsupported credential
    /// cache store or the cache cannot be read or parsed.
    /// Returns an I/O error when the blocking runtime cannot be created.
    #[inline]
    pub fn from_ccache_name<P>(config: Config, cache_name: P) -> Result<Self, Error>
    where
        P: AsRef<str>,
    {
        Self::new(NegotiateClient::from_ccache_name(config, cache_name)?)
    }

    /// Create a cache-only blocking Negotiate client from the default credential cache.
    ///
    /// # Errors
    ///
    /// Returns an error when `KRB5CCNAME` is set but not valid Unicode, when no
    /// default cache name is configured, or when the selected cache cannot be
    /// read or parsed.
    /// Returns an I/O error when the blocking runtime cannot be created.
    #[inline]
    pub fn from_default_ccache(config: Config) -> Result<Self, Error> {
        Self::new(NegotiateClient::from_default_ccache(config)?)
    }

    /// Create a cache-only blocking Negotiate client by loading the cache named by `KRB5CCNAME`.
    ///
    /// # Errors
    ///
    /// Returns an error when `KRB5CCNAME` is unset or not valid Unicode, or when
    /// the cache it names cannot be read or parsed.
    /// Returns an I/O error when the blocking runtime cannot be created.
    #[inline]
    pub fn from_ccache_env(config: Config) -> Result<Self, Error> {
        Self::new(NegotiateClient::from_ccache_env(config)?)
    }

    /// Borrow the wrapped async client.
    #[inline]
    pub const fn client(&self) -> &NegotiateClient {
        &self.client
    }

    /// Mutably borrow the wrapped async client.
    #[inline]
    pub const fn client_mut(&mut self) -> &mut NegotiateClient {
        &mut self.client
    }

    /// Build an HTTP `Authorization` header for a Kerberos service principal.
    ///
    /// # Errors
    ///
    /// Returns an error when a TGT or service ticket for `service` cannot be
    /// obtained from the cache or the KDC, or when the AP-REQ or SPNEGO token
    /// cannot be built.
    #[inline]
    pub fn authorization_header(&mut self, service: Principal) -> Result<String, Error> {
        Ok(self.authorization_context(service)?.header)
    }

    /// Build an HTTP `Authorization` header for a host-based service.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPrincipalName`] when the service or host name is
    /// empty, and otherwise the errors of obtaining a service ticket for the
    /// host-based principal or building its token.
    #[inline]
    pub fn authorization_header_for_host<P, Q>(
        &mut self,
        service: P,
        host: Q,
    ) -> Result<String, Error>
    where
        P: AsRef<str>,
        Q: AsRef<str>,
    {
        Ok(self.authorization_context_for_host(service, host)?.header)
    }

    /// Build a SPNEGO initiator context for a Kerberos service principal.
    ///
    /// # Errors
    ///
    /// Returns an error when a TGT or service ticket for `service` cannot be
    /// obtained from the cache or the KDC, or when the AP-REQ or SPNEGO token
    /// cannot be built.
    #[inline]
    pub fn authorization_context(&mut self, service: Principal) -> Result<InitiatorContext, Error> {
        self.runtime
            .block_on(self.client.authorization_context(service))
    }

    /// Build a SPNEGO initiator context with explicit initiator options.
    ///
    /// # Errors
    ///
    /// Returns an error when a TGT or service ticket for `service` cannot be
    /// obtained from the cache or the KDC, or when the AP-REQ or SPNEGO token
    /// cannot be built.
    #[inline]
    pub fn authorization_context_with_options(
        &mut self,
        service: Principal,
        options: InitiatorContextOptions,
    ) -> Result<InitiatorContext, Error> {
        self.runtime.block_on(
            self.client
                .authorization_context_with_options(service, options),
        )
    }

    /// Build a SPNEGO initiator context for a host-based service.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPrincipalName`] when the service or host name is
    /// empty, and otherwise the errors of obtaining a service ticket for the
    /// host-based principal or building its token.
    #[inline]
    pub fn authorization_context_for_host<P, Q>(
        &mut self,
        service: P,
        host: Q,
    ) -> Result<InitiatorContext, Error>
    where
        P: AsRef<str>,
        Q: AsRef<str>,
    {
        self.runtime
            .block_on(self.client.authorization_context_for_host(service, host))
    }

    /// Change this client's password using generated timestamp and sequence metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when reading the clock or the random source fails, when
    /// the `kadmin/changepw` service ticket cannot be obtained, when the request
    /// cannot be built or exchanged with a kpasswd server, when the reply fails
    /// verification or decryption, or when the server reports a non-success
    /// result code.
    #[inline]
    pub fn change_password<P>(
        &mut self,
        new_password: P,
        sender_address: rasn_kerberos::HostAddress,
    ) -> Result<ChangePasswordResult, Error>
    where
        P: AsRef<[u8]>,
    {
        self.runtime
            .block_on(self.client.change_password(new_password, sender_address))
    }

    /// Change the given target principal's password using generated timestamp and
    /// sequence metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when reading the clock or the random source fails, when
    /// the `kadmin/changepw` service ticket cannot be obtained, when the request
    /// cannot be built or exchanged with a kpasswd server, when the reply fails
    /// verification or decryption, or when the server reports a non-success
    /// result code.
    #[inline]
    pub fn change_password_for<P>(
        &mut self,
        target: Principal,
        new_password: P,
        sender_address: rasn_kerberos::HostAddress,
    ) -> Result<ChangePasswordResult, Error>
    where
        P: AsRef<[u8]>,
    {
        self.runtime.block_on(
            self.client
                .change_password_for(target, new_password, sender_address),
        )
    }

    /// Change this client's password using explicit kpasswd request metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when the `kadmin/changepw` service ticket cannot be
    /// obtained, when the request cannot be built or exchanged with a kpasswd
    /// server, when the reply fails verification or decryption, or when the
    /// server reports a non-success result code.
    #[inline]
    pub fn change_password_with_options<P>(
        &mut self,
        new_password: P,
        options: KpasswdRequestOptions,
    ) -> Result<ChangePasswordResult, Error>
    where
        P: AsRef<[u8]>,
    {
        self.runtime.block_on(
            self.client
                .change_password_with_options(new_password, options),
        )
    }

    /// Change the given target principal's password using explicit kpasswd
    /// request metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when the `kadmin/changepw` service ticket cannot be
    /// obtained, when the request cannot be built or exchanged with a kpasswd
    /// server, when the reply fails verification or decryption, or when the
    /// server reports a non-success result code.
    #[inline]
    pub fn change_password_for_with_options<P>(
        &mut self,
        target: Principal,
        new_password: P,
        options: KpasswdRequestOptions,
    ) -> Result<ChangePasswordResult, Error>
    where
        P: AsRef<[u8]>,
    {
        self.runtime
            .block_on(
                self.client
                    .change_password_for_with_options(target, new_password, options),
            )
    }
}

/// Build the current-thread runtime that drives a [`BlockingNegotiateClient`].
///
/// # Errors
///
/// Returns an I/O error when the runtime's I/O or timer driver cannot be
/// created.
fn blocking_runtime() -> Result<Runtime, Error> {
    Ok(Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?)
}
