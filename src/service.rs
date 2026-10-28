//! AP-REQ service-side validation.
//!
//! This module validates Kerberos AP-REQ messages by decoding the request,
//! decrypting the service ticket from a keytab, decrypting the authenticator
//! with the ticket session key, and enforcing the core identity, ticket-time,
//! clock-skew, address, and replay checks from gokrb5's service tests. It also
//! builds and verifies AP-REP mutual-auth replies using the AP-REQ
//! authenticator timestamp.

use alloc::{borrow::Cow, sync::Arc};
use core::{fmt::Debug, str::from_utf8, time::Duration};
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{SystemTime, SystemTimeError, UNIX_EPOCH},
};

use rasn::{der, types::Integer};
use sha2::{Digest as _, Sha256};

use crate::{
    ap_rep, ap_req,
    config::Config,
    error,
    keytab::{self, EncryptionKey, Keytab},
    pac::{self, Pac},
    ticket,
};

/// Default AP-REQ acceptance window: five minutes, MIT's default `clockskew`.
const DEFAULT_MAX_CLOCK_SKEW: Duration = Duration::from_mins(5);
/// Bit index of the `invalid` ticket flag (RFC 4120 section 5.3).
const INVALID_TICKET_FLAG: usize = 7;

/// Kerberos principal identity.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct Principal {
    /// Principal realm.
    pub realm: String,
    /// Kerberos name type. Name type is advisory and is not used for matching.
    pub name_type: i32,
    /// Principal name components.
    pub components: Vec<String>,
}

impl Principal {
    /// Creates a `Principal` from its required fields.
    #[must_use]
    #[inline]
    pub const fn new(realm: String, name_type: i32, components: Vec<String>) -> Self {
        Self {
            realm,
            name_type,
            components,
        }
    }

    #[must_use]
    /// Principal components joined by `/`.
    #[inline]
    pub fn name(&self) -> String {
        self.components.join("/")
    }
}

/// Host address used for optional ticket address validation.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct HostAddress {
    /// Kerberos host address type.
    pub addr_type: i32,
    /// Raw address bytes.
    pub address: Vec<u8>,
}

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

/// Successful AP-REQ validation result.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ValidatedApReq {
    /// Client identity from the KDC-authenticated ticket.
    pub client: Principal,
    /// Service identity from the ticket.
    pub service: Principal,
    /// Ticket session key used to decrypt the authenticator.
    pub session_key: EncryptionKey,
    /// Optional subkey supplied by the client authenticator.
    pub subkey: Option<EncryptionKey>,
    /// Optional sequence number supplied by the client authenticator.
    pub sequence_number: Option<u32>,
    /// Ticket start time, or auth time when start time is absent.
    pub ticket_start: SystemTime,
    /// Ticket end time.
    pub ticket_end: SystemTime,
    /// Authenticator `ctime` without `cusec`.
    pub authenticator_ctime: SystemTime,
    /// Authenticator microsecond field.
    pub authenticator_cusec: u32,
    /// Authenticator timestamp including `cusec`.
    pub authenticator_time: SystemTime,
    /// Verified PAC from the ticket authorization data, when present.
    pub pac: Option<Pac>,
}

impl ValidatedApReq {
    /// Build an AP-REP mutual-auth reply with an explicit confounder.
    ///
    /// The explicit confounder keeps tests deterministic and lets callers
    /// choose their own randomness policy. The AP-REP encrypted part is
    /// encrypted with the ticket session key using key usage 12.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TimeOverflow`] when the authenticator time is not a
    /// representable Kerberos time, and an encoding, crypto or key-type error
    /// when the AP-REP cannot be encrypted or encoded.
    #[inline]
    pub fn build_ap_rep_with_confounder(
        &self,
        confounder: &[u8],
        options: &ApRepOptions,
    ) -> Result<Vec<u8>, Error> {
        let cusec = microseconds_to_u32(
            "authenticator.cusec",
            &Integer::from(self.authenticator_cusec),
        )?;
        let enc_part = rasn_kerberos::EncApRepPart {
            ctime: kerberos_time_from_system_time(self.authenticator_ctime)?,
            cusec: Integer::from(cusec),
            subkey: options.subkey.as_ref().map(encryption_key_to_rasn),
            seq_number: options.sequence_number,
        };
        let ap_rep = ap_rep::build_ap_rep_with_confounder(
            &enc_part,
            &self.session_key,
            options.kvno,
            confounder,
        )
        .map_err(ap_rep_error)?;
        ap_rep::encode(&ap_rep).map_err(ap_rep_error)
    }

    /// Verify an AP-REP mutual-auth reply against this AP-REQ.
    ///
    /// The reply must use the same client timestamp from the AP-REQ
    /// authenticator. A verified AP-REP may carry a server-selected subkey and
    /// sequence number.
    ///
    /// # Errors
    ///
    /// Returns a decode, crypto or key-type error when the reply cannot be
    /// decoded or decrypted with the session key, a time or integer error when
    /// its timestamp is out of range, and [`Error::ApRepTimestampMismatch`]
    /// when its timestamp differs from the AP-REQ authenticator's.
    #[inline]
    pub fn verify_ap_rep(&self, bytes: &[u8]) -> Result<VerifiedApRep, Error> {
        let ap_rep = ap_rep::decode(bytes).map_err(ap_rep_error)?;
        let enc_part =
            ap_rep::decrypt_ap_rep_enc_part(&ap_rep, &self.session_key).map_err(ap_rep_error)?;
        let ctime = system_time_from_kerberos_time(&enc_part.ctime)?;
        let cusec = microseconds_to_u32("ap-rep.cusec", &enc_part.cusec)?;
        let authenticator_time = ctime
            .checked_add(Duration::from_micros(cusec.into()))
            .ok_or(Error::TimeOverflow)?;

        if ctime != self.authenticator_ctime || cusec != self.authenticator_cusec {
            return Err(Error::ApRepTimestampMismatch {
                expected: self.authenticator_time,
                actual: authenticator_time,
            });
        }

        Ok(VerifiedApRep {
            ctime,
            cusec,
            authenticator_time,
            subkey: enc_part.subkey.as_ref().map(encryption_key_from_rasn),
            sequence_number: enc_part.seq_number,
        })
    }
}

/// Options for constructing an AP-REP mutual-auth reply.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct ApRepOptions {
    /// Optional server-selected subkey.
    pub subkey: Option<EncryptionKey>,
    /// Optional server sequence number.
    pub sequence_number: Option<u32>,
    /// Optional encrypted-data key version number.
    pub kvno: Option<u32>,
}

impl ApRepOptions {
    /// Sets `subkey`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_subkey(mut self, value: Option<EncryptionKey>) -> Self {
        self.subkey = value;
        self
    }
    /// Sets `sequence_number`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_sequence_number(mut self, value: Option<u32>) -> Self {
        self.sequence_number = value;
        self
    }
    /// Sets `kvno`, preserving the other fields.
    #[must_use]
    #[inline]
    pub const fn with_kvno(mut self, value: Option<u32>) -> Self {
        self.kvno = value;
        self
    }
}

/// Verified AP-REP mutual-auth reply.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct VerifiedApRep {
    /// Reply `ctime` without `cusec`.
    pub ctime: SystemTime,
    /// Reply microsecond field.
    pub cusec: u32,
    /// Reply timestamp including `cusec`.
    pub authenticator_time: SystemTime,
    /// Optional server-selected subkey.
    pub subkey: Option<EncryptionKey>,
    /// Optional server sequence number.
    pub sequence_number: Option<u32>,
}

/// In-memory AP-REQ replay cache.
#[derive(Debug)]
pub struct ReplayCache {
    /// Immutable skew ceiling for every validator using this cache.
    max_clock_skew: Duration,
    /// Maximum live records; admission never evicts a live replay record.
    capacity: usize,
    /// Highest admission time, preserved even by explicit clearing.
    watermark: Option<SystemTime>,
    /// RFC 4120 replay keys of the accepted authenticators, each with the
    /// time it was presented.
    entries: HashMap<ReplayKey, SystemTime>,
    /// SHA-256 digests of the accepted authenticator ciphertexts, each with the
    /// time it was presented, so a re-presented authenticator is a replay
    /// whatever cleartext ticket field was rewritten around it.
    authenticators: HashMap<[u8; 32], SystemTime>,
}

impl Default for ReplayCache {
    #[inline]
    fn default() -> Self {
        Self::with_limits(DEFAULT_MAX_CLOCK_SKEW, 0x0001_0000)
    }
}

impl ReplayCache {
    /// Create an empty cache with immutable skew and live-entry admission limits.
    ///
    /// Validators exceeding `max_clock_skew` are rejected on admission. Zero
    /// capacity rejects all new records. Expiry retains twice the skew from
    /// presentation, covering authenticators first accepted in the future.
    /// Backward clock samples up to this skew are tolerated without lowering
    /// the high-water mark; larger rollbacks fail closed.
    #[must_use]
    #[inline]
    pub fn with_limits(max_clock_skew: Duration, capacity: usize) -> Self {
        Self {
            max_clock_skew,
            capacity,
            watermark: None,
            entries: HashMap::new(),
            authenticators: HashMap::new(),
        }
    }

    #[must_use]
    /// Create an empty replay cache.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Remove all cached replay entries.
    #[inline]
    pub fn clear(&mut self) {
        self.entries.clear();
        self.authenticators.clear();
    }

    #[must_use]
    /// Number of cached RFC 4120 replay entries, excluding the digest index.
    #[inline]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    /// Whether the RFC 4120 replay entries are empty, excluding the digest index.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Remove entries presented more than `max_age` ago.
    #[inline]
    pub fn clear_older_than(&mut self, max_age: Duration) -> usize {
        self.clear_older_than_at(max_age, SystemTime::now())
    }

    /// Remove entries presented more than `max_age` before `now`.
    #[inline]
    pub fn clear_older_than_at(&mut self, max_age: Duration, now: SystemTime) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, presented_at| {
            now.duration_since(*presented_at)
                .map_or(true, |age| age <= max_age)
        });
        self.authenticators.retain(|_, presented_at| {
            now.duration_since(*presented_at)
                .map_or(true, |age| age <= max_age)
        });
        // `retain` only removes entries, so the length cannot have grown.
        before.saturating_sub(self.entries.len())
    }

    /// Record one presentation, or report it as a replay.
    ///
    /// Returns `false`, recording nothing, when either the RFC 4120 replay key
    /// or the authenticator digest was already seen; `true` once both are
    /// recorded.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReplayCacheSkewExceeded`], [`Error::ReplayCacheClockRollback`]
    /// or [`Error::ReplayCacheCapacityExceeded`] when cache policy rejects admission.
    fn insert(
        &mut self,
        key: ReplayKey,
        authenticator_digest: [u8; 32],
        presented_at: SystemTime,
        validator_skew: Duration,
    ) -> Result<bool, Error> {
        if validator_skew > self.max_clock_skew {
            return Err(Error::ReplayCacheSkewExceeded {
                maximum: self.max_clock_skew,
                requested: validator_skew,
            });
        }
        if self.watermark.is_some_and(|latest| {
            latest
                .duration_since(presented_at)
                .is_ok_and(|rollback| rollback > self.max_clock_skew)
        }) {
            return Err(Error::ReplayCacheClockRollback);
        }
        self.watermark = Some(
            self.watermark
                .map_or(presented_at, |latest| latest.max(presented_at)),
        );
        let retention = self.max_clock_skew.saturating_mul(2);
        let _: usize = self.clear_older_than_at(retention, presented_at);
        if self.entries.contains_key(&key)
            || self.authenticators.contains_key(&authenticator_digest)
        {
            return Ok(false);
        }
        if self.entries.len() >= self.capacity {
            return Err(Error::ReplayCacheCapacityExceeded {
                capacity: self.capacity,
            });
        }
        // Both lookups above missed, so neither insert replaces an entry.
        let _: Option<SystemTime> = self.entries.insert(key, presented_at);
        let _: Option<SystemTime> = self
            .authenticators
            .insert(authenticator_digest, presented_at);
        Ok(true)
    }
}

/// Shareable in-memory AP-REQ replay cache.
///
/// This is useful when a service framework clones middleware or builds several
/// service instances from the same acceptor state.
#[derive(Clone, Debug, Default)]
pub struct SharedReplayCache {
    /// The cache shared by every clone.
    inner: Arc<Mutex<ReplayCache>>,
}

impl SharedReplayCache {
    #[must_use]
    /// Create an empty shared replay cache.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    /// Create a shared replay cache from an existing in-memory cache.
    #[inline]
    pub fn from_cache(cache: ReplayCache) -> Self {
        Self {
            inner: Arc::new(Mutex::new(cache)),
        }
    }

    /// Remove all cached replay entries.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReplayCachePoisoned`] when the lock is poisoned.
    #[inline]
    pub fn clear(&self) -> Result<(), Error> {
        self.with_cache_mut(ReplayCache::clear)
    }

    /// Number of cached replay entries.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReplayCachePoisoned`] when the lock is poisoned.
    #[inline]
    pub fn len(&self) -> Result<usize, Error> {
        self.with_cache(ReplayCache::len)
    }

    /// Whether the replay cache is empty.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReplayCachePoisoned`] when the lock is poisoned.
    #[inline]
    pub fn is_empty(&self) -> Result<bool, Error> {
        self.with_cache(ReplayCache::is_empty)
    }

    /// Remove entries presented more than `max_age` ago.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReplayCachePoisoned`] when the lock is poisoned.
    #[inline]
    pub fn clear_older_than(&self, max_age: Duration) -> Result<usize, Error> {
        self.with_cache_mut(|cache| cache.clear_older_than(max_age))
    }

    /// Remove entries presented more than `max_age` before `now`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReplayCachePoisoned`] when the lock is poisoned.
    #[inline]
    pub fn clear_older_than_at(&self, max_age: Duration, now: SystemTime) -> Result<usize, Error> {
        self.with_cache_mut(|cache| cache.clear_older_than_at(max_age, now))
    }

    /// [`ReplayCache::insert`] on the shared cache, under its lock.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReplayCachePoisoned`] when the lock is poisoned.
    fn insert(
        &self,
        key: ReplayKey,
        authenticator_digest: [u8; 32],
        presented_at: SystemTime,
        validator_skew: Duration,
    ) -> Result<bool, Error> {
        self.with_cache_mut(|cache| {
            cache.insert(key, authenticator_digest, presented_at, validator_skew)
        })?
    }

    /// Run `read` on the shared cache under its lock.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReplayCachePoisoned`] when the lock is poisoned.
    fn with_cache<R>(&self, read: impl FnOnce(&ReplayCache) -> R) -> Result<R, Error> {
        let cache = self
            .inner
            .lock()
            .map_err(|_poisoned| Error::ReplayCachePoisoned)?;
        Ok(read(&cache))
    }

    /// Run `update` on the shared cache under its lock.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReplayCachePoisoned`] when the lock is poisoned.
    fn with_cache_mut<R>(&self, update: impl FnOnce(&mut ReplayCache) -> R) -> Result<R, Error> {
        let mut cache = self
            .inner
            .lock()
            .map_err(|_poisoned| Error::ReplayCachePoisoned)?;
        Ok(update(&mut cache))
    }
}

/// Caller-owned policy for unchecked cross-realm transit (RFC 4120 section 2.7).
///
/// Implementations must validate both endpoint realms and the complete encoded
/// path. Empty contents mean direct cross-realm transit, not same-realm use.
/// Unsupported encodings must be rejected unless the implementation understands
/// their semantics. This policy is called only when the endpoint realms differ
/// and the KDC has not set TRANSITED-POLICY-CHECKED.
pub trait TransitValidator: Debug + Send + Sync {
    /// Return whether this realm path is explicitly trusted by the application.
    fn accepts(
        &self,
        client_realm: &str,
        service_realm: &str,
        transited: &rasn_kerberos::TransitedEncoding,
    ) -> bool;
}

/// AP-REQ validator backed by a service keytab.
#[derive(Debug)]
pub struct Validator<'keytab> {
    /// The service keytab, borrowed or owned.
    keytab: Cow<'keytab, Keytab>,
    /// The accepted clock skew between the authenticator time and now.
    max_clock_skew: Duration,
    /// A fixed validation time; `None` uses the system clock.
    now: Option<SystemTime>,
    /// Keytab principal components that override the ticket's server name.
    keytab_principal: Option<Vec<String>>,
    /// The peer address matched against the ticket's client addresses.
    client_address: Option<HostAddress>,
    /// Whether a ticket without client addresses is rejected.
    require_client_address: bool,
    /// This validator's own replay cache.
    replay_cache: ReplayCache,
    /// A shared replay cache that replaces `replay_cache` when attached.
    shared_replay_cache: Option<SharedReplayCache>,
    /// Explicit policy for cross-realm tickets not checked by the KDC.
    transit_policy: Option<Arc<dyn TransitValidator>>,
}

impl<'keytab> Validator<'keytab> {
    /// Create a validator with gokrb5-compatible defaults.
    #[must_use]
    #[inline]
    pub fn new(keytab: &'keytab Keytab) -> Self {
        Self::from_keytab_cow(Cow::Borrowed(keytab))
    }

    /// Create a validator with gokrb5-compatible defaults from a borrowed or
    /// owned keytab.
    pub(crate) fn from_keytab_cow(keytab: Cow<'keytab, Keytab>) -> Self {
        Self {
            keytab,
            max_clock_skew: DEFAULT_MAX_CLOCK_SKEW,
            now: None,
            keytab_principal: None,
            client_address: None,
            require_client_address: false,
            replay_cache: ReplayCache::new(),
            shared_replay_cache: None,
            transit_policy: None,
        }
    }

    /// Override the validation clock. Useful for deterministic tests.
    #[must_use]
    #[inline]
    pub const fn with_now(mut self, now: SystemTime) -> Self {
        self.now = Some(now);
        self
    }

    /// Override the maximum accepted clock skew.
    #[must_use]
    #[inline]
    pub const fn with_max_clock_skew(mut self, max_clock_skew: Duration) -> Self {
        self.max_clock_skew = max_clock_skew;
        self
    }

    /// Override the principal used for keytab lookup.
    ///
    /// The ticket realm remains the lookup realm, matching gokrb5's
    /// `KeytabPrincipal` behavior.
    #[must_use]
    #[inline]
    pub fn with_keytab_principal<I, S>(mut self, components: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.keytab_principal = Some(components.into_iter().map(Into::into).collect());
        self
    }

    /// Provide the client address observed by the service.
    #[must_use]
    #[inline]
    pub fn with_client_address(mut self, client_address: HostAddress) -> Self {
        self.client_address = Some(client_address);
        self
    }

    /// Require the ticket to contain client addresses.
    #[must_use]
    #[inline]
    pub const fn require_client_address(mut self, require_client_address: bool) -> Self {
        self.require_client_address = require_client_address;
        self
    }

    /// Accept unchecked cross-realm paths only when this policy explicitly trusts them.
    #[must_use]
    #[inline]
    pub fn with_transit_validator(mut self, validator: Arc<dyn TransitValidator>) -> Self {
        self.transit_policy = Some(validator);
        self
    }

    /// Share replay detection state with other validators.
    #[must_use]
    #[inline]
    pub fn with_shared_replay_cache(mut self, replay_cache: SharedReplayCache) -> Self {
        self.shared_replay_cache = Some(replay_cache);
        self
    }

    /// Remove any shared replay cache and use this validator's local cache.
    #[must_use]
    #[inline]
    pub fn without_shared_replay_cache(mut self) -> Self {
        self.shared_replay_cache = None;
        self
    }

    /// Shared replay cache used by this validator, if any.
    #[must_use]
    #[inline]
    pub const fn shared_replay_cache(&self) -> Option<&SharedReplayCache> {
        self.shared_replay_cache.as_ref()
    }

    /// Mutable replay cache for tests and integration with service state.
    ///
    /// If a shared replay cache has been installed, validation uses the shared
    /// cache instead of this local cache.
    #[inline]
    pub const fn replay_cache_mut(&mut self) -> &mut ReplayCache {
        &mut self.replay_cache
    }

    /// Decode and validate an AP-REQ.
    ///
    /// # Errors
    ///
    /// Returns a decode error for a malformed AP-REQ, [`Error::Keytab`] when
    /// no keytab key matches the ticket, a crypto, key-type or PAC error when
    /// the ticket, authenticator or PAC fails to decrypt or verify, and the
    /// policy errors [`Error::TicketNotYetValid`], [`Error::TicketExpired`],
    /// [`Error::BadClientAddress`], [`Error::RequiredClientAddressMissing`],
    /// [`Error::ClientPrincipalMismatch`], [`Error::ClockSkew`] and
    /// [`Error::Replay`]. A poisoned shared replay cache returns
    /// [`Error::ReplayCachePoisoned`]. Unchecked cross-realm transit without an
    /// approving caller policy returns [`Error::TransitPolicyRejected`].
    #[inline]
    pub fn validate_ap_req(&mut self, bytes: &[u8]) -> Result<ValidatedApReq, Error> {
        self.validate_ap_req_with_check(bytes, |_| Ok::<(), Error>(()))
    }

    /// Apply a protocol-specific authenticator check before committing replay state.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::validate_ap_req`] or the supplied check.
    pub(crate) fn validate_ap_req_with_check<F, E>(
        &mut self,
        bytes: &[u8],
        check: F,
    ) -> Result<ValidatedApReq, E>
    where
        F: FnOnce(&rasn_kerberos::Authenticator) -> Result<(), E>,
        E: From<Error>,
    {
        let ap_req = ap_req::decode(bytes).map_err(ap_req_error)?;

        let ticket_service = principal_from_parts(&ap_req.ticket.realm, &ap_req.ticket.sname)?;
        let ticket_etype = ap_req.ticket.enc_part.etype;
        let ticket_kvno = ap_req.ticket.enc_part.kvno.unwrap_or(0);
        let keytab_components = self
            .keytab_principal
            .clone()
            .unwrap_or_else(|| ticket_service.components.clone());
        let keytab_refs = keytab_components
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let service_key = self
            .keytab
            .find_key(
                &keytab_refs,
                &ticket_service.realm,
                ticket_kvno,
                ticket_etype,
            )
            .map_err(Error::from)?;

        let enc_ticket =
            ticket::decrypt_ticket_enc_part(&ap_req.ticket, service_key.0).map_err(ticket_error)?;
        self.validate_ticket_times(&ticket_service, &enc_ticket)?;
        self.validate_client_address(&ticket_service, &enc_ticket)?;
        self.validate_transit(&ticket_service, &enc_ticket)?;
        let pac = verified_ticket_pac(enc_ticket.authorization_data.as_ref(), service_key.0)?;

        let session_key = encryption_key_from_rasn(&enc_ticket.key);
        let authenticator_usage = ap_req::authenticator_usage_for_ticket(&ap_req.ticket);
        let authenticator =
            ap_req::decrypt_ap_req_authenticator(&ap_req, &session_key, authenticator_usage)
                .map_err(ap_req_error)?;

        validate_authorization_data(authenticator.authorization_data.as_ref(), false)?;

        let ticket_client = principal_from_parts(&enc_ticket.crealm, &enc_ticket.cname)?;
        let authenticator_client =
            principal_from_parts(&authenticator.crealm, &authenticator.cname)?;
        // RFC 4120 section 3.2.3: compare the client name and realm of the
        // ticket with the same fields in the authenticator and reject
        // KRB_AP_ERR_BADMATCH on any mismatch.
        if authenticator_client.realm != ticket_client.realm
            || authenticator_client.components != ticket_client.components
        {
            return Err(Error::ClientPrincipalMismatch {
                ticket: format!("{}@{}", ticket_client.name(), ticket_client.realm),
                authenticator: format!(
                    "{}@{}",
                    authenticator_client.name(),
                    authenticator_client.realm
                ),
            }
            .into());
        }

        let cusec = microseconds_to_u32("authenticator.cusec", &authenticator.cusec)?;
        let authenticator_ctime = system_time_from_kerberos_time(&authenticator.ctime)?;
        let authenticator_timestamp = authenticator_ctime
            .checked_add(Duration::from_micros(cusec.into()))
            .ok_or(Error::TimeOverflow)?;
        let now = self.now();
        if abs_duration(now, authenticator_timestamp) > self.max_clock_skew {
            return Err(Error::ClockSkew {
                max_clock_skew: self.max_clock_skew,
            }
            .into());
        }

        check(&authenticator)?;

        // RFC 4120 section 3.2.3 keys the replay cache on the server name, the
        // client name, the time and the microseconds. Section 6.2 makes the
        // advisory name-type "not significant when checking for equivalence",
        // and the ticket's outer sname is cleartext a peer can rewrite, so the
        // identity is built without it; the service side is the key identity
        // that actually accepted the ticket (the configured override when one
        // is set, otherwise the ticket's own components). Keep that RFC key,
        // and also index the authenticator ciphertext to reject re-presentation
        // under any rewritten cleartext ticket field, including an sname alias
        // whose keytab entry shares the key. Hash only the cipher octets:
        // unauthenticated etype/kvno metadata must not create a fresh digest.
        let authenticator_digest: [u8; 32] =
            Sha256::digest(ap_req.authenticator.cipher.as_ref()).into();
        let replay_key = ReplayKey {
            service: Principal {
                realm: ticket_service.realm.clone(),
                name_type: 0,
                components: keytab_components.clone(),
            },
            client: Principal {
                realm: authenticator_client.realm.clone(),
                name_type: 0,
                components: authenticator_client.components,
            },
            ctime_seconds: authenticator.ctime.0.timestamp(),
            cusec,
        };
        let validated = ValidatedApReq {
            client: ticket_client,
            service: ticket_service,
            session_key,
            subkey: authenticator.subkey.as_ref().map(encryption_key_from_rasn),
            sequence_number: authenticator.seq_number,
            ticket_start: ticket_start_time(&enc_ticket)?,
            ticket_end: system_time_from_kerberos_time(&enc_ticket.end_time)?,
            authenticator_ctime,
            authenticator_cusec: cusec,
            authenticator_time: authenticator_timestamp,
            pac,
        };
        self.record_replay(replay_key, authenticator_digest, now)?;
        Ok(validated)
    }

    /// Enforce RFC 4120 section 2.7 before replay admission.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TransitPolicyRejected`] for unchecked cross-realm paths
    /// without explicit approval, or [`Error::InvalidString`] for invalid realms.
    fn validate_transit(
        &self,
        service: &Principal,
        ticket: &rasn_kerberos::EncTicketPart,
    ) -> Result<(), Error> {
        let client_realm = kerberos_string_to_string(&ticket.crealm)?;
        if client_realm != service.realm
            && !ticket.flags.0.get(12).is_some_and(|bit| *bit)
            && !self.transit_policy.as_ref().is_some_and(|policy| {
                policy.accepts(&client_realm, &service.realm, &ticket.transited)
            })
        {
            return Err(Error::TransitPolicyRejected);
        }
        Ok(())
    }

    /// The validation time: the fixed time when one is set, otherwise the
    /// system clock.
    fn now(&self) -> SystemTime {
        self.now.unwrap_or_else(SystemTime::now)
    }

    /// Record an accepted AP-REQ in the shared replay cache when one is
    /// attached, otherwise in this validator's own cache.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Replay`] when the replay key or the authenticator
    /// digest was already recorded, and [`Error::ReplayCachePoisoned`] when the
    /// shared cache's lock is poisoned.
    fn record_replay(
        &mut self,
        replay_key: ReplayKey,
        authenticator_digest: [u8; 32],
        now: SystemTime,
    ) -> Result<(), Error> {
        let inserted = if let Some(replay_cache) = &self.shared_replay_cache {
            replay_cache.insert(replay_key, authenticator_digest, now, self.max_clock_skew)?
        } else {
            self.replay_cache
                .insert(replay_key, authenticator_digest, now, self.max_clock_skew)?
        };
        if inserted { Ok(()) } else { Err(Error::Replay) }
    }

    /// Check the ticket's start and end times, and its invalid flag, against
    /// now and the accepted clock skew.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TicketNotYetValid`] for a future or invalid ticket,
    /// [`Error::TicketExpired`] for an expired one, and
    /// [`Error::TimeOverflow`] when a ticket time is out of range.
    fn validate_ticket_times(
        &self,
        service: &Principal,
        enc_ticket: &rasn_kerberos::EncTicketPart,
    ) -> Result<(), Error> {
        let _: SystemTime = system_time_from_kerberos_time(&enc_ticket.auth_time)?;
        if let Some(renew_till) = &enc_ticket.renew_till {
            let _: SystemTime = system_time_from_kerberos_time(renew_till)?;
        }
        let now = self.now();
        let start = ticket_start_time(enc_ticket)?;
        if starts_after_skew(start, now, self.max_clock_skew) || has_invalid_flag(&enc_ticket.flags)
        {
            return Err(Error::TicketNotYetValid {
                service: service.name(),
                realm: service.realm.clone(),
            });
        }

        let end = system_time_from_kerberos_time(&enc_ticket.end_time)?;
        if expired_after_skew(now, end, self.max_clock_skew) {
            return Err(Error::TicketExpired {
                service: service.name(),
                realm: service.realm.clone(),
            });
        }

        Ok(())
    }

    /// Match the ticket's client addresses against the configured peer
    /// address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RequiredClientAddressMissing`] when addresses are
    /// required and the ticket has none, and [`Error::BadClientAddress`] when
    /// the ticket has addresses and none matches the peer address.
    fn validate_client_address(
        &self,
        service: &Principal,
        enc_ticket: &rasn_kerberos::EncTicketPart,
    ) -> Result<(), Error> {
        let Some(ticket_addresses) = &enc_ticket.caddr else {
            if self.require_client_address {
                return Err(Error::RequiredClientAddressMissing {
                    service: service.name(),
                    realm: service.realm.clone(),
                });
            }
            return Ok(());
        };

        let Some(client_address) = &self.client_address else {
            return Err(Error::BadClientAddress {
                service: service.name(),
                realm: service.realm.clone(),
            });
        };

        if ticket_addresses.iter().any(|address| {
            let same_type = address.addr_type == client_address.addr_type;
            same_type && address.address.as_ref() == client_address.address.as_slice()
        }) {
            Ok(())
        } else {
            Err(Error::BadClientAddress {
                service: service.name(),
                realm: service.realm.clone(),
            })
        }
    }
}

impl Validator<'static> {
    #[must_use]
    /// Create a validator from an owned keytab.
    #[inline]
    pub fn from_keytab(keytab: Keytab) -> Self {
        Self::from_keytab_cow(Cow::Owned(keytab))
    }

    /// Create a validator by loading a file-backed keytab name.
    ///
    /// Bare paths, `FILE:path`, and `WRFILE:path` are supported by the keytab
    /// module. Other keytab stores are rejected explicitly.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Keytab`] when the name is not a file keytab or the
    /// file cannot be read or parsed.
    #[inline]
    pub fn from_keytab_name<P>(keytab_name: P) -> Result<Self, Error>
    where
        P: AsRef<str>,
    {
        Ok(Self::from_keytab(Keytab::load_name(keytab_name)?))
    }

    /// Create a validator from `config.libdefaults.default_keytab_name`.
    ///
    /// The configured `[libdefaults] clockskew` becomes the acceptance window;
    /// [`Self::new`] keeps the gokrb5-compatible 300 s default.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Keytab`] when the configured name is not a file keytab
    /// or the file cannot be read or parsed.
    #[inline]
    pub fn from_default_keytab_name(config: &Config) -> Result<Self, Error> {
        Ok(
            Self::from_keytab_name(&config.libdefaults.default_keytab_name)?
                .with_max_clock_skew(config.libdefaults.clockskew),
        )
    }

    /// Create a validator from the default keytab.
    ///
    /// `KRB5_KTNAME` takes precedence when set. Otherwise this falls back to
    /// `config.libdefaults.default_keytab_name`. The configured
    /// `[libdefaults] clockskew` becomes the acceptance window.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Keytab`] when the selected name is not a file keytab
    /// or the file cannot be read or parsed.
    #[inline]
    pub fn from_default_keytab(config: &Config) -> Result<Self, Error> {
        Ok(Self::from_keytab_name(keytab::default_keytab_name(
            &config.libdefaults.default_keytab_name,
        )?)?
        .with_max_clock_skew(config.libdefaults.clockskew))
    }

    /// Create a validator by loading the file keytab named by `KRB5_KTNAME`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Keytab`] when the variable is unset, names a
    /// non-file keytab, or the file cannot be read or parsed.
    #[inline]
    pub fn from_keytab_env() -> Result<Self, Error> {
        Ok(Self::from_keytab(Keytab::load_from_env()?))
    }
}

use crate::error::Service as Error;

/// Authorization-data interpretation context, including wrapper criticality.
#[derive(Clone, Copy)]
struct AuthorizationScope {
    /// AD-IF-RELEVANT makes unknown direct children optional.
    critical: bool,
    /// Only ticket PACs are authenticated by the existing PAC verification path.
    ticket: bool,
    /// Maximum nesting is eight wrappers, independently of DER validity.
    depth: usize,
}

/// Validate every restriction independently of first-PAC extraction (RFC 4120 section 5.2.6).
///
/// # Errors
///
/// Returns [`Error::UnsupportedAuthorizationData`] for uninterpreted mandatory
/// semantics, [`Error::AuthorizationDataLimit`] for excess depth/decoded bytes,
/// and [`Error::Decode`] for malformed known wrappers.
fn validate_authorization_data(
    data: Option<&rasn_kerberos::AuthorizationData>,
    ticket: bool,
) -> Result<(), Error> {
    if let Some(elements) = data {
        validate_authorization_elements(
            elements,
            AuthorizationScope {
                critical: true,
                ticket,
                depth: 0,
            },
            &mut 0x0010_0000,
        )?;
    }
    Ok(())
}

/// Interpret wrapper criticality with a shared decoded-byte budget.
///
/// # Errors
///
/// Returns the errors documented by [`validate_authorization_data`].
fn validate_authorization_elements(
    data: &rasn_kerberos::AuthorizationData,
    scope: AuthorizationScope,
    remaining: &mut usize,
) -> Result<(), Error> {
    for entry in data {
        *remaining = remaining
            .checked_sub(entry.data.len())
            .ok_or(Error::AuthorizationDataLimit)?;
        match entry.r#type {
            pac::AD_IF_RELEVANT | 8_i32 => {
                if scope.depth >= 8 {
                    return Err(Error::AuthorizationDataLimit);
                }
                let nested = der::decode::<rasn_kerberos::AuthorizationData>(entry.data.as_ref())
                    .map_err(|source| Error::Decode {
                    target: "AuthorizationData",
                    message: source.to_string(),
                })?;
                validate_authorization_elements(
                    &nested,
                    AuthorizationScope {
                        critical: entry.r#type == 8_i32,
                        ticket: scope.ticket,
                        depth: scope.depth.saturating_add(1),
                    },
                    remaining,
                )?;
            }
            pac::AD_WIN2K_PAC if scope.ticket => {}
            4_i32 | 5_i32 => {
                return Err(Error::UnsupportedAuthorizationData { kind: entry.r#type });
            }
            _ if scope.critical => {
                return Err(Error::UnsupportedAuthorizationData { kind: entry.r#type });
            }
            _ => {}
        }
    }
    Ok(())
}

/// Validate every ticket restriction before extracting and verifying its first PAC.
///
/// # Errors
///
/// Returns authorization-policy errors or [`Error::Pac`] for PAC parsing/checksum failures.
fn verified_ticket_pac(
    data: Option<&rasn_kerberos::AuthorizationData>,
    key: &EncryptionKey,
) -> Result<Option<Pac>, Error> {
    validate_authorization_data(data, true)?;
    let Some(elements) = data else {
        return Ok(None);
    };
    let pac = pac::find_pac_in_authorization_data(elements)?;
    if let Some(value) = &pac {
        value.verify(key)?;
    }
    Ok(pac)
}

/// RFC 4120 section 3.2.3 replay-cache key of one authenticator.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ReplayKey {
    /// The accepting service principal, without its name type.
    service: Principal,
    /// The authenticator's client principal, without its name type.
    client: Principal,
    /// The authenticator's `ctime`, in seconds since the Unix epoch.
    ctime_seconds: i64,
    /// The authenticator's `cusec`.
    cusec: u32,
}

/// Map an AP-REQ message error onto the service error.
fn ap_req_error(error: error::ApReq) -> Error {
    match error {
        error::ApReq::Decode { target, message } => Error::Decode { target, message },
        error::ApReq::Encode { target, message } => Error::Encode { target, message },
        error::ApReq::InvalidMessage {
            field,
            expected,
            actual,
        } => Error::InvalidMessage {
            field,
            expected,
            actual,
        },
        error::ApReq::UnsupportedEtype(etype) => Error::UnsupportedEtype(etype),
        error::ApReq::KeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        } => Error::ApReqKeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        },
        error::ApReq::Random(source) => Error::Random(source),
        error::ApReq::Crypto(source) => Error::Crypto(source),
    }
}

/// Map a ticket message error onto the service error.
fn ticket_error(error: error::Ticket) -> Error {
    match error {
        error::Ticket::Decode { target, message } => Error::Decode { target, message },
        error::Ticket::Encode { target, message } => Error::Encode { target, message },
        error::Ticket::InvalidMessage {
            field,
            expected,
            actual,
        } => Error::InvalidMessage {
            field,
            expected,
            actual,
        },
        error::Ticket::UnsupportedEtype(etype) => Error::UnsupportedEtype(etype),
        error::Ticket::KeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        } => Error::TicketKeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        },
        error::Ticket::Random(source) => Error::Random(source),
        error::Ticket::Crypto(source) => Error::Crypto(source),
    }
}

/// Map an AP-REP message error onto the service error.
fn ap_rep_error(error: error::ApRep) -> Error {
    match error {
        error::ApRep::Decode { target, message } => Error::Decode { target, message },
        error::ApRep::Encode { target, message } => Error::Encode { target, message },
        error::ApRep::InvalidMessage {
            field,
            expected,
            actual,
        } => Error::InvalidMessage {
            field,
            expected,
            actual,
        },
        error::ApRep::UnsupportedEtype(etype) => Error::UnsupportedEtype(etype),
        error::ApRep::KeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        } => Error::ApRepKeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        },
        error::ApRep::Random(source) => Error::Random(source),
        error::ApRep::Crypto(source) => Error::Crypto(source),
    }
}

/// Build a principal from a wire realm and principal name.
///
/// # Errors
///
/// Returns [`Error::InvalidString`] when the realm or a name component is not
/// UTF-8.
fn principal_from_parts(
    realm: &rasn_kerberos::Realm,
    name: &rasn_kerberos::PrincipalName,
) -> Result<Principal, Error> {
    Ok(Principal {
        realm: kerberos_string_to_string(realm)?,
        name_type: name.r#type,
        components: name
            .string
            .iter()
            .map(kerberos_string_to_string)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

/// Convert a wire Kerberos string to a Rust string.
///
/// # Errors
///
/// Returns [`Error::InvalidString`] when the string is not UTF-8.
fn kerberos_string_to_string(value: &rasn_kerberos::KerberosString) -> Result<String, Error> {
    Ok(from_utf8(value.as_bytes())?.to_owned())
}

/// Convert a wire encryption key to the keytab key type.
///
/// # Errors
///
/// Never fails today; the `Result` is kept for the callers' `?` chains.
fn encryption_key_from_rasn(value: &rasn_kerberos::EncryptionKey) -> EncryptionKey {
    EncryptionKey {
        etype: value.r#type,
        value: value.value.as_ref().to_vec(),
    }
}

/// Convert a keytab key to the wire encryption key type.
fn encryption_key_to_rasn(value: &EncryptionKey) -> rasn_kerberos::EncryptionKey {
    rasn_kerberos::EncryptionKey {
        r#type: value.etype,
        value: value.value.clone().into(),
    }
}

/// The ticket's start time, or its auth time when it has none.
///
/// # Errors
///
/// Returns [`Error::TimeOverflow`] when the time is out of range.
fn ticket_start_time(enc_ticket: &rasn_kerberos::EncTicketPart) -> Result<SystemTime, Error> {
    system_time_from_kerberos_time(
        enc_ticket
            .start_time
            .as_ref()
            .unwrap_or(&enc_ticket.auth_time),
    )
}

/// Convert a Kerberos time to a `SystemTime`.
///
/// # Errors
///
/// Returns [`Error::TimeOverflow`] when the time is not representable.
fn system_time_from_kerberos_time(time: &rasn_kerberos::KerberosTime) -> Result<SystemTime, Error> {
    let seconds = time.0.timestamp();
    let nanos = time.0.timestamp_subsec_nanos();
    if nanos != 0 {
        return Err(Error::FractionalKerberosTime);
    }
    u64::try_from(seconds)
        .map_or_else(
            |_before_epoch| UNIX_EPOCH.checked_sub(Duration::new(seconds.unsigned_abs(), nanos)),
            |after_epoch| UNIX_EPOCH.checked_add(Duration::new(after_epoch, nanos)),
        )
        .ok_or(Error::TimeOverflow)
}

/// Convert a `SystemTime` to a Kerberos time in UTC.
///
/// # Errors
///
/// Returns [`Error::TimeOverflow`] when the time is not representable.
fn kerberos_time_from_system_time(time: SystemTime) -> Result<rasn_kerberos::KerberosTime, Error> {
    let (seconds, nanos) = unix_timestamp_parts(time)?;
    if nanos != 0 {
        return Err(Error::FractionalKerberosTime);
    }
    let utc = chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, nanos)
        .ok_or(Error::TimeOverflow)?;
    let offset = chrono::FixedOffset::east_opt(0).ok_or(Error::TimeOverflow)?;
    Ok(rasn_kerberos::KerberosTime(utc.with_timezone(&offset)))
}

/// Split a `SystemTime` into whole seconds since the Unix epoch (floored)
/// and the non-negative nanoseconds past them.
///
/// # Errors
///
/// Returns [`Error::TimeOverflow`] when the seconds do not fit in `i64`.
fn unix_timestamp_parts(time: SystemTime) -> Result<(i64, u32), Error> {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => Ok((
            duration
                .as_secs()
                .try_into()
                .map_err(|_out_of_range| Error::TimeOverflow)?,
            duration.subsec_nanos(),
        )),
        Err(source) => {
            let duration = source.duration();
            let whole_seconds: i64 = duration
                .as_secs()
                .try_into()
                .map_err(|_out_of_range| Error::TimeOverflow)?;
            if duration.subsec_nanos() == 0 {
                return Ok((whole_seconds.checked_neg().ok_or(Error::TimeOverflow)?, 0));
            }

            // The seconds are floored: a time 1.25 s before the epoch is
            // -2 s plus 750 ms. `subsec_nanos` is below one billion.
            let floored_seconds = whole_seconds.checked_add(1).ok_or(Error::TimeOverflow)?;
            let nanos = 1_000_000_000_u32
                .checked_sub(duration.subsec_nanos())
                .ok_or(Error::TimeOverflow)?;
            Ok((
                floored_seconds.checked_neg().ok_or(Error::TimeOverflow)?,
                nanos,
            ))
        }
    }
}

/// Enforce the RFC 4120 Microseconds domain before timestamp arithmetic.
///
/// # Errors
///
/// Returns [`Error::IntegerOutOfRange`], naming `field`, outside 0..=999999.
fn microseconds_to_u32(field: &'static str, value: &Integer) -> Result<u32, Error> {
    value
        .to_string()
        .parse::<u32>()
        .ok()
        .filter(|parsed| *parsed <= 999_999)
        .ok_or_else(|| Error::IntegerOutOfRange {
            field,
            value: value.to_string(),
        })
}

/// Whether the ticket's `invalid` flag is set.
fn has_invalid_flag(flags: &rasn_kerberos::TicketFlags) -> bool {
    flags.0.get(INVALID_TICKET_FLAG).is_some_and(|bit| *bit)
}

/// Whether `start` lies more than `max_clock_skew` after `now`.
fn starts_after_skew(start: SystemTime, now: SystemTime, max_clock_skew: Duration) -> bool {
    start
        .duration_since(now)
        .is_ok_and(|delta| delta > max_clock_skew)
}

/// Whether `end` lies more than `max_clock_skew` before `now`.
fn expired_after_skew(now: SystemTime, end: SystemTime, max_clock_skew: Duration) -> bool {
    now.duration_since(end)
        .is_ok_and(|delta| delta > max_clock_skew)
}

/// The absolute distance between two times.
fn abs_duration(left: SystemTime, right: SystemTime) -> Duration {
    // An error carries how far `right` lies after `left`.
    left.duration_since(right)
        .unwrap_or_else(|later| SystemTimeError::duration(&later))
}
