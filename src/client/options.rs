use core::time::Duration;
use std::time::SystemTime;

use super::{
    DEFAULT_TGS_ENCTYPES, DEFAULT_TICKET_LIFETIME, DEFAULT_TKT_ENCTYPES, KDC_OPTION_CANONICALIZE,
    renewal_kdc_option_bits,
};
use crate::{config::LibDefaults, keytab::EncryptionKey};

/// Options for constructing an AS-REQ.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct AsReq {
    /// Client clock used for request time fields.
    pub now: SystemTime,
    /// Requested ticket lifetime.
    pub ticket_lifetime: Duration,
    /// Optional renewable lifetime.
    pub renew_lifetime: Option<Duration>,
    /// Client nonce. Callers are responsible for supplying fresh randomness.
    pub nonce: u32,
    /// Requested response encryption types in preference order.
    pub etypes: Vec<i32>,
    /// KDC option bit string as stored in krb5.conf.
    pub kdc_option_bits: u32,
    /// Optional preauthentication data.
    pub padata: Vec<rasn_kerberos::PaData>,
    /// Send PA-ENC-TIMESTAMP in the first AS-REQ using requested etype defaults.
    pub assume_preauthentication: bool,
    /// Advertise support for AS-REP encrypted padata negotiation.
    pub fast_negotiation: bool,
}

impl AsReq {
    #[must_use]
    /// Construct options with gokrb5-compatible AES defaults.
    #[inline]
    pub fn new(now: SystemTime, nonce: u32) -> Self {
        Self {
            now,
            ticket_lifetime: DEFAULT_TICKET_LIFETIME,
            renew_lifetime: None,
            nonce,
            etypes: DEFAULT_TKT_ENCTYPES.to_vec(),
            kdc_option_bits: 0,
            padata: Vec::new(),
            assume_preauthentication: false,
            fast_negotiation: true,
        }
    }

    #[must_use]
    /// Construct options from parsed `[libdefaults]`.
    ///
    /// When `permitted_enctypes_explicit` is set, the request list is narrowed
    /// to `permitted_enctype_ids`. `Config::parse` already rejects an explicit
    /// `default_tkt_enctypes` naming an enctype outside the allowlist, so for
    /// parsed configs this only narrows the seeded default list that no
    /// operator requested. A programmatically built `LibDefaults` whose lists
    /// are disjoint, or whose `permitted_enctype_ids` is empty, yields an
    /// empty list, which the request builders reject.
    #[inline]
    pub fn from_libdefaults(now: SystemTime, nonce: u32, defaults: &LibDefaults) -> Self {
        let mut options = Self::new(now, nonce);
        options.ticket_lifetime = defaults.ticket_lifetime;
        options.renew_lifetime =
            (defaults.renew_lifetime != Duration::ZERO).then_some(defaults.renew_lifetime);
        options.etypes = if defaults.default_tkt_enctype_ids.is_empty() {
            DEFAULT_TKT_ENCTYPES.to_vec()
        } else {
            defaults.default_tkt_enctype_ids.clone()
        };
        if defaults.permitted_enctypes_explicit.is_enabled() {
            options
                .etypes
                .retain(|etype| defaults.permitted_enctype_ids.contains(etype));
        }
        options.kdc_option_bits = defaults.kdc_default_options;
        if defaults.canonicalize.is_enabled() {
            options.kdc_option_bits |= KDC_OPTION_CANONICALIZE;
        }
        options
    }

    #[must_use]
    /// Override the requested ticket lifetime.
    #[inline]
    pub const fn with_ticket_lifetime(mut self, ticket_lifetime: Duration) -> Self {
        self.ticket_lifetime = ticket_lifetime;
        self
    }

    #[must_use]
    /// Override the renewable lifetime.
    #[inline]
    pub const fn with_renew_lifetime(mut self, renew_lifetime: Option<Duration>) -> Self {
        self.renew_lifetime = renew_lifetime;
        self
    }

    #[must_use]
    /// Override requested response encryption types.
    #[inline]
    pub fn with_etypes<P>(mut self, etypes: P) -> Self
    where
        P: Into<Vec<i32>>,
    {
        self.etypes = etypes.into();
        self
    }

    #[must_use]
    /// Override KDC options using the raw krb5.conf bit representation.
    #[inline]
    pub const fn with_kdc_option_bits(mut self, kdc_option_bits: u32) -> Self {
        self.kdc_option_bits = kdc_option_bits;
        self
    }

    #[must_use]
    /// Add preauthentication data.
    #[inline]
    pub fn with_padata<P>(mut self, padata: P) -> Self
    where
        P: Into<Vec<rasn_kerberos::PaData>>,
    {
        self.padata = padata.into();
        self
    }

    #[must_use]
    /// Send PA-ENC-TIMESTAMP in the first AS-REQ.
    #[inline]
    pub const fn with_assume_preauthentication(mut self, assume_preauthentication: bool) -> Self {
        self.assume_preauthentication = assume_preauthentication;
        self
    }

    #[must_use]
    /// Configure whether high-level AS login advertises PA-REQ-ENC-PA-REP.
    #[inline]
    pub const fn with_fast_negotiation(mut self, fast_negotiation: bool) -> Self {
        self.fast_negotiation = fast_negotiation;
        self
    }
}

/// Options for constructing a TGS-REQ.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct TgsReq {
    /// Client clock used for request time fields.
    pub now: SystemTime,
    /// Requested service-ticket lifetime.
    pub ticket_lifetime: Duration,
    /// Optional renewable lifetime.
    pub renew_lifetime: Option<Duration>,
    /// Client nonce. Callers are responsible for supplying fresh randomness.
    pub nonce: u32,
    /// Requested response encryption types in preference order.
    pub etypes: Vec<i32>,
    /// KDC option bit string as stored in krb5.conf.
    pub kdc_option_bits: u32,
    /// Additional TGS padata appended after PA-TGS-REQ.
    pub padata: Vec<rasn_kerberos::PaData>,
    /// Additional tickets included in the TGS request body.
    pub additional_tickets: Vec<rasn_kerberos::Ticket>,
}

impl TgsReq {
    #[must_use]
    /// Construct options with gokrb5-compatible AES defaults.
    #[inline]
    pub fn new(now: SystemTime, nonce: u32) -> Self {
        Self {
            now,
            ticket_lifetime: DEFAULT_TICKET_LIFETIME,
            renew_lifetime: None,
            nonce,
            etypes: DEFAULT_TGS_ENCTYPES.to_vec(),
            kdc_option_bits: 0,
            padata: Vec::new(),
            additional_tickets: Vec::new(),
        }
    }

    #[must_use]
    /// Construct options from parsed `[libdefaults]`.
    ///
    /// When `permitted_enctypes_explicit` is set, the request list is narrowed
    /// to `permitted_enctype_ids`. `Config::parse` already rejects an explicit
    /// `default_tgs_enctypes` naming an enctype outside the allowlist, so for
    /// parsed configs this only narrows the seeded default list that no
    /// operator requested. A programmatically built `LibDefaults` whose lists
    /// are disjoint, or whose `permitted_enctype_ids` is empty, yields an
    /// empty list, which the request builders reject.
    #[inline]
    pub fn from_libdefaults(now: SystemTime, nonce: u32, defaults: &LibDefaults) -> Self {
        let mut options = Self::new(now, nonce);
        options.ticket_lifetime = defaults.ticket_lifetime;
        options.renew_lifetime =
            (defaults.renew_lifetime != Duration::ZERO).then_some(defaults.renew_lifetime);
        options.etypes = if defaults.default_tgs_enctype_ids.is_empty() {
            DEFAULT_TGS_ENCTYPES.to_vec()
        } else {
            defaults.default_tgs_enctype_ids.clone()
        };
        if defaults.permitted_enctypes_explicit.is_enabled() {
            options
                .etypes
                .retain(|etype| defaults.permitted_enctype_ids.contains(etype));
        }
        options.kdc_option_bits = defaults.kdc_default_options;
        if defaults.canonicalize.is_enabled() {
            options.kdc_option_bits |= KDC_OPTION_CANONICALIZE;
        }
        options
    }

    #[must_use]
    /// Override the requested service-ticket lifetime.
    #[inline]
    pub const fn with_ticket_lifetime(mut self, ticket_lifetime: Duration) -> Self {
        self.ticket_lifetime = ticket_lifetime;
        self
    }

    #[must_use]
    /// Override the renewable lifetime.
    #[inline]
    pub const fn with_renew_lifetime(mut self, renew_lifetime: Option<Duration>) -> Self {
        self.renew_lifetime = renew_lifetime;
        self
    }

    #[must_use]
    /// Override requested response encryption types.
    #[inline]
    pub fn with_etypes<P>(mut self, etypes: P) -> Self
    where
        P: Into<Vec<i32>>,
    {
        self.etypes = etypes.into();
        self
    }

    #[must_use]
    /// Override KDC options using the raw krb5.conf bit representation.
    #[inline]
    pub const fn with_kdc_option_bits(mut self, kdc_option_bits: u32) -> Self {
        self.kdc_option_bits = kdc_option_bits;
        self
    }

    #[must_use]
    /// Add additional TGS padata.
    #[inline]
    pub fn with_padata<P>(mut self, padata: P) -> Self
    where
        P: Into<Vec<rasn_kerberos::PaData>>,
    {
        self.padata = padata.into();
        self
    }

    #[must_use]
    /// Add additional tickets to the TGS request body.
    #[inline]
    pub fn with_additional_tickets<P>(mut self, additional_tickets: P) -> Self
    where
        P: Into<Vec<rasn_kerberos::Ticket>>,
    {
        self.additional_tickets = additional_tickets.into();
        self
    }

    #[must_use]
    /// Add the TGS renewal flags used for renewing an existing ticket.
    #[inline]
    pub const fn with_renewal(mut self) -> Self {
        self.kdc_option_bits = renewal_kdc_option_bits(self.kdc_option_bits);
        self
    }
}

/// Options for constructing a client AP-REQ.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ApReq {
    /// Raw AP option bit string.
    pub ap_option_bits: u32,
    /// Optional authenticator checksum.
    pub checksum: Option<rasn_kerberos::Checksum>,
    /// Optional client-selected subkey.
    pub subkey: Option<EncryptionKey>,
    /// Optional client sequence number.
    pub sequence_number: Option<u32>,
}

impl ApReq {
    #[must_use]
    /// Construct AP-REQ options with no flags or optional authenticator fields.
    #[inline]
    pub const fn new() -> Self {
        Self {
            ap_option_bits: 0,
            checksum: None,
            subkey: None,
            sequence_number: None,
        }
    }

    #[must_use]
    /// Override AP-REQ option bits.
    #[inline]
    pub const fn with_ap_option_bits(mut self, ap_option_bits: u32) -> Self {
        self.ap_option_bits = ap_option_bits;
        self
    }

    #[must_use]
    /// Set or clear the authenticator checksum.
    #[inline]
    pub fn with_checksum(mut self, checksum: Option<rasn_kerberos::Checksum>) -> Self {
        self.checksum = checksum;
        self
    }

    #[must_use]
    /// Set or clear the client-selected subkey.
    #[inline]
    pub fn with_subkey(mut self, subkey: Option<EncryptionKey>) -> Self {
        self.subkey = subkey;
        self
    }

    #[must_use]
    /// Set or clear the client sequence number.
    #[inline]
    pub const fn with_sequence_number(mut self, sequence_number: Option<u32>) -> Self {
        self.sequence_number = sequence_number;
        self
    }
}

impl Default for ApReq {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
