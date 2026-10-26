//! Kerberos message/type wrappers that need gokrb5-compatible DER behavior.

use core::{
    str::{self, Utf8Error},
    time::Duration,
};
use std::time::{SystemTime, UNIX_EPOCH};

use rasn::{
    AsnType, Decode, Decoder as _, Encode, Encoder as _, der,
    types::{Integer, OctetString},
};

/// Kerberos protocol version number carried in every message (RFC 4120).
const KRB5_PVNO: i32 = 5;
/// `msg-type` of a KRB-ERROR message (RFC 4120 section 5.9.1).
const KRB_ERROR_MSG_TYPE: i32 = 30;

/// RFC 4120 `EncryptedData` with a signed/raw ASN.1 `kvno`.
///
/// `rasn_kerberos::EncryptedData` models `kvno` as `u32`, which is appropriate
/// for normal Kerberos messages but normalizes gokrb5's signed edge-case
/// fixtures on re-encode. This wrapper preserves those DER fixtures exactly.
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
#[non_exhaustive]
pub struct EncryptedData {
    /// Identifies the encryption algorithm used to encipher `cipher`.
    #[rasn(tag(explicit(0)))]
    pub etype: i32,
    /// Key version number, kept as ASN.1 INTEGER for gokrb5 signed edge cases.
    #[rasn(tag(explicit(1)))]
    pub kvno: Option<Integer>,
    /// Enciphered text.
    #[rasn(tag(explicit(2)))]
    pub cipher: OctetString,
}

/// MS-SFU `PA-FOR-USER` padata value used by `S4U2Self`.
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
#[non_exhaustive]
pub struct PaForUser {
    /// User principal name.
    #[rasn(tag(explicit(0)))]
    pub user_name: rasn_kerberos::PrincipalName,
    /// User realm.
    #[rasn(tag(explicit(1)))]
    pub user_realm: rasn_kerberos::Realm,
    /// Checksum over the MS-SFU S4U byte array.
    #[rasn(tag(explicit(2)))]
    pub cksum: rasn_kerberos::Checksum,
    /// Authentication package name, normally `Kerberos`.
    #[rasn(tag(explicit(3)))]
    pub auth_package: rasn_kerberos::KerberosString,
}

/// MS-KILE `PA-PAC-OPTIONS` padata value.
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
#[non_exhaustive]
pub struct PaPacOptions {
    /// PAC option flags.
    #[rasn(tag(explicit(0)))]
    pub flags: rasn_kerberos::KerberosFlags,
}

/// RFC 6806 `PA-REQ-ENC-PA-REP` encrypted padata value.
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
#[non_exhaustive]
pub struct PaReqEncPaRep {
    /// Checksum type used to protect the original AS-REQ bytes.
    #[rasn(tag(explicit(0)))]
    pub checksum_type: i32,
    /// Checksum over the DER-encoded AS-REQ.
    #[rasn(tag(explicit(1)))]
    pub checksum: OctetString,
}

impl PaForUser {
    /// Decode a DER-encoded `PA-FOR-USER` value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Decode`] when `bytes` is not a DER `PA-FOR-USER`.
    #[inline]
    pub fn decode_der(bytes: &[u8]) -> Result<Self, Error> {
        decode_der("PA-FOR-USER", bytes)
    }

    /// Encode the value as DER.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Encode`] when the DER encoder fails.
    #[inline]
    pub fn encode_der(&self) -> Result<Vec<u8>, Error> {
        encode_der("PA-FOR-USER", self)
    }
}

impl PaPacOptions {
    #[must_use]
    /// Build PAC options from a raw `KerberosFlags` bit mask.
    #[inline]
    pub fn from_bits(bits: u32) -> Self {
        Self {
            flags: rasn_kerberos::KerberosFlags::from_slice(&bits.to_be_bytes()),
        }
    }

    #[must_use]
    /// Return the first 32 PAC option bits as a raw bit mask.
    #[inline]
    pub fn bits(&self) -> u32 {
        let raw = self.flags.as_raw_slice();
        u32::from_be_bytes([
            raw.first().copied().unwrap_or_default(),
            raw.get(1).copied().unwrap_or_default(),
            raw.get(2).copied().unwrap_or_default(),
            raw.get(3).copied().unwrap_or_default(),
        ])
    }

    /// Decode a DER-encoded `PA-PAC-OPTIONS` value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Decode`] when `bytes` is not a DER `PA-PAC-OPTIONS`.
    #[inline]
    pub fn decode_der(bytes: &[u8]) -> Result<Self, Error> {
        decode_der("PA-PAC-OPTIONS", bytes)
    }

    /// Encode the value as DER.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Encode`] when the DER encoder fails.
    #[inline]
    pub fn encode_der(&self) -> Result<Vec<u8>, Error> {
        encode_der("PA-PAC-OPTIONS", self)
    }
}

impl PaReqEncPaRep {
    /// Creates a `PaReqEncPaRep` from its required fields.
    #[must_use]
    #[inline]
    pub const fn new(checksum_type: i32, checksum: OctetString) -> Self {
        Self {
            checksum_type,
            checksum,
        }
    }

    /// Build the value from a Kerberos checksum.
    #[inline]
    pub fn from_checksum(checksum: rasn_kerberos::Checksum) -> Self {
        Self {
            checksum_type: checksum.r#type,
            checksum: checksum.checksum,
        }
    }

    /// Convert the value to a Kerberos checksum.
    #[inline]
    pub fn to_checksum(&self) -> rasn_kerberos::Checksum {
        rasn_kerberos::Checksum {
            r#type: self.checksum_type,
            checksum: self.checksum.clone(),
        }
    }

    /// Decode a DER-encoded `PA-REQ-ENC-PA-REP` value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Decode`] when `bytes` is not a DER `PA-REQ-ENC-PA-REP`.
    #[inline]
    pub fn decode_der(bytes: &[u8]) -> Result<Self, Error> {
        decode_der("PA-REQ-ENC-PA-REP", bytes)
    }

    /// Encode the value as DER.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Encode`] when the DER encoder fails.
    #[inline]
    pub fn encode_der(&self) -> Result<Vec<u8>, Error> {
        encode_der("PA-REQ-ENC-PA-REP", self)
    }
}

impl EncryptedData {
    /// Creates a `EncryptedData` from its required fields.
    #[must_use]
    #[inline]
    pub const fn new(etype: i32, cipher: OctetString) -> Self {
        Self {
            etype,
            kvno: None,
            cipher,
        }
    }
    /// Sets `kvno`, preserving the other fields.
    #[must_use]
    #[inline]
    pub fn with_kvno(mut self, value: Option<Integer>) -> Self {
        self.kvno = value;
        self
    }

    /// Build the preserving wrapper from the upstream rasn Kerberos type.
    #[inline]
    pub fn from_rasn(value: rasn_kerberos::EncryptedData) -> Self {
        Self {
            etype: value.etype,
            kvno: value.kvno.map(Integer::from),
            cipher: value.cipher,
        }
    }

    /// Convert to the upstream rasn Kerberos type when `kvno` is a valid `u32`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KvnoOutOfRange`] when `kvno` is negative or does not fit
    /// a `u32`.
    #[inline]
    pub fn try_to_rasn(&self) -> Result<rasn_kerberos::EncryptedData, Error> {
        Ok(rasn_kerberos::EncryptedData {
            etype: self.etype,
            kvno: self.kvno_u32()?,
            cipher: self.cipher.clone(),
        })
    }

    /// Return `kvno` as a signed 32-bit value, matching gokrb5's `int` tests.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KvnoOutOfRange`] when `kvno` does not fit an `i32`.
    #[inline]
    pub fn kvno_i32(&self) -> Result<Option<i32>, Error> {
        self.kvno
            .as_ref()
            .map(|kvno| {
                i32::try_from(kvno)
                    .ok()
                    .ok_or_else(|| Error::KvnoOutOfRange {
                        target: "i32",
                        kvno: kvno.clone(),
                    })
            })
            .transpose()
    }

    /// Return `kvno` as the normal non-negative Kerberos `u32` representation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KvnoOutOfRange`] when `kvno` is negative or does not fit
    /// a `u32`.
    #[inline]
    pub fn kvno_u32(&self) -> Result<Option<u32>, Error> {
        self.kvno
            .as_ref()
            .map(|kvno| {
                u32::try_from(kvno)
                    .ok()
                    .ok_or_else(|| Error::KvnoOutOfRange {
                        target: "u32",
                        kvno: kvno.clone(),
                    })
            })
            .transpose()
    }
}

/// Principal summary decoded from a Kerberos message.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct PrincipalNameInfo {
    /// Principal realm.
    pub realm: String,
    /// Kerberos name type. Name type is advisory and not used for matching.
    pub name_type: i32,
    /// Principal name components.
    pub components: Vec<String>,
}

impl PrincipalNameInfo {
    #[must_use]
    /// Principal components joined with `/`.
    #[inline]
    pub fn name(&self) -> String {
        self.components.join("/")
    }
}

/// Decoded KRB-ERROR fields useful for diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct KrbErrorInfo {
    /// Client time, when present.
    pub ctime: Option<SystemTime>,
    /// Client microseconds, when present.
    pub cusec: Option<u32>,
    /// KDC/server time.
    pub stime: SystemTime,
    /// KDC/server microseconds.
    pub susec: u32,
    /// Kerberos error code.
    pub error_code: i32,
    /// Client principal carried by the error, when present.
    pub client: Option<PrincipalNameInfo>,
    /// Service principal that issued the error.
    pub service: PrincipalNameInfo,
    /// Optional human-readable error text.
    pub e_text: Option<String>,
    /// Raw e-data bytes, when present.
    pub e_data: Option<Vec<u8>>,
}

impl KrbErrorInfo {
    /// Decode and validate a DER-encoded KRB-ERROR.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Decode`] when `bytes` is not a DER KRB-ERROR, and the
    /// errors of [`Self::from_rasn`].
    #[inline]
    pub fn decode_der(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_rasn(&decode_der("KRB-ERROR", bytes)?)
    }

    /// Build a diagnostic summary from a decoded KRB-ERROR.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidMessage`] when the protocol version or message type
    /// is wrong, [`Error::IntegerOutOfRange`] when `cusec` or `susec` does not fit
    /// a `u32`, [`Error::InvalidString`] when a name, realm or `e-text` is not
    /// UTF-8, and [`Error::TimeOverflow`] when `ctime` or `stime` does not fit a
    /// `SystemTime`.
    #[inline]
    pub fn from_rasn(error: &rasn_kerberos::KrbError) -> Result<Self, Error> {
        validate_integer("pvno", &error.pvno, KRB5_PVNO)?;
        validate_integer("msg-type", &error.msg_type, KRB_ERROR_MSG_TYPE)?;
        let client = match (&error.crealm, &error.cname) {
            (Some(realm), Some(name)) => Some(principal_from_parts(realm, name)?),
            _ => None,
        };
        Ok(Self {
            ctime: error
                .ctime
                .as_ref()
                .map(system_time_from_kerberos_time)
                .transpose()?,
            cusec: error
                .cusec
                .as_ref()
                .map(|value| integer_to_u32("cusec", value))
                .transpose()?,
            stime: system_time_from_kerberos_time(&error.stime)?,
            susec: integer_to_u32("susec", &error.susec)?,
            error_code: error.error_code,
            client,
            service: principal_from_parts(&error.realm, &error.sname)?,
            e_text: error
                .e_text
                .as_ref()
                .map(kerberos_string_to_string)
                .transpose()?,
            e_data: error.e_data.as_ref().map(|data| data.as_ref().to_vec()),
        })
    }
}

/// Decode a DER value with a typed error.
///
/// # Errors
///
/// Returns [`Error::Decode`] naming `target` when `bytes` is not valid DER for
/// `T`.
#[inline]
pub fn decode_der<T>(target: &'static str, bytes: &[u8]) -> Result<T, Error>
where
    T: Decode,
{
    der::decode(bytes).map_err(|source| Error::Decode {
        target,
        message: source.to_string(),
    })
}

/// Encode a value to DER with a typed error.
///
/// # Errors
///
/// Returns [`Error::Encode`] naming `target` when the DER encoder fails.
#[inline]
pub fn encode_der<T>(target: &'static str, value: &T) -> Result<Vec<u8>, Error>
where
    T: Encode,
{
    der::encode(value).map_err(|source| Error::Encode {
        target,
        message: source.to_string(),
    })
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            not(test)
        ),
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            not(test)
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            not(test)
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            not(test)
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            not(test)
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            not(test)
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::error_impl_error,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
/// Errors from Kerberos message helpers.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// ASN.1 DER decode failed.
    #[error("failed to decode {target}: {message}")]
    Decode {
        /// Decoded type name.
        target: &'static str,
        /// Decoder error text.
        message: String,
    },

    /// ASN.1 DER encode failed.
    #[error("failed to encode {target}: {message}")]
    Encode {
        /// Encoded type name.
        target: &'static str,
        /// Encoder error text.
        message: String,
    },

    /// ASN.1 string value was not valid UTF-8.
    #[error("invalid Kerberos string: {0}")]
    InvalidString(#[from] Utf8Error),

    /// A Kerberos integer could not fit in the expected Rust type.
    #[error("integer field {field} is out of range: {value}")]
    IntegerOutOfRange {
        /// Field name.
        field: &'static str,
        /// Integer value.
        value: String,
    },

    /// Message field did not contain the expected value.
    #[error("invalid {field}: expected {expected}, got {actual}")]
    InvalidMessage {
        /// Field name.
        field: &'static str,
        /// Expected value.
        expected: i32,
        /// Actual value.
        actual: String,
    },

    /// The ASN.1 INTEGER `kvno` cannot be represented as the requested type.
    #[error("encrypted data kvno cannot be represented as {target}: {kvno:?}")]
    KvnoOutOfRange {
        /// Target integer representation.
        target: &'static str,
        /// Original ASN.1 INTEGER value.
        kvno: Integer,
    },

    /// A Kerberos time could not be represented as a `SystemTime`.
    #[error("Kerberos time overflows SystemTime")]
    TimeOverflow,
}

/// Check that a decoded protocol integer such as `pvno` equals `expected`.
///
/// # Errors
///
/// Returns [`Error::InvalidMessage`] naming `field` when the value differs.
fn validate_integer(field: &'static str, actual: &Integer, expected: i32) -> Result<(), Error> {
    if actual != &Integer::from(expected) {
        return Err(Error::InvalidMessage {
            field,
            expected,
            actual: actual.to_string(),
        });
    }
    Ok(())
}

/// Convert a decoded ASN.1 integer field to `u32`.
///
/// # Errors
///
/// Returns [`Error::IntegerOutOfRange`] naming `field` when the value is
/// negative or does not fit a `u32`.
fn integer_to_u32(field: &'static str, value: &Integer) -> Result<u32, Error> {
    u32::try_from(value)
        .ok()
        .ok_or_else(|| Error::IntegerOutOfRange {
            field,
            value: value.to_string(),
        })
}

/// Build a principal summary from a Kerberos realm and principal name.
///
/// # Errors
///
/// Returns [`Error::InvalidString`] when the realm or a name component is not
/// UTF-8.
fn principal_from_parts(
    realm: &rasn_kerberos::Realm,
    name: &rasn_kerberos::PrincipalName,
) -> Result<PrincipalNameInfo, Error> {
    Ok(PrincipalNameInfo {
        realm: kerberos_string_to_string(realm)?,
        name_type: name.r#type,
        components: name
            .string
            .iter()
            .map(kerberos_string_to_string)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

/// Convert a Kerberos string to an owned UTF-8 string.
///
/// # Errors
///
/// Returns [`Error::InvalidString`] when the bytes are not UTF-8.
fn kerberos_string_to_string(value: &rasn_kerberos::KerberosString) -> Result<String, Error> {
    Ok(str::from_utf8(value.as_bytes())?.to_owned())
}

/// Convert a Kerberos time to a `SystemTime`, keeping sub-second precision.
///
/// # Errors
///
/// Returns [`Error::TimeOverflow`] when the time is outside the `SystemTime`
/// range.
fn system_time_from_kerberos_time(time: &rasn_kerberos::KerberosTime) -> Result<SystemTime, Error> {
    let seconds = time.0.timestamp();
    let nanos = time.0.timestamp_subsec_nanos();
    match u64::try_from(seconds) {
        Ok(after_epoch) => UNIX_EPOCH
            .checked_add(Duration::new(after_epoch, nanos))
            .ok_or(Error::TimeOverflow),
        Err(_before_epoch) => UNIX_EPOCH
            .checked_sub(Duration::new(seconds.unsigned_abs(), nanos))
            .ok_or(Error::TimeOverflow),
    }
}
