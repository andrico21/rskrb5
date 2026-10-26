//! RFC 3244 password-change protocol helpers.

use rasn::{
    AsnType, Decode, Decoder as _, Encode, Encoder as _, der,
    types::{Integer, OctetString},
};

pub use crate::krb_priv::{
    EncKrbPrivPartOptions, KRB_PRIV_ENCPART_USAGE, KRB_PRIV_MSG_TYPE, KRB_PRIV_PVNO, host_address,
    ipv4_host_address, ipv6_host_address,
};
use crate::{ap_rep, ap_req, crypto::KerberosEtype, keytab::EncryptionKey, krb_error, krb_priv};

/// Password-change request protocol version (`0xff80`).
pub const CHANGE_PASSWORD_REQUEST_VERSION: u16 = 0xff80;
/// Password-change reply protocol version.
pub const CHANGE_PASSWORD_REPLY_VERSION: u16 = 1;
/// Password change succeeded.
pub const KPASSWD_SUCCESS: u16 = 0;
/// Request was malformed.
pub const KPASSWD_MALFORMED: u16 = 1;
/// Server hard error.
pub const KPASSWD_HARDERROR: u16 = 2;
/// Authentication error.
pub const KPASSWD_AUTHERROR: u16 = 3;
/// Server soft error.
pub const KPASSWD_SOFTERROR: u16 = 4;
/// Access denied.
pub const KPASSWD_ACCESSDENIED: u16 = 5;
/// Bad protocol version.
pub const KPASSWD_BAD_VERSION: u16 = 6;
/// Initial ticket flag is required.
pub const KPASSWD_INITIAL_FLAG_NEEDED: u16 = 7;
/// The length of the kpasswd frame header: message length, protocol version
/// and AP-REQ/AP-REP length, two big-endian bytes each.
const HEADER_LEN: usize = 6;

/// Payload encrypted inside a Kerberos password-change request.
#[derive(AsnType, Clone, Debug, Decode, Encode, Eq, PartialEq)]
#[non_exhaustive]
pub struct ChangePasswdData {
    /// New password bytes.
    #[rasn(tag(explicit(0)))]
    pub new_passwd: OctetString,
    /// Optional target principal name.
    #[rasn(tag(explicit(1)))]
    pub targ_name: Option<rasn_kerberos::PrincipalName>,
    /// Optional target realm.
    #[rasn(tag(explicit(2)))]
    pub targ_realm: Option<rasn_kerberos::Realm>,
}

impl ChangePasswdData {
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
            clippy::impl_trait_in_params,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    /// Create password-change data for the authenticated principal.
    #[inline]
    pub fn new(new_passwd: impl AsRef<[u8]>) -> Self {
        Self {
            new_passwd: new_passwd.as_ref().to_vec().into(),
            targ_name: None,
            targ_realm: None,
        }
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
            clippy::impl_trait_in_params,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    /// Create password-change data for an explicit target principal.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKerberosString`] when a name component or the
    /// realm is not a valid Kerberos string.
    #[inline]
    pub fn for_target<I, S>(
        new_passwd: impl AsRef<[u8]>,
        name_type: i32,
        components: I,
        realm: &str,
    ) -> Result<Self, Error>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Ok(Self {
            new_passwd: new_passwd.as_ref().to_vec().into(),
            targ_name: Some(principal_name(name_type, components)?),
            targ_realm: Some(kerberos_string(realm)?),
        })
    }

    /// Decode DER-encoded password-change data.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Decode`] when `bytes` is not DER `ChangePasswdData`.
    #[inline]
    pub fn decode_der(bytes: &[u8]) -> Result<Self, Error> {
        decode("ChangePasswdData", bytes)
    }

    /// Encode password-change data using DER.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Encode`] when the DER encoder fails.
    #[inline]
    pub fn encode_der(&self) -> Result<Vec<u8>, Error> {
        encode("ChangePasswdData", self)
    }
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
        clippy::impl_trait_in_params,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
/// Build an unencrypted KRB-PRIV part around application data.
#[inline]
pub fn build_enc_krb_priv_part(
    user_data: impl AsRef<[u8]>,
    options: EncKrbPrivPartOptions,
) -> rasn_kerberos::EncKrbPrivPart {
    krb_priv::build_enc_krb_priv_part(user_data, options)
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
        clippy::impl_trait_in_params,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
/// Build a KRB-PRIV message using a caller-supplied confounder.
///
/// # Errors
///
/// Returns [`Error::UnsupportedEtype`] for a key whose enctype is not
/// implemented, and [`Error::Encode`] or [`Error::Crypto`] when encoding or
/// encrypting the part fails.
#[inline]
pub fn build_krb_priv_with_confounder(
    user_data: impl AsRef<[u8]>,
    options: EncKrbPrivPartOptions,
    key: &EncryptionKey,
    confounder: &[u8],
) -> Result<rasn_kerberos::KrbPriv, Error> {
    krb_priv::build_krb_priv_with_confounder(user_data, options, key, None, confounder)
        .map_err(krb_priv_error)
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
        clippy::impl_trait_in_params,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
/// Build a KRB-PRIV message using a random confounder.
///
/// # Errors
///
/// Returns [`Error::UnsupportedEtype`] for a key whose enctype is not
/// implemented, and [`Error::Encode`] or [`Error::Crypto`] when generating the
/// confounder, encoding or encrypting the part fails.
#[inline]
pub fn build_krb_priv(
    user_data: impl AsRef<[u8]>,
    options: EncKrbPrivPartOptions,
    key: &EncryptionKey,
) -> Result<rasn_kerberos::KrbPriv, Error> {
    krb_priv::build_krb_priv(user_data, options, key, None).map_err(krb_priv_error)
}

/// Decode and validate a DER-encoded KRB-PRIV message.
///
/// # Errors
///
/// Returns [`Error::Decode`] when `bytes` is not a DER KRB-PRIV, and
/// [`Error::InvalidKerberosMessage`] when its protocol version or message type
/// is wrong.
#[inline]
pub fn decode_krb_priv(bytes: &[u8]) -> Result<rasn_kerberos::KrbPriv, Error> {
    krb_priv::decode_krb_priv(bytes).map_err(krb_priv_error)
}

/// Encode a KRB-PRIV message as DER.
///
/// # Errors
///
/// Returns [`Error::Encode`] when the DER encoder fails.
#[inline]
pub fn encode_krb_priv(krb_priv: &rasn_kerberos::KrbPriv) -> Result<Vec<u8>, Error> {
    krb_priv::encode_krb_priv(krb_priv).map_err(krb_priv_error)
}

/// Decode a DER-encoded `EncKrbPrivPart`.
///
/// # Errors
///
/// Returns [`Error::Decode`] when `bytes` is not a DER `EncKrbPrivPart`.
#[inline]
pub fn decode_enc_krb_priv_part(bytes: &[u8]) -> Result<rasn_kerberos::EncKrbPrivPart, Error> {
    krb_priv::decode_enc_krb_priv_part(bytes).map_err(krb_priv_error)
}

/// Decrypt and decode a KRB-PRIV encrypted part.
///
/// # Errors
///
/// Returns [`Error::KeyEtypeMismatch`] when the key's enctype differs from
/// the encrypted part's, [`Error::UnsupportedEtype`] for an enctype that is not
/// implemented, [`Error::Crypto`] when decryption fails, and [`Error::Decode`]
/// when the plaintext is not a DER `EncKrbPrivPart`.
#[inline]
pub fn decrypt_krb_priv_enc_part(
    krb_priv: &rasn_kerberos::KrbPriv,
    key: &EncryptionKey,
) -> Result<rasn_kerberos::EncKrbPrivPart, Error> {
    krb_priv::decrypt_krb_priv_enc_part(krb_priv, key).map_err(krb_priv_error)
}

/// Complete password-change request assembled for transport.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct BuiltChangePasswordRequest {
    /// Framed request message.
    pub request: Request,
    /// DER-encoded kpasswd request frame.
    pub der: Vec<u8>,
    /// Reply key used for the request subkey and KRB-PRIV encryption.
    pub reply_key: EncryptionKey,
}

/// Options for constructing a full kpasswd request message.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ChangePasswdMessageOptions {
    /// Authenticator and KRB-PRIV timestamp.
    pub timestamp: rasn_kerberos::KerberosTime,
    /// Authenticator and KRB-PRIV microseconds.
    pub cusec: u32,
    /// Authenticator and KRB-PRIV sequence number.
    pub sequence_number: u32,
    /// Sender address used in KRB-PRIV encrypted part.
    pub sender_address: rasn_kerberos::HostAddress,
    /// Optional recipient address used in KRB-PRIV encrypted part.
    pub recipient_address: Option<rasn_kerberos::HostAddress>,
}

impl ChangePasswdMessageOptions {
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
            clippy::missing_const_for_fn,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    /// Construct options with the required authenticator timestamp, microseconds,
    /// sequence number, and sender address.
    #[inline]
    pub fn new(
        timestamp: rasn_kerberos::KerberosTime,
        cusec: u32,
        sequence_number: u32,
        sender_address: rasn_kerberos::HostAddress,
    ) -> Self {
        Self {
            timestamp,
            cusec,
            sequence_number,
            sender_address,
            recipient_address: None,
        }
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
            clippy::return_self_not_must_use,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    /// Set the optional recipient address.
    #[inline]
    pub fn with_recipient_address(mut self, recipient_address: rasn_kerberos::HostAddress) -> Self {
        self.recipient_address = Some(recipient_address);
        self
    }
}

/// Password-change request frame containing AP-REQ and KRB-PRIV messages.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Request {
    /// AP-REQ authenticating the password-change request.
    pub ap_req: rasn_kerberos::ApReq,
    /// KRB-PRIV carrying encrypted `ChangePasswdData`.
    pub krb_priv: rasn_kerberos::KrbPriv,
}

impl Request {
    /// Parse a password-change request frame.
    ///
    /// # Errors
    ///
    /// Returns the frame header errors ([`Error::FrameTooShort`],
    /// [`Error::InvalidMessageLength`], [`Error::TruncatedFrame`]),
    /// [`Error::InvalidRequestVersion`] for a version other than
    /// [`CHANGE_PASSWORD_REQUEST_VERSION`], [`Error::InvalidApReqLength`] when
    /// the AP-REQ length leaves no room for the AP-REQ or the KRB-PRIV, and the
    /// decode errors of either message.
    #[inline]
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let frame = parse_header(bytes)?;
        if frame.version != CHANGE_PASSWORD_REQUEST_VERSION {
            return Err(Error::InvalidRequestVersion(frame.version));
        }

        let ap_req_end = usize::from(frame.payload_length);
        let invalid_length = Error::InvalidApReqLength {
            ap_req_length: frame.payload_length,
            body_length: frame.body.len(),
        };
        if ap_req_end == 0 || ap_req_end >= frame.body.len() {
            return Err(invalid_length);
        }
        let (ap_req_bytes, krb_priv_bytes) = frame
            .body
            .split_at_checked(ap_req_end)
            .ok_or(invalid_length)?;

        let ap_req = ap_req::decode_ap_req(ap_req_bytes).map_err(ap_req_error)?;
        let krb_priv = decode_krb_priv(krb_priv_bytes)?;
        Ok(Self { ap_req, krb_priv })
    }

    /// Encode a password-change request frame.
    ///
    /// # Errors
    ///
    /// Returns the encode errors of either message,
    /// [`Error::ApReqTooLarge`] when the AP-REQ does not fit the 16-bit length
    /// field, and [`Error::FrameTooLarge`] when the whole frame does not.
    #[inline]
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let ap_req = ap_req::encode_ap_req(&self.ap_req).map_err(ap_req_error)?;
        let krb_priv = encode_krb_priv(&self.krb_priv)?;
        let Ok(ap_req_length) = u16::try_from(ap_req.len()) else {
            return Err(Error::ApReqTooLarge {
                actual: ap_req.len(),
            });
        };

        // Saturating: a total past `usize::MAX` is past `u16::MAX` too, and is
        // refused as too large just below.
        let message_length = HEADER_LEN
            .saturating_add(ap_req.len())
            .saturating_add(krb_priv.len());
        let Ok(wire_length) = u16::try_from(message_length) else {
            return Err(Error::FrameTooLarge {
                actual: message_length,
            });
        };

        let mut frame = Vec::with_capacity(message_length);
        frame.extend_from_slice(&wire_length.to_be_bytes());
        frame.extend_from_slice(&CHANGE_PASSWORD_REQUEST_VERSION.to_be_bytes());
        frame.extend_from_slice(&ap_req_length.to_be_bytes());
        frame.extend_from_slice(&ap_req);
        frame.extend_from_slice(&krb_priv);
        Ok(frame)
    }
}

/// Build a complete kpasswd request frame using a caller-supplied AP-REQ,
/// reply key, request payload, and KRB-PRIV confounder.
///
/// # Errors
///
/// Returns the [`ChangePasswdData::encode_der`] and
/// [`build_krb_priv_with_confounder`] errors, and the [`Request::encode`]
/// errors for the frame.
#[inline]
pub fn build_change_password_request_with_confounder(
    ap_req: rasn_kerberos::ApReq,
    change_data: &ChangePasswdData,
    reply_key: EncryptionKey,
    options: EncKrbPrivPartOptions,
    confounder: &[u8],
) -> Result<BuiltChangePasswordRequest, Error> {
    let krb_priv =
        build_krb_priv_with_confounder(change_data.encode_der()?, options, &reply_key, confounder)?;
    build_change_password_request_from_parts(ap_req, krb_priv, reply_key)
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
        clippy::too_many_arguments,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
/// Build a full kpasswd request message using a service ticket, explicit context,
/// and explicit confounders for AP-REQ and KRB-PRIV encryption.
///
/// # Errors
///
/// Returns [`Error::InvalidKerberosString`] for a client realm that is not a
/// valid Kerberos string, the AP-REQ build errors mapped onto [`Error`], and
/// the [`build_change_password_request_with_confounder`] errors.
#[inline]
pub fn build_change_password_message_with_confounders(
    client_principal: rasn_kerberos::PrincipalName,
    client_realm: &str,
    change_data: &ChangePasswdData,
    service_ticket: rasn_kerberos::Ticket,
    session_key: &EncryptionKey,
    options: ChangePasswdMessageOptions,
    reply_key: EncryptionKey,
    ap_req_confounder: &[u8],
    krb_priv_confounder: &[u8],
) -> Result<BuiltChangePasswordRequest, Error> {
    let mut krb_priv_options = EncKrbPrivPartOptions::new(options.sender_address.clone())
        .with_timestamp(options.timestamp.clone(), options.cusec)
        .with_sequence_number(options.sequence_number);
    if let Some(recipient_address) = options.recipient_address {
        krb_priv_options = krb_priv_options.with_recipient_address(recipient_address);
    }

    let authenticator = rasn_kerberos::Authenticator {
        authenticator_vno: Integer::from(5_i32),
        crealm: kerberos_string(client_realm)?,
        cname: client_principal,
        cksum: None,
        cusec: Integer::from(options.cusec),
        ctime: options.timestamp,
        subkey: Some(encryption_key_to_rasn(&reply_key)),
        seq_number: Some(options.sequence_number),
        authorization_data: None,
    };
    let authenticator_usage = ap_req::authenticator_usage_for_ticket(&service_ticket);
    let ap_req_kvno = service_ticket.enc_part.kvno;
    let ap_req = ap_req::build_ap_req_with_confounder(
        service_ticket,
        ap_req::ap_options_from_bits(0),
        &authenticator,
        session_key,
        authenticator_usage,
        ap_req_kvno,
        ap_req_confounder,
    )
    .map_err(ap_req_error)?;

    build_change_password_request_with_confounder(
        ap_req,
        change_data,
        reply_key,
        krb_priv_options,
        krb_priv_confounder,
    )
}

/// Build a full kpasswd request message using generated subkey and confounders.
///
/// # Errors
///
/// Returns [`Error::UnsupportedEtype`] for a session key whose enctype is not
/// implemented, [`Error::Crypto`] when the random subkey or confounders cannot
/// be generated, and the
/// [`build_change_password_message_with_confounders`] errors.
#[inline]
pub fn build_change_password_message(
    client_principal: rasn_kerberos::PrincipalName,
    client_realm: &str,
    change_data: &ChangePasswdData,
    service_ticket: rasn_kerberos::Ticket,
    session_key: &EncryptionKey,
    options: ChangePasswdMessageOptions,
) -> Result<BuiltChangePasswordRequest, Error> {
    let etype = KerberosEtype::from_etype_id(session_key.etype)
        .ok_or(Error::UnsupportedEtype(session_key.etype))?;
    let reply_key = EncryptionKey {
        etype: session_key.etype,
        value: random_key_material(etype.key_len())?,
    };
    let ap_req_confounder = random_key_material(etype.confounder_len())?;
    let krb_priv_confounder = random_key_material(etype.confounder_len())?;

    build_change_password_message_with_confounders(
        client_principal,
        client_realm,
        change_data,
        service_ticket,
        session_key,
        options,
        reply_key,
        &ap_req_confounder,
        &krb_priv_confounder,
    )
}

/// Frame an AP-REQ and a KRB-PRIV into a request, keeping the reply key.
///
/// # Errors
///
/// Returns the [`Request::encode`] errors.
fn build_change_password_request_from_parts(
    ap_req: rasn_kerberos::ApReq,
    krb_priv: rasn_kerberos::KrbPriv,
    reply_key: EncryptionKey,
) -> Result<BuiltChangePasswordRequest, Error> {
    let request = Request { ap_req, krb_priv };
    let der = request.encode()?;

    Ok(BuiltChangePasswordRequest {
        request,
        der,
        reply_key,
    })
}

/// Build a complete kpasswd request frame using a caller-supplied AP-REQ,
/// reply key, request payload, and random KRB-PRIV confounder.
///
/// # Errors
///
/// Returns the [`ChangePasswdData::encode_der`] and [`build_krb_priv`]
/// errors, and the [`Request::encode`] errors for the frame.
#[inline]
pub fn build_change_password_request(
    ap_req: rasn_kerberos::ApReq,
    change_data: &ChangePasswdData,
    reply_key: EncryptionKey,
    options: EncKrbPrivPartOptions,
) -> Result<BuiltChangePasswordRequest, Error> {
    let krb_priv = build_krb_priv(change_data.encode_der()?, options, &reply_key)?;
    build_change_password_request_from_parts(ap_req, krb_priv, reply_key)
}

/// Parsed RFC 3244-style password-change reply frame.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Reply {
    /// Total message length from the two-byte frame prefix.
    pub message_length: u16,
    /// Protocol version from the reply frame.
    pub version: u16,
    /// DER byte length of the AP-REP section, or zero for a KRB-ERROR reply.
    pub ap_rep_length: u16,
    /// Parsed AP-REP section for successful protocol replies.
    pub ap_rep: Option<rasn_kerberos::ApRep>,
    /// Parsed KRB-PRIV section for successful protocol replies.
    pub krb_priv: Option<rasn_kerberos::KrbPriv>,
    /// Parsed KRB-ERROR section for error replies.
    pub krb_error: Option<rasn_kerberos::KrbError>,
    /// Parsed password-change result from KRB-ERROR `e-data`.
    pub result: Option<ChangePasswordResult>,
}

impl Reply {
    /// Parse a password-change reply frame.
    ///
    /// # Errors
    ///
    /// Returns the frame header errors ([`Error::FrameTooShort`],
    /// [`Error::InvalidMessageLength`], [`Error::TruncatedFrame`]),
    /// [`Error::InvalidReplyVersion`] for a version other than
    /// [`CHANGE_PASSWORD_REPLY_VERSION`], [`Error::InvalidApRepLength`] when the
    /// AP-REP length leaves no room for the KRB-PRIV, the decode errors of the
    /// KRB-ERROR, AP-REP or KRB-PRIV, and the [`ChangePasswordResult::parse`]
    /// error of KRB-ERROR e-data.
    #[inline]
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let frame = parse_header(bytes)?;
        if frame.version != CHANGE_PASSWORD_REPLY_VERSION {
            return Err(Error::InvalidReplyVersion(frame.version));
        }

        if frame.payload_length == 0 {
            let krb_error = krb_error::decode_krb_error(frame.body).map_err(krb_error_error)?;
            let result = krb_error
                .e_data
                .as_ref()
                .map(|data| ChangePasswordResult::parse(data.as_ref()))
                .transpose()?;
            return Ok(Self {
                message_length: frame.message_length,
                version: frame.version,
                ap_rep_length: frame.payload_length,
                ap_rep: None,
                krb_priv: None,
                krb_error: Some(krb_error),
                result,
            });
        }

        let ap_rep_end = usize::from(frame.payload_length);
        let invalid_length = Error::InvalidApRepLength {
            ap_rep_length: frame.payload_length,
            body_length: frame.body.len(),
        };
        if ap_rep_end >= frame.body.len() {
            return Err(invalid_length);
        }
        let (ap_rep_bytes, krb_priv_bytes) = frame
            .body
            .split_at_checked(ap_rep_end)
            .ok_or(invalid_length)?;

        let ap_rep = ap_rep::decode_ap_rep(ap_rep_bytes).map_err(ap_rep_error)?;
        let krb_priv = decode_krb_priv(krb_priv_bytes)?;

        Ok(Self {
            message_length: frame.message_length,
            version: frame.version,
            ap_rep_length: frame.payload_length,
            ap_rep: Some(ap_rep),
            krb_priv: Some(krb_priv),
            krb_error: None,
            result: None,
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
            clippy::missing_const_for_fn,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    /// Whether the reply carried KRB-ERROR instead of AP-REP/KRB-PRIV.
    #[inline]
    pub fn is_krb_error(&self) -> bool {
        self.krb_error.is_some()
    }

    /// Return the password-change result, decrypting KRB-PRIV when needed.
    ///
    /// A result parsed from a KRB-ERROR reply is unauthenticated: a success
    /// code there is rejected with [`Error::UnauthenticatedSuccess`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnauthenticatedSuccess`] as above,
    /// [`Error::MissingReplyResult`] for a KRB-ERROR reply without result data,
    /// [`Error::MissingKrbPriv`] for a reply without KRB-PRIV, the
    /// [`decrypt_krb_priv_enc_part`] errors, and the
    /// [`ChangePasswordResult::parse`] error of the decrypted data.
    #[inline]
    pub fn decrypt_result(&self, key: &EncryptionKey) -> Result<ChangePasswordResult, Error> {
        if let Some(result) = &self.result {
            // `result` is populated only from the unauthenticated KRB-ERROR
            // e-data branch; a success code there is not proof that the
            // password change happened.
            if result.is_success() {
                return Err(Error::UnauthenticatedSuccess);
            }
            return Ok(result.clone());
        }
        if self.krb_error.is_some() {
            return Err(Error::MissingReplyResult);
        }

        let krb_priv = self.krb_priv.as_ref().ok_or(Error::MissingKrbPriv)?;
        let enc_part = decrypt_krb_priv_enc_part(krb_priv, key)?;
        ChangePasswordResult::parse(enc_part.user_data.as_ref())
    }

    /// Re-encode this reply into a framed kpasswd response.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidErrorReplyPayload`] for a KRB-ERROR reply that
    /// also carries an AP-REP or KRB-PRIV, [`Error::MissingKrbError`],
    /// [`Error::MissingApRep`] or [`Error::MissingKrbPriv`] for a missing
    /// message, the encode errors of each message, and [`Error::FrameTooLarge`]
    /// when the AP-REP or the whole frame does not fit its 16-bit length field.
    #[inline]
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let (ap_rep_part, krb_priv_part, krb_error_part) = (
            self.ap_rep.as_ref(),
            self.krb_priv.as_ref(),
            self.krb_error.as_ref(),
        );

        if self.is_krb_error() {
            if ap_rep_part.is_some() || krb_priv_part.is_some() {
                return Err(Error::InvalidErrorReplyPayload);
            }
            let body = krb_error_part
                .map(|message| krb_error::encode_krb_error(message).map_err(krb_error_error))
                .ok_or(Error::MissingKrbError)??;
            // Saturating: a total past `usize::MAX` is past `u16::MAX` too, and
            // is refused as too large just below.
            let frame_length = HEADER_LEN.saturating_add(body.len());
            let Ok(wire_length) = u16::try_from(frame_length) else {
                return Err(Error::FrameTooLarge {
                    actual: frame_length,
                });
            };

            let mut frame = Vec::with_capacity(frame_length);
            frame.extend_from_slice(&wire_length.to_be_bytes());
            frame.extend_from_slice(&CHANGE_PASSWORD_REPLY_VERSION.to_be_bytes());
            frame.extend_from_slice(&0_u16.to_be_bytes());
            frame.extend_from_slice(&body);
            return Ok(frame);
        }

        let ap_rep = ap_rep_part.ok_or(Error::MissingApRep)?;
        let krb_priv = krb_priv_part.ok_or(Error::MissingKrbPriv)?;
        let encoded_ap_rep = ap_rep::encode_ap_rep(ap_rep).map_err(ap_rep_error)?;
        let Ok(ap_rep_length) = u16::try_from(encoded_ap_rep.len()) else {
            return Err(Error::FrameTooLarge {
                actual: encoded_ap_rep.len(),
            });
        };
        let encoded_krb_priv = encode_krb_priv(krb_priv)?;

        // Saturating: a total past `usize::MAX` is past `u16::MAX` too, and is
        // refused as too large just below.
        let frame_length = HEADER_LEN
            .saturating_add(encoded_ap_rep.len())
            .saturating_add(encoded_krb_priv.len());
        let Ok(wire_length) = u16::try_from(frame_length) else {
            return Err(Error::FrameTooLarge {
                actual: frame_length,
            });
        };

        let mut frame = Vec::with_capacity(frame_length);
        frame.extend_from_slice(&wire_length.to_be_bytes());
        frame.extend_from_slice(&CHANGE_PASSWORD_REPLY_VERSION.to_be_bytes());
        frame.extend_from_slice(&ap_rep_length.to_be_bytes());
        frame.extend_from_slice(&encoded_ap_rep);
        frame.extend_from_slice(&encoded_krb_priv);
        Ok(frame)
    }
}

/// Cleartext password-change response code and text.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ChangePasswordResult {
    /// Result code from the first two bytes.
    pub code: u16,
    /// Result text from the remaining bytes.
    pub text: String,
    /// Result text as received, before lossy UTF-8 conversion.
    pub text_raw: Vec<u8>,
}

impl ChangePasswordResult {
    /// Parse a cleartext password-change response.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ResponseTooShort`] when `bytes` is shorter than the
    /// two-byte result code.
    #[inline]
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let [code_high, code_low, text @ ..] = bytes else {
            return Err(Error::ResponseTooShort {
                actual: bytes.len(),
            });
        };
        let text_raw = text.to_vec();
        Ok(Self {
            code: u16::from_be_bytes([*code_high, *code_low]),
            text: String::from_utf8_lossy(&text_raw).into_owned(),
            text_raw,
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
            clippy::missing_const_for_fn,
            clippy::must_use_candidate,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    /// Whether this result indicates a successful password change.
    #[inline]
    pub fn is_success(&self) -> bool {
        self.code == KPASSWD_SUCCESS
    }

    /// Return success or an error carrying the kpasswd failure code and text.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PasswordChangeFailed`] carrying the code and text when
    /// the code is not [`KPASSWD_SUCCESS`].
    #[inline]
    pub fn ensure_success(&self) -> Result<(), Error> {
        if self.is_success() {
            Ok(())
        } else {
            Err(Error::PasswordChangeFailed {
                code: self.code,
                text: self.text.clone(),
                text_raw: self.text_raw.clone(),
            })
        }
    }
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
        clippy::enum_variant_names,
        clippy::error_impl_error,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
/// kadmin message parsing errors.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The frame is too short to contain the kpasswd header.
    #[error("kadmin reply frame is too short: {actual} bytes")]
    FrameTooShort {
        /// Actual byte length.
        actual: usize,
    },
    /// The frame prefix length is smaller than the fixed kpasswd header.
    #[error("invalid kadmin reply message length: {0}")]
    InvalidMessageLength(u16),
    /// Kerberos message field did not contain the expected value.
    #[error("invalid {field}: expected {expected}, got {actual}")]
    InvalidKerberosMessage {
        /// Field name.
        field: &'static str,
        /// Expected value.
        expected: i32,
        /// Actual value.
        actual: String,
    },
    /// The frame prefix length exceeds the supplied byte slice.
    #[error("truncated kadmin reply frame: expected {expected} bytes, got {actual}")]
    TruncatedFrame {
        /// Expected frame byte length.
        expected: usize,
        /// Actual supplied byte length.
        actual: usize,
    },
    /// The reply protocol version is not supported.
    #[error("invalid kadmin reply protocol version: {0}")]
    InvalidReplyVersion(u16),
    /// The request protocol version is not supported.
    #[error("invalid kadmin request protocol version: {0:#06x}")]
    InvalidRequestVersion(u16),
    /// The AP-REQ length points outside the frame body.
    #[error("invalid kadmin AP-REQ length {ap_req_length} for body length {body_length}")]
    InvalidApReqLength {
        /// AP-REQ byte length from the frame header.
        ap_req_length: u16,
        /// Available frame body byte length.
        body_length: usize,
    },
    /// The AP-REP length points outside the frame body.
    #[error("invalid kadmin AP-REP length {ap_rep_length} for body length {body_length}")]
    InvalidApRepLength {
        /// AP-REP byte length from the frame header.
        ap_rep_length: u16,
        /// Available frame body byte length.
        body_length: usize,
    },
    /// The response data is too short to hold a result code.
    #[error("kadmin response data is too short: {actual} bytes")]
    ResponseTooShort {
        /// Actual response byte length.
        actual: usize,
    },
    /// A KRB-ERROR reply did not include kpasswd response data.
    #[error("kadmin reply does not contain response data")]
    MissingReplyResult,
    /// A KRB-ERROR reply carried a success result without authenticated
    /// provenance.
    #[error("kadmin success result is not authenticated")]
    UnauthenticatedSuccess,
    /// A non-error reply did not include a KRB-PRIV section.
    #[error("kadmin reply does not contain KRB-PRIV")]
    MissingKrbPriv,
    /// A failure reply did not include a KRB-ERROR section.
    #[error("kadmin reply does not contain KRB-ERROR")]
    MissingKrbError,
    /// A successful reply did not include an AP-REP section.
    #[error("kadmin reply does not contain AP-REP")]
    MissingApRep,
    /// A KRB-ERROR reply included AP-REP and/or KRB-PRIV payload fields.
    #[error("kadmin error reply cannot include AP-REP or KRB-PRIV")]
    InvalidErrorReplyPayload,
    /// The encrypted data etype is not implemented yet.
    #[error("unsupported encryption type: {0}")]
    UnsupportedEtype(i32),
    /// The supplied key etype did not match the encrypted KRB-PRIV etype.
    #[error(
        "key etype {key_etype} does not match KRB-PRIV encrypted data etype {encrypted_data_etype}"
    )]
    KeyEtypeMismatch {
        /// Supplied key encryption type.
        key_etype: i32,
        /// KRB-PRIV encrypted data encryption type.
        encrypted_data_etype: i32,
    },
    /// Cryptographic decrypt or integrity verification failed.
    #[error("kadmin crypto operation failed: {message}")]
    Crypto {
        /// Crypto error message.
        message: String,
    },
    /// kpasswd returned a non-success result code.
    #[error("kpasswd failed with code {code}: {text}")]
    PasswordChangeFailed {
        /// kpasswd result code.
        code: u16,
        /// kpasswd result text.
        text: String,
        /// kpasswd result text as received, before lossy UTF-8 conversion.
        text_raw: Vec<u8>,
    },
    /// DER decoding failed for a framed Kerberos message.
    #[error("{target} decode failed: {message}")]
    Decode {
        /// Kerberos message being decoded.
        target: &'static str,
        /// Decoder error.
        message: String,
    },
    /// DER encoding failed for a framed Kerberos message.
    #[error("{target} encode failed: {message}")]
    Encode {
        /// Kerberos message being encoded.
        target: &'static str,
        /// Encoder error.
        message: String,
    },
    /// A Kerberos string value could not be constructed.
    #[error("invalid Kerberos string value: {0}")]
    InvalidKerberosString(String),
    /// Encoded AP-REQ is too large for the two-byte kpasswd length field.
    #[error("encoded AP-REQ is too large: {actual} bytes")]
    ApReqTooLarge {
        /// Encoded AP-REQ byte length.
        actual: usize,
    },
    /// Encoded kadmin frame is too large for the two-byte length prefix.
    #[error("encoded kadmin frame is too large: {actual} bytes")]
    FrameTooLarge {
        /// Encoded frame byte length.
        actual: usize,
    },
}

/// A kpasswd frame split into its header fields and body.
struct Frame<'bytes> {
    /// The total frame length the header declares.
    message_length: u16,
    /// The protocol version.
    version: u16,
    /// The AP-REQ or AP-REP length; zero for a KRB-ERROR reply.
    payload_length: u16,
    /// The bytes after the header, up to the declared frame length.
    body: &'bytes [u8],
}

/// Decode one DER value, naming `target` in the error.
///
/// # Errors
///
/// Returns [`Error::Decode`] when `bytes` is not a DER `T`.
fn decode<T>(target: &'static str, bytes: &[u8]) -> Result<T, Error>
where
    T: Decode,
{
    der::decode(bytes).map_err(|source| Error::Decode {
        target,
        message: source.to_string(),
    })
}

/// Encode one value as DER, naming `target` in the error.
///
/// # Errors
///
/// Returns [`Error::Encode`] when the DER encoder fails.
fn encode<T>(target: &'static str, value: &T) -> Result<Vec<u8>, Error>
where
    T: Encode,
{
    der::encode(value).map_err(|source| Error::Encode {
        target,
        message: source.to_string(),
    })
}

/// Map an AP-REQ error onto the kadmin [`Error`].
fn ap_req_error(error: ap_req::Error) -> Error {
    match error {
        ap_req::Error::Decode { target, message } => Error::Decode { target, message },
        ap_req::Error::Encode { target, message } => Error::Encode { target, message },
        ap_req::Error::InvalidMessage {
            field,
            expected,
            actual,
        } => Error::InvalidKerberosMessage {
            field,
            expected,
            actual,
        },
        other @ (ap_req::Error::UnsupportedEtype(_)
        | ap_req::Error::KeyEtypeMismatch {
            key_etype: _,
            encrypted_data_etype: _,
        }
        | ap_req::Error::Random(_)
        | ap_req::Error::Crypto(_)) => Error::Decode {
            target: "AP-REQ",
            message: other.to_string(),
        },
    }
}

/// Map an AP-REP error onto the kadmin [`Error`].
fn ap_rep_error(error: ap_rep::Error) -> Error {
    match error {
        ap_rep::Error::Decode { target, message } => Error::Decode { target, message },
        ap_rep::Error::Encode { target, message } => Error::Encode { target, message },
        ap_rep::Error::InvalidMessage {
            field,
            expected,
            actual,
        } => Error::InvalidKerberosMessage {
            field,
            expected,
            actual,
        },
        other @ (ap_rep::Error::UnsupportedEtype(_)
        | ap_rep::Error::KeyEtypeMismatch {
            key_etype: _,
            encrypted_data_etype: _,
        }
        | ap_rep::Error::Random(_)
        | ap_rep::Error::Crypto(_)) => Error::Decode {
            target: "AP-REP",
            message: other.to_string(),
        },
    }
}

/// Map a KRB-ERROR error onto the kadmin [`Error`].
fn krb_error_error(error: krb_error::Error) -> Error {
    match error {
        krb_error::Error::Decode { target, message } => Error::Decode { target, message },
        krb_error::Error::Encode { target, message } => Error::Encode { target, message },
        krb_error::Error::InvalidMessage {
            field,
            expected,
            actual,
        } => Error::InvalidKerberosMessage {
            field,
            expected,
            actual,
        },
        other @ (krb_error::Error::InvalidString(_)
        | krb_error::Error::IntegerOutOfRange { field: _, value: _ }
        | krb_error::Error::KvnoOutOfRange { target: _, kvno: _ }
        | krb_error::Error::TimeOverflow) => Error::Decode {
            target: "KRB-ERROR",
            message: other.to_string(),
        },
    }
}

/// Map a KRB-PRIV error onto the kadmin [`Error`].
fn krb_priv_error(error: krb_priv::Error) -> Error {
    match error {
        krb_priv::Error::Decode { target, message } => Error::Decode { target, message },
        krb_priv::Error::Encode { target, message } => Error::Encode { target, message },
        krb_priv::Error::InvalidMessage {
            field,
            expected,
            actual,
        } => Error::InvalidKerberosMessage {
            field,
            expected,
            actual,
        },
        krb_priv::Error::UnsupportedEtype(etype) => Error::UnsupportedEtype(etype),
        krb_priv::Error::KeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        } => Error::KeyEtypeMismatch {
            key_etype,
            encrypted_data_etype,
        },
        krb_priv::Error::Crypto(source) => Error::Crypto {
            message: source.to_string(),
        },
        krb_priv::Error::Random(source) => Error::Crypto {
            message: source.to_string(),
        },
    }
}

/// A principal name of `name_type` made of `components`.
///
/// # Errors
///
/// Returns [`Error::InvalidKerberosString`] for a component that is not a valid
/// Kerberos string.
fn principal_name<I, S>(
    name_type: i32,
    components: I,
) -> Result<rasn_kerberos::PrincipalName, Error>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    Ok(rasn_kerberos::PrincipalName {
        r#type: name_type,
        string: components
            .into_iter()
            .map(|component| kerberos_string(component.as_ref()))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

/// `value` as a Kerberos string.
///
/// # Errors
///
/// Returns [`Error::InvalidKerberosString`] when `value` is not a valid
/// Kerberos string.
fn kerberos_string(value: &str) -> Result<rasn_kerberos::KerberosString, Error> {
    rasn_kerberos::KerberosString::from_bytes(value.as_bytes())
        .map_err(|source| Error::InvalidKerberosString(source.to_string()))
}

/// Split a kpasswd frame into its header fields and body.
///
/// # Errors
///
/// Returns [`Error::FrameTooShort`] when `bytes` is shorter than the header,
/// [`Error::InvalidMessageLength`] when the declared length is shorter than the
/// header, and [`Error::TruncatedFrame`] when it is longer than `bytes`.
fn parse_header(bytes: &[u8]) -> Result<Frame<'_>, Error> {
    let [
        length_high,
        length_low,
        version_high,
        version_low,
        payload_high,
        payload_low,
        ..,
    ] = *bytes
    else {
        return Err(Error::FrameTooShort {
            actual: bytes.len(),
        });
    };

    let message_length = u16::from_be_bytes([length_high, length_low]);
    let frame_len = usize::from(message_length);
    if frame_len < HEADER_LEN {
        return Err(Error::InvalidMessageLength(message_length));
    }
    let Some(body) = bytes.get(HEADER_LEN..frame_len) else {
        return Err(Error::TruncatedFrame {
            expected: frame_len,
            actual: bytes.len(),
        });
    };

    Ok(Frame {
        message_length,
        version: u16::from_be_bytes([version_high, version_low]),
        payload_length: u16::from_be_bytes([payload_high, payload_low]),
        body,
    })
}

/// `size` bytes from the operating system's random source.
///
/// # Errors
///
/// Returns [`Error::Crypto`] when the random source fails.
fn random_key_material(size: usize) -> Result<Vec<u8>, Error> {
    let mut value = vec![0_u8; size];
    getrandom::fill(&mut value).map_err(|source| Error::Crypto {
        message: source.to_string(),
    })?;
    Ok(value)
}

/// `value` as the `rasn` Kerberos `EncryptionKey`.
fn encryption_key_to_rasn(value: &EncryptionKey) -> rasn_kerberos::EncryptionKey {
    rasn_kerberos::EncryptionKey {
        r#type: value.etype,
        value: value.value.clone().into(),
    }
}
