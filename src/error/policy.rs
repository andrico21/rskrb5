use core::fmt;

/// Permanent security-policy failures, independent of protocol and transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum Policy {
    /// A caller selected an insecure feature that cannot be enabled.
    #[error("rejected feature {feature}: {reason}")]
    RejectedFeature {
        /// The prohibited feature, not a cryptographic capability switch.
        feature: RejectedFeature,
        /// A policy explanation, not an underlying error source.
        reason: RejectionReason,
    },
}

/// Features permanently excluded by the security policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RejectedFeature {
    /// Single DES: [policy](https://github.com/andrico21/rskrb5-ng/blob/main/docs/security-policy.md#single-des).
    SingleDes,
    /// Kerberos V4: [policy](https://github.com/andrico21/rskrb5-ng/blob/main/docs/security-policy.md#kerberos-v4).
    KerberosV4,
    /// V4 conversion: [policy](https://github.com/andrico21/rskrb5-ng/blob/main/docs/security-policy.md#v4-conversion).
    V4Conversion,
    /// Removed RSA key-transport PKINIT, not RSA certificate signatures: [policy](https://github.com/andrico21/rskrb5-ng/blob/main/docs/security-policy.md#rsa-pkinit).
    RsaPkinit,
    /// Obsolete draft-9 PKINIT: [policy](https://github.com/andrico21/rskrb5-ng/blob/main/docs/security-policy.md#draft9-pkinit).
    Draft9Pkinit,
    /// Export-strength RC4: [policy](https://github.com/andrico21/rskrb5-ng/blob/main/docs/security-policy.md#rc4-export).
    Rc4Export,
    /// Negotiable unauthenticated integrity: [policy](https://github.com/andrico21/rskrb5-ng/blob/main/docs/security-policy.md#unauthenticated-checksum).
    UnauthenticatedChecksum {
        /// Kerberos checksum identifier selected by the caller.
        id: i32,
    },
    /// Password mutation without protection: [policy](https://github.com/andrico21/rskrb5-ng/blob/main/docs/security-policy.md#unprotected-password-change).
    UnprotectedPasswordChange,
    /// Blanket weak-crypto enablement: [policy](https://github.com/andrico21/rskrb5-ng/blob/main/docs/security-policy.md#weak-crypto).
    WeakCrypto,
}

impl fmt::Display for RejectedFeature {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::SingleDes => "single DES",
            Self::KerberosV4 => "Kerberos V4",
            Self::V4Conversion => "V4 conversion",
            Self::RsaPkinit => "RSA PKINIT",
            Self::Draft9Pkinit => "draft-9 PKINIT",
            Self::Rc4Export => "RC4 export",
            Self::UnauthenticatedChecksum { id } => {
                return write!(f, "unauthenticated checksum {id}");
            }
            Self::UnprotectedPasswordChange => "unprotected password change",
            Self::WeakCrypto => "weak crypto",
        };
        f.write_str(name)
    }
}

/// Machine-readable explanation of a permanent rejection.
///
/// These values describe policy, not causal errors: they deliberately do not
/// implement `Error` and are not marked `#[source]`. Display text is explanatory;
/// callers should match the enum rather than parse that text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RejectionReason {
    /// Removed legacy cryptography or protocol with inadequate security.
    RemovedAndInsecure,
    /// Insecure construction or blanket weakening, regardless of availability.
    InsecureByDesign,
    /// The selected construction cannot authenticate the protected operation.
    MissingAuthentication,
}

impl fmt::Display for RejectionReason {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RemovedAndInsecure => "removed and insecure",
            Self::InsecureByDesign => "insecure by design",
            Self::MissingAuthentication => "does not provide authenticated protection",
        })
    }
}

/// Reuse existing crypto-source wrappers instead of duplicating policy variants.
macro_rules! policy_via_crypto {
    ($($domain:ident),+ $(,)?) => {
        $(impl From<Policy> for $domain {
            #[inline]
            fn from(policy: Policy) -> Self {
                Self::Crypto(Crypto::from(policy))
            }
        })+
    };
}

policy_via_crypto!(Keytab, Pac);
#[cfg(feature = "messages")]
policy_via_crypto!(
    ApRep, ApReq, Client, KdcRep, KdcReq, KrbCred, KrbPriv, KrbSafe, Service, Ticket
);
#[cfg(feature = "spnego")]
policy_via_crypto!(Spnego);

#[cfg(feature = "http")]
impl From<Policy> for Http {
    #[inline]
    fn from(policy: Policy) -> Self {
        Self::Spnego(Spnego::from(policy))
    }
}
