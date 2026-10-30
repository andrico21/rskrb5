//! MIT selector vocabulary; recognition never grants runtime permission.

use crate::{
    crypto::{AesSha1Etype, AesSha2Etype, Des3CbcSha1KdEtype, KerberosEtype, Rc4HmacEtype},
    error::RejectedFeature,
};

/// Implemented secure defaults retain the crate's SHA2-first preference.
pub(super) const SECURE_DEFAULT: &[KerberosEtype] = &[
    KerberosEtype::Sha2(AesSha2Etype::Aes256),
    KerberosEtype::Sha2(AesSha2Etype::Aes128),
    KerberosEtype::Sha1(AesSha1Etype::Aes256),
    KerberosEtype::Sha1(AesSha1Etype::Aes128),
];

/// Recognized selectors distinguish availability from permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Selector {
    /// One or more implemented secure enctypes in expansion order.
    Secure(&'static [KerberosEtype]),
    /// Deprecated DES3 requiring a runtime opt-in.
    Des3,
    /// Deprecated RC4-HMAC requiring a runtime opt-in.
    Rc4,
    /// Secure Camellia is unavailable until plan 2.
    Camellia,
    /// Known insecure names exist solely for rejection or removal.
    Rejected(RejectedFeature),
}

impl Selector {
    /// Recognize case-insensitive MIT names and aliases without heap allocation.
    pub(super) fn parse(name: &str) -> Option<Self> {
        NAMES.iter().find_map(|(names, selector)| {
            names
                .iter()
                .any(|alias| alias.eq_ignore_ascii_case(name))
                .then_some(*selector)
        })
    }

    /// Return only implemented enctypes; unavailable removals are harmless no-ops.
    pub(super) const fn enctypes(self) -> &'static [KerberosEtype] {
        match self {
            Self::Secure(enctypes) => enctypes,
            Self::Des3 => &[KerberosEtype::Des3CbcSha1Kd(Des3CbcSha1KdEtype)],
            Self::Rc4 => &[KerberosEtype::Rc4Hmac(Rc4HmacEtype)],
            Self::Camellia | Self::Rejected(_) => &[],
        }
    }
}

/// Vocabulary from MIT 1.22.2 `etypes.c` and `init_ctx.c:411-492`.
/// Historical single-DES names are recognized only for permanent rejection.
const NAMES: &[(&[&str], Selector)] = &[
    (&["DEFAULT"], Selector::Secure(SECURE_DEFAULT)),
    (
        &["aes"],
        Selector::Secure(&[
            KerberosEtype::Sha1(AesSha1Etype::Aes256),
            KerberosEtype::Sha1(AesSha1Etype::Aes128),
            KerberosEtype::Sha2(AesSha2Etype::Aes256),
            KerberosEtype::Sha2(AesSha2Etype::Aes128),
        ]),
    ),
    (
        &["aes128-cts-hmac-sha1-96", "aes128-cts", "aes128-sha1"],
        Selector::Secure(&[KerberosEtype::Sha1(AesSha1Etype::Aes128)]),
    ),
    (
        &["aes256-cts-hmac-sha1-96", "aes256-cts", "aes256-sha1"],
        Selector::Secure(&[KerberosEtype::Sha1(AesSha1Etype::Aes256)]),
    ),
    (
        &["aes128-cts-hmac-sha256-128", "aes128-sha2"],
        Selector::Secure(&[KerberosEtype::Sha2(AesSha2Etype::Aes128)]),
    ),
    (
        &["aes256-cts-hmac-sha384-192", "aes256-sha2"],
        Selector::Secure(&[KerberosEtype::Sha2(AesSha2Etype::Aes256)]),
    ),
    (
        &[
            "des3",
            "des3-cbc-sha1",
            "des3-hmac-sha1",
            "des3-cbc-sha1-kd",
        ],
        Selector::Des3,
    ),
    (
        &["rc4", "arcfour-hmac", "rc4-hmac", "arcfour-hmac-md5"],
        Selector::Rc4,
    ),
    (
        &[
            "camellia",
            "camellia128-cts-cmac",
            "camellia128-cts",
            "camellia256-cts-cmac",
            "camellia256-cts",
        ],
        Selector::Camellia,
    ),
    (
        &[
            "des-cbc-crc",
            "des-cbc-md4",
            "des-cbc-md5",
            "des-cbc-raw",
            "des-hmac-sha1",
        ],
        Selector::Rejected(RejectedFeature::SingleDes),
    ),
    (
        &["arcfour-hmac-exp", "rc4-hmac-exp", "arcfour-hmac-md5-exp"],
        Selector::Rejected(RejectedFeature::Rc4Export),
    ),
    (
        &["des3-cbc-raw"],
        Selector::Rejected(RejectedFeature::WeakCrypto),
    ),
];
