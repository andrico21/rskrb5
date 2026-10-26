//! Kerberos keytab parsing and serialization.
//!
//! This module covers the MIT keytab file format surface needed before client
//! and service flows can consume long-term keys.

use alloc::fmt;
use core::{
    str::{self, FromStr, Utf8Error},
    time::Duration,
};
use std::{
    env, fs, io,
    path::{Path, PathBuf},
    time::{SystemTime, SystemTimeError, UNIX_EPOCH},
};

use crate::{
    crypto::{self, KerberosEtype},
    file_name,
};

/// First byte of every keytab file.
const KEYTAB_FIRST_BYTE: u8 = 5;
/// Environment variable naming the default keytab.
const KRB5_KTNAME_ENV: &str = "KRB5_KTNAME";

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
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            not(feature = "messages"),
            not(feature = "serde"),
            not(feature = "spnego"),
            not(feature = "tokio"),
            not(feature = "tower"),
            not(test)
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            not(feature = "messages"),
            not(feature = "serde"),
            not(feature = "spnego"),
            not(feature = "tokio"),
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::module_name_repetitions,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
/// Parsed MIT-style keytab name.
///
/// `rskrb5` currently supports file-backed keytabs only. The explicit name
/// type gives callers a validation point before attempting filesystem access.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum KeytabName {
    /// A file-backed keytab.
    File(PathBuf),
}

impl KeytabName {
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
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                not(test)
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                test
            )
        ),
        expect(
            clippy::impl_trait_in_params,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    /// Parse a MIT-style keytab name.
    ///
    /// Bare paths, `FILE:path`, and `WRFILE:path` are supported. Collection
    /// and platform stores such as `DIR:`, `KEYRING:`, and `MEMORY:` are
    /// rejected explicitly.
    ///
    /// # Errors
    ///
    /// Returns any error of [`Keytab::file_path_from_keytab_name`].
    #[inline]
    pub fn parse(name: impl AsRef<str>) -> Result<Self, Error> {
        Keytab::file_path_from_keytab_name(name.as_ref()).map(Self::File)
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
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                not(test)
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                test
            )
        ),
        expect(
            clippy::must_use_candidate,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    /// File path for this keytab name.
    #[inline]
    pub fn file_path(&self) -> &Path {
        match self {
            Self::File(path) => path,
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
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                not(test)
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                test
            )
        ),
        expect(
            clippy::must_use_candidate,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    /// Consume this keytab name and return its file path.
    #[inline]
    pub fn into_file_path(self) -> PathBuf {
        match self {
            Self::File(path) => path,
        }
    }
}

impl FromStr for KeytabName {
    type Err = Error;

    #[inline]
    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Self::parse(name)
    }
}

/// Parsed keytab file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Keytab {
    /// File format version, 1 or 2.
    version: u8,
    /// Entries in file order.
    entries: Vec<Entry>,
}

impl Keytab {
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
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                not(test)
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
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
    /// Create an empty version 2 keytab.
    #[inline]
    pub fn new() -> Self {
        Self {
            version: 2,
            entries: Vec::new(),
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
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                not(test)
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                test
            )
        ),
        expect(
            clippy::impl_trait_in_params,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    /// Load and parse a keytab file.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] when the file cannot be read, and any error of
    /// [`Keytab::parse`] for its contents.
    #[inline]
    pub fn load(path: impl AsRef<Path>) -> Result<Self, Error> {
        let bytes = fs::read(path.as_ref())?;
        Self::parse(&bytes)
    }

    /// Load and parse the file keytab named by `KRB5_KTNAME`.
    ///
    /// Only file-backed keytab names are supported: bare paths, `FILE:path`,
    /// and `WRFILE:path`. Collection and platform stores such as `DIR:`,
    /// `KEYRING:`, and `MEMORY:` are rejected explicitly.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DefaultKeytabName`] when `KRB5_KTNAME` is unset or not
    /// valid Unicode, and any error of [`Keytab::load_name`].
    #[inline]
    pub fn load_from_env() -> Result<Self, Error> {
        let name = env::var(KRB5_KTNAME_ENV).map_err(Error::DefaultKeytabName)?;
        Self::load_name(name)
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
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                not(test)
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                test
            )
        ),
        expect(
            clippy::impl_trait_in_params,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    /// Load and parse a keytab by MIT-style keytab name.
    ///
    /// Bare paths, `FILE:path`, and `WRFILE:path` are supported.
    ///
    /// # Errors
    ///
    /// Returns any error of [`KeytabName::parse`] and [`Keytab::load`].
    #[inline]
    pub fn load_name(name: impl AsRef<str>) -> Result<Self, Error> {
        Self::load(KeytabName::parse(name)?.into_file_path())
    }

    /// Parse keytab bytes.
    ///
    /// Entries with a negative length are holes left by deleted entries and
    /// are skipped; a zero length ends the entry list.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooShort`] for input shorter than two bytes,
    /// [`Error::InvalidFirstByte`] and [`Error::InvalidVersion`] for a bad
    /// file prefix, [`Error::Truncated`], [`Error::NegativeLength`] and
    /// [`Error::LengthOverflow`] for lengths and counts that do not fit the
    /// input, and [`Error::InvalidString`] for a principal string that is not
    /// UTF-8.
    #[inline]
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let [first_byte, version, ..] = *bytes else {
            return Err(Error::TooShort {
                actual: bytes.len(),
            });
        };
        if first_byte != KEYTAB_FIRST_BYTE {
            return Err(Error::InvalidFirstByte(first_byte));
        }
        if version != 1 && version != 2 {
            return Err(Error::InvalidVersion(version));
        }

        let endian = Endian::for_version(version);
        let mut offset = 2_usize;
        let mut entries = Vec::new();

        while bytes.len().saturating_sub(offset) >= 4 {
            let entry_len = read_i32(bytes, &mut offset, endian)?;
            if entry_len == 0_i32 {
                break;
            }
            if entry_len < 0_i32 {
                let skip = entry_len
                    .checked_abs()
                    .ok_or(Error::LengthOverflow)?
                    .try_into()
                    .map_err(|_out_of_range| Error::LengthOverflow)?;
                checked_advance(bytes, &mut offset, skip)?;
                continue;
            }

            let body_len =
                usize::try_from(entry_len).map_err(|_out_of_range| Error::LengthOverflow)?;
            let entry_bytes = read_bytes(bytes, &mut offset, body_len)?;
            let mut entry_offset = 0_usize;

            let principal = Principal::parse(entry_bytes, &mut entry_offset, version, endian)?;
            let timestamp = read_u32(entry_bytes, &mut entry_offset, endian)?;
            let kvno8 = read_u8(entry_bytes, &mut entry_offset)?;
            let etype = i32::from(read_i16(entry_bytes, &mut entry_offset, endian)?);
            let raw_key_len = read_i16(entry_bytes, &mut entry_offset, endian)?;
            let Ok(key_len) = usize::try_from(raw_key_len) else {
                return Err(Error::NegativeLength(raw_key_len.into()));
            };
            let key_value = read_bytes(entry_bytes, &mut entry_offset, key_len)?.to_vec();

            let mut kvno = if entry_bytes.len().saturating_sub(entry_offset) >= 4 {
                read_u32(entry_bytes, &mut entry_offset, endian)?
            } else {
                kvno8.into()
            };
            if kvno == 0 {
                kvno = kvno8.into();
            }

            entries.push(Entry {
                principal,
                timestamp,
                kvno8,
                key: EncryptionKey {
                    etype,
                    value: key_value,
                },
                kvno,
            });
        }

        Ok(Self { version, entries })
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
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                not(test)
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                test
            )
        ),
        expect(
            clippy::impl_trait_in_params,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    /// Save this keytab to a file.
    ///
    /// # Errors
    ///
    /// Returns any error of [`Keytab::to_bytes`], and [`Error::Io`] when the
    /// file cannot be written.
    #[inline]
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), Error> {
        fs::write(path.as_ref(), self.to_bytes()?)?;
        Ok(())
    }

    /// Save this keytab to the file keytab named by `KRB5_KTNAME`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DefaultKeytabName`] when `KRB5_KTNAME` is unset or not
    /// valid Unicode, and any error of [`Keytab::save_name`].
    #[inline]
    pub fn save_to_env(&self) -> Result<(), Error> {
        let name = env::var(KRB5_KTNAME_ENV).map_err(Error::DefaultKeytabName)?;
        self.save_name(name)
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
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                not(test)
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                test
            )
        ),
        expect(
            clippy::impl_trait_in_params,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    /// Save this keytab by MIT-style keytab name.
    ///
    /// Bare paths, `FILE:path`, and `WRFILE:path` are supported.
    ///
    /// # Errors
    ///
    /// Returns any error of [`KeytabName::parse`] and [`Keytab::save`].
    #[inline]
    pub fn save_name(&self, name: impl AsRef<str>) -> Result<(), Error> {
        self.save(KeytabName::parse(name)?.into_file_path())
    }

    /// Resolve a MIT-style keytab name to a file path.
    ///
    /// This does not touch the filesystem; it only validates that the name
    /// denotes a keytab format backed by this module.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeytabName`] when the name or its path is
    /// empty, and [`Error::UnsupportedKeytabType`] for a type prefix other
    /// than `FILE` or `WRFILE`.
    #[inline]
    pub fn file_path_from_keytab_name(name: &str) -> Result<PathBuf, Error> {
        file_name::file_path_from_name(name, &["FILE", "WRFILE"]).map_err(|error| match error {
            file_name::Error::Empty => Error::InvalidKeytabName,
            file_name::Error::UnsupportedType { name_type } => Error::UnsupportedKeytabType {
                keytab_type: name_type,
            },
        })
    }

    /// Serialize the keytab to bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LengthOverflow`] when a component count, string or key
    /// length, or encryption type does not fit a `u16`, or an entry does not
    /// fit an `i32` length.
    #[inline]
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let endian = Endian::for_version(self.version);
        let mut out = vec![KEYTAB_FIRST_BYTE, self.version];
        for entry in &self.entries {
            let mut body = Vec::new();
            entry.principal.write_to(&mut body, self.version, endian)?;
            write_u32(&mut body, entry.timestamp, endian);
            body.push(entry.kvno8);
            write_u16_checked(&mut body, entry.key.etype, endian)?;
            write_u16_checked(&mut body, entry.key.value.len(), endian)?;
            body.extend_from_slice(&entry.key.value);
            write_u32(&mut body, entry.kvno, endian);

            let body_len: i32 = body
                .len()
                .try_into()
                .map_err(|_out_of_range| Error::LengthOverflow)?;
            write_i32(&mut out, body_len, endian);
            out.extend_from_slice(&body);
        }
        Ok(out)
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
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                not(test)
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
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
    /// Keytab file format version.
    #[inline]
    pub fn version(&self) -> u8 {
        self.version
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
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                not(test)
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                test
            )
        ),
        expect(
            clippy::must_use_candidate,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    /// Parsed entries.
    #[inline]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
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
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                not(test)
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                test
            )
        ),
        expect(
            clippy::missing_const_for_fn,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    /// Mutable parsed entries, useful for tests and construction.
    #[inline]
    pub fn entries_mut(&mut self) -> &mut Vec<Entry> {
        &mut self.entries
    }

    /// Redacted entry metadata, suitable for diagnostics and JSON rendering.
    #[cfg(feature = "serde")]
    #[inline]
    pub fn entry_metadata(&self) -> Vec<KeytabEntryMetadata> {
        self.entries
            .iter()
            .map(KeytabEntryMetadata::from_entry)
            .collect()
    }

    /// Return redacted entry metadata as pretty-printed JSON.
    ///
    /// Raw key bytes are intentionally omitted.
    ///
    /// # Errors
    ///
    /// Returns the [`serde_json::Error`] of a failed serialization.
    #[cfg(feature = "serde")]
    #[inline]
    pub fn entries_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.entry_metadata())
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
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                not(test)
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                test
            )
        ),
        expect(
            clippy::impl_trait_in_params,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    /// Add an entry by deriving key material from a password.
    ///
    /// This mirrors gokrb5's keytab entry generation: the default Kerberos
    /// password salt is `realm + principal components`, and the selected
    /// encryption type's default string-to-key parameters are used.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedEtype`] for an encryption type this crate
    /// does not implement, [`Error::Crypto`] when key derivation fails, and
    /// [`Error::TimestampBeforeUnixEpoch`] or [`Error::TimestampOverflow`]
    /// when `timestamp` does not fit the file's unsigned 32-bit seconds.
    #[inline]
    pub fn add_entry_from_password(
        &mut self,
        principal: Principal,
        password: impl AsRef<[u8]>,
        timestamp: SystemTime,
        kvno: u8,
        etype: i32,
    ) -> Result<(), Error> {
        let etype_impl =
            KerberosEtype::from_etype_id(etype).ok_or(Error::UnsupportedEtype(etype))?;
        let salt = principal.default_password_salt();
        let key = etype_impl.string_to_key(
            password.as_ref(),
            salt.as_bytes(),
            etype_impl.default_s2kparams(),
        )?;
        let seconds = system_time_to_u32_seconds(timestamp)?;
        self.entries.push(Entry {
            principal,
            timestamp: seconds,
            kvno8: kvno,
            key: EncryptionKey { etype, value: key },
            kvno: kvno.into(),
        });
        Ok(())
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
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                not(test)
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                test
            )
        ),
        expect(
            clippy::impl_trait_in_params,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    /// Add an entry from an SPN-style principal name string.
    ///
    /// The name is split on `/` and stored with name type `1`
    /// (`KRB_NT_PRINCIPAL`), matching gokrb5's keytab `AddEntry` behavior.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPrincipalName`] when the name is empty or has
    /// an empty component, and any error of
    /// [`Keytab::add_entry_from_password`].
    #[inline]
    pub fn add_entry_from_password_name(
        &mut self,
        principal_name: impl AsRef<str>,
        realm: impl Into<String>,
        password: impl AsRef<[u8]>,
        timestamp: SystemTime,
        kvno: u8,
        etype: i32,
    ) -> Result<(), Error> {
        self.add_entry_from_password(
            Principal::from_name(realm, 1, principal_name)?,
            password,
            timestamp,
            kvno,
            etype,
        )
    }

    /// Find the newest key matching principal components, realm, kvno, and
    /// encryption type. A `kvno` of `0` matches any kvno, mirroring gokrb5.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoMatchingKey`] when no entry matches.
    #[inline]
    pub fn find_key(
        &self,
        principal_components: &[&str],
        realm: &str,
        kvno: u32,
        etype: i32,
    ) -> Result<(&EncryptionKey, u32), Error> {
        let mut selected: Option<&Entry> = None;
        for entry in &self.entries {
            if entry.principal.realm == realm
                && entry.principal.components.len() == principal_components.len()
                && entry
                    .principal
                    .components
                    .iter()
                    .zip(principal_components)
                    .all(|(left, right)| left == right)
                && entry.key.etype == etype
                && (kvno == 0 || entry.kvno == kvno)
            {
                match selected {
                    Some(current) if current.timestamp >= entry.timestamp => {}
                    _ => selected = Some(entry),
                }
            }
        }

        selected
            .map(|entry| (&entry.key, entry.kvno))
            .ok_or_else(|| Error::NoMatchingKey {
                principal: principal_components.join("/"),
                realm: realm.to_owned(),
                kvno,
                etype,
            })
    }
}

/// The default keytab name: `KRB5_KTNAME` when it is set, otherwise
/// `configured_name`.
///
/// # Errors
///
/// Returns [`Error::DefaultKeytabName`] when `KRB5_KTNAME` is set but not
/// valid Unicode.
#[cfg(feature = "messages")]
pub(crate) fn default_keytab_name(configured_name: &str) -> Result<String, Error> {
    match env::var(KRB5_KTNAME_ENV) {
        Ok(keytab_name) => Ok(keytab_name),
        Err(env::VarError::NotPresent) => Ok(configured_name.to_owned()),
        Err(error) => Err(Error::DefaultKeytabName(error)),
    }
}

impl Default for Keytab {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// A keytab entry.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Entry {
    /// Principal for the key.
    pub principal: Principal,
    /// POSIX timestamp in seconds.
    pub timestamp: u32,
    /// 8-bit key version number stored in the fixed entry fields.
    pub kvno8: u8,
    /// Long-term key material.
    pub key: EncryptionKey,
    /// 32-bit key version number, falling back to `kvno8` when absent or zero.
    pub kvno: u32,
}

impl Entry {
    /// Creates a `Entry` from its required fields.
    #[must_use]
    #[inline]
    pub const fn new(
        principal: Principal,
        timestamp: u32,
        kvno8: u8,
        key: EncryptionKey,
        kvno: u32,
    ) -> Self {
        Self {
            principal,
            timestamp,
            kvno8,
            key,
            kvno,
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
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                not(test)
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                test
            )
        ),
        expect(
            clippy::must_use_candidate,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    /// Entry timestamp as `SystemTime`.
    ///
    /// Every supported platform represents all unsigned 32-bit POSIX seconds;
    /// a platform that cannot gets the Unix epoch instead.
    #[inline]
    pub fn system_time(&self) -> SystemTime {
        UNIX_EPOCH
            .checked_add(Duration::from_secs(self.timestamp.into()))
            .unwrap_or(UNIX_EPOCH)
    }
}

/// Keytab principal.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Principal {
    /// Principal realm.
    pub realm: String,
    /// Principal name components.
    pub components: Vec<String>,
    /// Kerberos name type. Version 1 keytabs omit this and parse as `0`.
    pub name_type: i32,
}

impl Principal {
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
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                not(test)
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                test
            )
        ),
        expect(
            clippy::impl_trait_in_params,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    /// Create a keytab principal.
    #[inline]
    pub fn new<I, S>(realm: impl Into<String>, name_type: i32, components: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            realm: realm.into(),
            components: components.into_iter().map(Into::into).collect(),
            name_type,
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
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                not(test)
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                test
            )
        ),
        expect(
            clippy::impl_trait_in_params,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    /// Create a keytab principal from components separated by `/`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPrincipalName`] when the name is empty or has
    /// an empty component.
    #[inline]
    pub fn from_name(
        realm: impl Into<String>,
        name_type: i32,
        principal_name: impl AsRef<str>,
    ) -> Result<Self, Error> {
        let name = principal_name.as_ref();
        if name.is_empty() {
            return Err(Error::InvalidPrincipalName);
        }
        let components = name.split('/');
        if components.clone().any(str::is_empty) {
            return Err(Error::InvalidPrincipalName);
        }
        Ok(Self::new(realm, name_type, components))
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
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                not(test)
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                test
            )
        ),
        expect(
            clippy::must_use_candidate,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    /// Return the default Kerberos password salt for this principal.
    #[inline]
    pub fn default_password_salt(&self) -> String {
        let mut salt = self.realm.clone();
        for component in &self.components {
            salt.push_str(component);
        }
        salt
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
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                not(test)
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                test
            )
        ),
        expect(
            clippy::must_use_candidate,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    /// Principal components joined by `/`.
    #[inline]
    pub fn name_string(&self) -> String {
        self.components.join("/")
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
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                not(test)
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                test
            )
        ),
        expect(
            clippy::must_use_candidate,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    /// Principal as `name@REALM`.
    #[inline]
    pub fn principal_string(&self) -> String {
        format!("{}@{}", self.name_string(), self.realm)
    }

    /// Parse a principal at `offset` in the encoding of `version`, advancing
    /// `offset` past it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`], [`Error::NegativeLength`] or
    /// [`Error::LengthOverflow`] when a count or length does not fit the
    /// input, and [`Error::InvalidString`] for a string that is not UTF-8.
    fn parse(bytes: &[u8], offset: &mut usize, version: u8, endian: Endian) -> Result<Self, Error> {
        let mut raw_count = read_i16(bytes, offset, endian)?;
        if version == 1 {
            // Version 1 counts the realm as a component.
            raw_count = raw_count.checked_sub(1).ok_or(Error::LengthOverflow)?;
        }
        let Ok(component_count) = usize::try_from(raw_count) else {
            return Err(Error::NegativeLength(raw_count.into()));
        };

        let realm = read_counted_string(bytes, offset, endian)?;
        let mut components = Vec::with_capacity(component_count);
        for _ in 0..component_count {
            components.push(read_counted_string(bytes, offset, endian)?);
        }

        let name_type = if version == 1 {
            0_i32
        } else {
            read_i32(bytes, offset, endian)?
        };

        Ok(Self {
            realm,
            components,
            name_type,
        })
    }

    /// Append the principal to `out` in the encoding of `version`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LengthOverflow`] when the component count or a string
    /// length does not fit a `u16`.
    fn write_to(&self, out: &mut Vec<u8>, version: u8, endian: Endian) -> Result<(), Error> {
        let component_count = if version == 1 {
            self.components
                .len()
                .checked_add(1)
                .ok_or(Error::LengthOverflow)?
        } else {
            self.components.len()
        };
        write_u16_checked(out, component_count, endian)?;
        write_counted_string(out, &self.realm, endian)?;
        for component in &self.components {
            write_counted_string(out, component, endian)?;
        }
        if version != 1 {
            write_i32(out, self.name_type, endian);
        }
        Ok(())
    }
}

/// Kerberos encryption key as stored in a keytab.
#[derive(Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[non_exhaustive]
pub struct EncryptionKey {
    /// Kerberos encryption type id.
    pub etype: i32,
    /// Raw key bytes.
    pub value: Vec<u8>,
}

impl EncryptionKey {
    /// Creates a `EncryptionKey` from its required fields.
    #[must_use]
    #[inline]
    pub const fn new(etype: i32, value: Vec<u8>) -> Self {
        Self { etype, value }
    }
}

impl fmt::Debug for EncryptionKey {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptionKey")
            .field("etype", &self.etype)
            .field("value_len", &self.value.len())
            .finish()
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
        )
    ),
    expect(
        clippy::module_name_repetitions,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
/// Redacted keytab entry metadata.
#[cfg(feature = "serde")]
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "PascalCase")]
#[non_exhaustive]
pub struct KeytabEntryMetadata {
    /// Principal as `name@REALM`.
    pub principal: String,
    /// Principal realm.
    pub realm: String,
    /// Principal name components.
    pub components: Vec<String>,
    /// Kerberos name type.
    pub name_type: i32,
    /// Entry timestamp as POSIX seconds.
    pub timestamp: u32,
    /// 8-bit key version number.
    #[serde(rename = "KVNO8")]
    pub kvno8: u8,
    /// 32-bit key version number.
    #[serde(rename = "KVNO")]
    pub kvno: u32,
    /// Kerberos encryption type id.
    #[serde(rename = "EType")]
    pub etype: i32,
    /// Length of the key value in bytes.
    pub key_length: usize,
}

#[cfg(feature = "serde")]
impl KeytabEntryMetadata {
    /// Redacted metadata of one entry.
    fn from_entry(entry: &Entry) -> Self {
        Self {
            principal: entry.principal.principal_string(),
            realm: entry.principal.realm.clone(),
            components: entry.principal.components.clone(),
            name_type: entry.principal.name_type,
            timestamp: entry.timestamp,
            kvno8: entry.kvno8,
            kvno: entry.kvno,
            etype: entry.key.etype,
            key_length: entry.key.value.len(),
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
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            not(feature = "messages"),
            not(feature = "serde"),
            not(feature = "spnego"),
            not(feature = "tokio"),
            not(feature = "tower"),
            not(test)
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            not(feature = "messages"),
            not(feature = "serde"),
            not(feature = "spnego"),
            not(feature = "tokio"),
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::error_impl_error,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
/// Keytab parsing and serialization error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// File loading or saving failed.
    #[error("keytab file could not be read or written: {0}")]
    Io(#[from] io::Error),
    /// The default keytab name could not be read from `KRB5_KTNAME`.
    #[error("default keytab name could not be read from KRB5_KTNAME: {0}")]
    DefaultKeytabName(env::VarError),
    /// A keytab name was empty or did not include a path.
    #[error("invalid keytab name")]
    InvalidKeytabName,
    /// The keytab name uses a keytab type this module cannot parse.
    #[error("unsupported keytab type: {keytab_type}")]
    UnsupportedKeytabType {
        /// Keytab type prefix before the first colon.
        keytab_type: String,
    },
    /// A principal name was empty or contained empty components.
    #[error("invalid keytab principal name")]
    InvalidPrincipalName,
    /// Input is too short to contain the keytab header.
    #[error("keytab is too short: {actual} bytes")]
    TooShort {
        /// Actual input length.
        actual: usize,
    },
    /// Keytab does not start with the required first byte.
    #[error("invalid keytab first byte: {0}")]
    InvalidFirstByte(u8),
    /// Unsupported keytab version.
    #[error("invalid keytab version: {0}")]
    InvalidVersion(u8),
    /// A read would exceed the input length.
    #[error("keytab data is truncated at offset {offset}; need {needed} bytes, have {remaining}")]
    Truncated {
        /// Offset where the read started.
        offset: usize,
        /// Bytes needed.
        needed: usize,
        /// Bytes remaining from offset.
        remaining: usize,
    },
    /// A signed length was negative where the field cannot be negative.
    #[error("negative keytab length: {0}")]
    NegativeLength(i32),
    /// A length cannot fit in the target integer type.
    #[error("keytab length overflow")]
    LengthOverflow,
    /// A keytab entry timestamp was before the Unix epoch.
    #[error("keytab timestamp is before the Unix epoch: {0}")]
    TimestampBeforeUnixEpoch(#[from] SystemTimeError),
    /// A keytab entry timestamp cannot fit in the file format.
    #[error("keytab timestamp overflow")]
    TimestampOverflow,
    /// Principal strings must be valid UTF-8.
    #[error("invalid keytab string: {0}")]
    InvalidString(#[from] Utf8Error),
    /// The encrypted data etype is not implemented yet.
    #[error("unsupported encryption type: {0}")]
    UnsupportedEtype(i32),
    /// Key derivation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] crypto::Error),
    /// Key lookup did not find a matching entry.
    #[error("matching key not found in keytab for {principal}@{realm}, kvno {kvno}, etype {etype}")]
    NoMatchingKey {
        /// Principal components joined by `/`.
        principal: String,
        /// Principal realm.
        realm: String,
        /// Requested kvno, or 0 for latest.
        kvno: u32,
        /// Requested encryption type.
        etype: i32,
    },
}

/// Byte order of the integers in a keytab file.
#[derive(Clone, Copy, Debug)]
enum Endian {
    /// Network byte order, used by version 2.
    Big,
    /// Little-endian host order, used by version 1 on such hosts.
    Little,
}

impl Endian {
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
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                not(test)
            ),
            all(
                not(feature = "default"),
                not(feature = "evaluation"),
                not(feature = "http"),
                not(feature = "messages"),
                not(feature = "serde"),
                not(feature = "spnego"),
                not(feature = "tokio"),
                not(feature = "tower"),
                test
            )
        ),
        expect(
            clippy::missing_const_for_fn,
            reason = "lint-migration: upstream baseline at ee9cb04"
        )
    )]
    /// Byte order of a file of `version`: version 1 uses host order.
    fn for_version(version: u8) -> Self {
        if version == 1 && cfg!(target_endian = "little") {
            Self::Little
        } else {
            Self::Big
        }
    }
}

/// The error for a read of `needed` bytes at `offset` past the input end.
const fn truncated(bytes: &[u8], offset: usize, needed: usize) -> Error {
    Error::Truncated {
        offset,
        needed,
        remaining: bytes.len().saturating_sub(offset),
    }
}

/// The end offset of a read of `len` bytes at `offset`.
///
/// # Errors
///
/// Returns [`Error::LengthOverflow`] when the end does not fit `usize`, and
/// [`Error::Truncated`] when it lies past the input end.
fn checked_end(bytes: &[u8], offset: usize, len: usize) -> Result<usize, Error> {
    let end = offset.checked_add(len).ok_or(Error::LengthOverflow)?;
    if end > bytes.len() {
        return Err(truncated(bytes, offset, len));
    }
    Ok(end)
}

/// Whole POSIX seconds of `value`, as stored in a keytab entry.
///
/// # Errors
///
/// Returns [`Error::TimestampBeforeUnixEpoch`] for a time before the epoch and
/// [`Error::TimestampOverflow`] when the seconds do not fit a `u32`.
fn system_time_to_u32_seconds(value: SystemTime) -> Result<u32, Error> {
    value
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .try_into()
        .map_err(|_out_of_range| Error::TimestampOverflow)
}

/// Advance `offset` past `len` bytes without reading them.
///
/// # Errors
///
/// Returns the [`checked_end`] error when the bytes do not fit the input.
fn checked_advance(bytes: &[u8], offset: &mut usize, len: usize) -> Result<(), Error> {
    *offset = checked_end(bytes, *offset, len)?;
    Ok(())
}

/// Read `len` bytes at `offset`, advancing it past them.
///
/// # Errors
///
/// Returns the [`checked_end`] error when the bytes do not fit the input.
fn read_bytes<'input>(
    bytes: &'input [u8],
    offset: &mut usize,
    len: usize,
) -> Result<&'input [u8], Error> {
    let start = *offset;
    let end = checked_end(bytes, start, len)?;
    let raw = bytes
        .get(start..end)
        .ok_or_else(|| truncated(bytes, start, len))?;
    *offset = end;
    Ok(raw)
}

/// Read `N` bytes at `offset` into an array, advancing it past them.
///
/// # Errors
///
/// Returns the [`checked_end`] error when the bytes do not fit the input.
fn read_array<const N: usize>(bytes: &[u8], offset: &mut usize) -> Result<[u8; N], Error> {
    let start = *offset;
    read_bytes(bytes, offset, N)?
        .first_chunk::<N>()
        .copied()
        .ok_or_else(|| truncated(bytes, start, N))
}

/// Read one byte at `offset`, advancing it.
///
/// # Errors
///
/// Returns [`Error::Truncated`] at the input end.
fn read_u8(bytes: &[u8], offset: &mut usize) -> Result<u8, Error> {
    let [byte] = read_array::<1>(bytes, offset)?;
    Ok(byte)
}

/// Read an `i16` at `offset`, advancing it.
///
/// # Errors
///
/// Returns [`Error::Truncated`] when fewer than two bytes remain.
fn read_i16(bytes: &[u8], offset: &mut usize, endian: Endian) -> Result<i16, Error> {
    let raw = read_array::<2>(bytes, offset)?;
    Ok(match endian {
        Endian::Big => i16::from_be_bytes(raw),
        Endian::Little => i16::from_le_bytes(raw),
    })
}

/// Read an `i32` at `offset`, advancing it.
///
/// # Errors
///
/// Returns [`Error::Truncated`] when fewer than four bytes remain.
fn read_i32(bytes: &[u8], offset: &mut usize, endian: Endian) -> Result<i32, Error> {
    let raw = read_array::<4>(bytes, offset)?;
    Ok(match endian {
        Endian::Big => i32::from_be_bytes(raw),
        Endian::Little => i32::from_le_bytes(raw),
    })
}

/// Read a `u32` at `offset`, advancing it.
///
/// # Errors
///
/// Returns [`Error::Truncated`] when fewer than four bytes remain.
fn read_u32(bytes: &[u8], offset: &mut usize, endian: Endian) -> Result<u32, Error> {
    let raw = read_array::<4>(bytes, offset)?;
    Ok(match endian {
        Endian::Big => u32::from_be_bytes(raw),
        Endian::Little => u32::from_le_bytes(raw),
    })
}

/// Read an `i16`-length-prefixed UTF-8 string at `offset`, advancing it.
///
/// # Errors
///
/// Returns [`Error::NegativeLength`] for a negative length,
/// [`Error::Truncated`] or [`Error::LengthOverflow`] when the string does not
/// fit the input, and [`Error::InvalidString`] when it is not UTF-8.
fn read_counted_string(bytes: &[u8], offset: &mut usize, endian: Endian) -> Result<String, Error> {
    let raw_len = read_i16(bytes, offset, endian)?;
    let Ok(len) = usize::try_from(raw_len) else {
        return Err(Error::NegativeLength(raw_len.into()));
    };
    let raw = read_bytes(bytes, offset, len)?;
    Ok(str::from_utf8(raw)?.to_owned())
}

/// Append an `i32` to `out`.
fn write_i32(out: &mut Vec<u8>, value: i32, endian: Endian) {
    out.extend_from_slice(&match endian {
        Endian::Big => value.to_be_bytes(),
        Endian::Little => value.to_le_bytes(),
    });
}

/// Append a `u32` to `out`.
fn write_u32(out: &mut Vec<u8>, value: u32, endian: Endian) {
    out.extend_from_slice(&match endian {
        Endian::Big => value.to_be_bytes(),
        Endian::Little => value.to_le_bytes(),
    });
}

/// Append `value` to `out` as a `u16`.
///
/// # Errors
///
/// Returns [`Error::LengthOverflow`] when `value` does not fit a `u16`.
fn write_u16_checked<T>(out: &mut Vec<u8>, value: T, endian: Endian) -> Result<(), Error>
where
    T: TryInto<u16>,
{
    let narrowed: u16 = value
        .try_into()
        .map_err(|_out_of_range| Error::LengthOverflow)?;
    out.extend_from_slice(&match endian {
        Endian::Big => narrowed.to_be_bytes(),
        Endian::Little => narrowed.to_le_bytes(),
    });
    Ok(())
}

/// Append `value` to `out` as a `u16`-length-prefixed string.
///
/// # Errors
///
/// Returns [`Error::LengthOverflow`] when the length does not fit a `u16`.
fn write_counted_string(out: &mut Vec<u8>, value: &str, endian: Endian) -> Result<(), Error> {
    write_u16_checked(out, value.len(), endian)?;
    out.extend_from_slice(value.as_bytes());
    Ok(())
}
