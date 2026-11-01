//! Typed MIT DNS canonicalization selection; resolution belongs to WP-10.

use super::{Error, Toggle, parse_boolean};

/// Hostname canonicalization requested by the profile, not a DNS operation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(try_from = "Wire", into = "Wire"))]
#[non_exhaustive]
pub enum Canonicalization {
    /// Never perform DNS canonicalization.
    Never,
    /// Always canonicalize before the request (MIT default).
    #[default]
    Always,
    /// Try the supplied hostname before DNS canonicalization.
    Fallback,
}

impl Canonicalization {
    /// Parse the MIT boolean vocabulary or case-insensitive `fallback`.
    /// # Errors
    /// Returns an invalid-boolean error for any other spelling.
    #[inline]
    pub fn parse(value: &str) -> Result<Self, Error> {
        if value.eq_ignore_ascii_case("fallback") {
            Ok(Self::Fallback)
        } else {
            Ok(Self::from(Toggle::from_bool(parse_boolean(value)?)))
        }
    }

    /// Whether unconditional canonicalization was requested.
    #[inline]
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        matches!(self, Self::Always)
    }
}

impl From<Toggle> for Canonicalization {
    #[inline]
    fn from(value: Toggle) -> Self {
        match value {
            Toggle::Enabled => Self::Always,
            Toggle::Disabled => Self::Never,
        }
    }
}

/// Preserve boolean JSON compatibility while representing the third state.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(untagged)]
enum Wire {
    /// Historical boolean representation.
    Boolean(bool),
    /// MIT's additional fallback spelling.
    Text(String),
}

#[cfg(feature = "serde")]
impl From<Canonicalization> for Wire {
    fn from(value: Canonicalization) -> Self {
        match value {
            Canonicalization::Never => Self::Boolean(false),
            Canonicalization::Always => Self::Boolean(true),
            Canonicalization::Fallback => Self::Text("fallback".to_owned()),
        }
    }
}

#[cfg(feature = "serde")]
impl TryFrom<Wire> for Canonicalization {
    type Error = Error;

    #[inline]
    fn try_from(value: Wire) -> Result<Self, Self::Error> {
        match value {
            Wire::Boolean(enabled) => Ok(Toggle::from_bool(enabled).into()),
            Wire::Text(text) => Self::parse(&text),
        }
    }
}
