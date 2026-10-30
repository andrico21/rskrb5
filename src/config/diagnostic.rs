/// Treatment of secure configuration features that are not implemented yet.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[non_exhaustive]
pub enum ParseMode {
    /// Skip only explicitly classified secure unsupported features with diagnostics.
    #[default]
    Compatible,
    /// Reject unsupported secure features as well as forbidden or unknown input.
    Strict,
}

/// A configuration selection that could not take effect in compatible mode.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Diagnostic {
    /// A removed draft-9 mechanism was ignored in a preference list.
    IgnoredPreauthType {
        /// Ignored PA type, never selected for an outgoing exchange.
        id: i32,
    },
    /// A secure encryption type is known but not implemented in this release.
    UnsupportedSecureEnctype {
        /// Original expression token, including its prefix and case.
        token: String,
        /// Work package required before this selection can take effect.
        until: &'static str,
    },
}
