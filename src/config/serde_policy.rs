//! Serde selection guards; opaque cache/key records are not selecting configuration.
use serde::{Deserialize as _, Deserializer, de::Error as _};

use super::{EnctypeExpr, ParseMode, Toggle};
use crate::{
    crypto::selection,
    error::{Policy, RejectedFeature, RejectionReason},
};

/// Reject positive D2 names while preserving expressions for policy resolution.
/// # Errors
/// Returns serde's error envelope for a typed policy or expression rejection.
pub(super) fn enctypes<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let names = Vec::<String>::deserialize(deserializer)?;
    if !names.is_empty() {
        drop(
            EnctypeExpr::parse(&names.join(" "))
                .and_then(|expr| {
                    expr.resolve(Toggle::Enabled, Toggle::Enabled, ParseMode::Compatible)
                })
                .map_err(D::Error::custom)?,
        );
    }
    Ok(names)
}

/// Weak crypto is never a deserializable permission.
/// # Errors
/// Returns a serde error containing the permanent typed-policy explanation.
pub(super) fn weak<'de, D>(deserializer: D) -> Result<Toggle, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Toggle::deserialize(deserializer)?;
    if value.is_enabled() {
        return Err(D::Error::custom(Policy::RejectedFeature {
            feature: RejectedFeature::WeakCrypto,
            reason: RejectionReason::InsecureByDesign,
        }));
    }
    Ok(value)
}

/// Reject forbidden checksum selection at deserialization, not after use.
/// # Errors
/// Returns serde's error envelope for a permanent checksum-policy refusal.
pub(super) fn checksum<'de, D>(deserializer: D) -> Result<i32, D::Error>
where
    D: Deserializer<'de>,
{
    let id = i32::deserialize(deserializer)?;
    selection::reject_checksum(id).map_err(D::Error::custom)?;
    Ok(id)
}
