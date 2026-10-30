//! Serde selection guards; opaque cache/key records are not selecting configuration.
use alloc::collections::BTreeMap;

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

/// Check unknown configuration relations at the serde boundary, then discard them.
/// # Errors
/// Returns serde's envelope for a prohibited protocol selection.
pub(super) fn relations<'de, D>(deserializer: D) -> Result<BTreeMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    let values = BTreeMap::<String, serde_json::Value>::deserialize(deserializer)?;
    for (key, value) in values {
        let text = match value {
            serde_json::Value::String(text) => text,
            serde_json::Value::Bool(enabled) => enabled.to_string(),
            serde_json::Value::Number(number) => number.to_string(),
            serde_json::Value::Null => String::new(),
            serde_json::Value::Array(_) | serde_json::Value::Object(_) => "{".to_owned(),
        };
        super::protocol::relation(&key, &text).map_err(D::Error::custom)?;
    }
    Ok(BTreeMap::new())
}

/// Preserve informational preference IDs so the diagnostic accessor can report them.
/// # Errors
/// Returns serde's error for malformed integer lists.
pub(super) fn preferences<'de, D>(deserializer: D) -> Result<Vec<i32>, D::Error>
where
    D: Deserializer<'de>,
{
    Vec::<i32>::deserialize(deserializer)
}
