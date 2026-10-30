//! Budgeted first-PAC traversal, independent of service authorization policy.

use rasn::der;
use rasn_kerberos::AuthorizationData;

use super::{AD_IF_RELEVANT, AD_WIN2K_PAC, Error, Pac};

/// Finds the first PAC while sharing the byte budget across the bounded tree.
///
/// # Errors
///
/// Returns the errors documented by [`super::find_pac_in_authorization_data`].
pub(super) fn find(
    data: &AuthorizationData,
    depth: usize,
    remaining: &mut usize,
) -> Result<Option<Pac>, Error> {
    for entry in data {
        *remaining = remaining
            .checked_sub(entry.data.len())
            .ok_or(Error::AuthorizationDataByteLimit)?;
        match entry.r#type {
            AD_WIN2K_PAC => return Ok(Some(Pac::parse_and_process(entry.data.as_ref())?)),
            AD_IF_RELEVANT | 8_i32 => {
                (depth < 8).ok_or(Error::AuthorizationDataDepthLimit)?;
                let nested = der::decode::<AuthorizationData>(entry.data.as_ref())
                    .map_err(|error| Error::DerDecode(error.to_string()))?;
                if let Some(pac) = find(&nested, depth.saturating_add(1), remaining)? {
                    return Ok(Some(pac));
                }
            }
            _ => {}
        }
    }
    Ok(None)
}
