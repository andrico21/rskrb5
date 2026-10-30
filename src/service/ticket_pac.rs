//! Ticket PAC verification.

use super::{EncryptionKey, Error, Pac, pac, validate_authorization_data};

/// Validate every ticket restriction before extracting and verifying its first PAC.
///
/// # Errors
///
/// Returns authorization-policy errors or [`Error::Pac`] for PAC parsing/checksum failures.
pub(super) fn verified_ticket_pac(
    data: Option<&rasn_kerberos::AuthorizationData>,
    key: &EncryptionKey,
) -> Result<Option<Pac>, Error> {
    validate_authorization_data(data, true)?;
    let Some(elements) = data else {
        return Ok(None);
    };
    let pac = pac::find_pac_in_authorization_data(elements)?;
    if let Some(value) = &pac {
        value.verify(key)?;
    }
    Ok(pac)
}
