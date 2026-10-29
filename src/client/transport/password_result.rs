//! Password result consumption after a transport exchange.

use super::Error;
use crate::{kadmin, keytab::EncryptionKey};

/// Consume the password result after the transport has delivered the request.
///
/// # Errors
/// Returns decryption, parsing and server rejection errors.
pub(super) fn checked(
    reply: &kadmin::Reply,
    reply_key: &EncryptionKey,
) -> Result<kadmin::ChangePasswordResult, Error> {
    let result = reply
        .decrypt_result(reply_key)
        .map_err(|source| Error::KpasswdOutcomeUnknown(Box::new(Error::from(source))))?;
    result.ensure_success()?;
    Ok(result)
}
