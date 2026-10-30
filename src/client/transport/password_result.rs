//! Password result consumption after a transport exchange.

use super::Error;
use crate::{
    client::kpasswd::{BuiltKpasswdRequest, RequestOptions, validated_result},
    kadmin,
};

/// Consume the password result after the transport has delivered the request.
///
/// # Errors
/// Wraps contextual validation and decryption failures exactly once as unknown;
/// only authenticated and contextually valid server rejection is definite.
pub(super) fn checked(
    reply: &kadmin::Reply,
    request: &BuiltKpasswdRequest,
    options: &RequestOptions,
) -> Result<kadmin::ChangePasswordResult, Error> {
    let result = validated_result(reply, request, options)
        .map_err(|source| Error::KpasswdOutcomeUnknown(Box::new(source)))?;
    result.ensure_success()?;
    Ok(result)
}
