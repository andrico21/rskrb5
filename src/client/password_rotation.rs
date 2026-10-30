//! Password credential rotation eligibility after confirmed success.

use super::{Principal, Tokio, TokioClientCredentials, principal_matches};

/// Whether the changed target owns this client's stored password credential.
pub(super) fn should_rotate(client: &Tokio, target: &Principal) -> bool {
    principal_matches(target, &client.client)
        && matches!(
            client.credentials,
            Some(TokioClientCredentials::Password(_))
        )
}
