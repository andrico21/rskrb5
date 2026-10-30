//! In-memory credential-cache replacement.

use super::{Error, Tokio, ccache_principal};
use crate::ccache;

/// Convert all credentials before replacing any destination state.
///
/// # Errors
/// Returns [`Error::TimeOverflow`] for unrepresentable session times.
pub(super) fn update(kerberos: &Tokio, cache: &mut ccache::CCache) -> Result<(), Error> {
    let credentials = kerberos.ccache_credentials()?;
    let client = ccache_principal(&kerberos.client);
    *cache.default_principal_mut() = client.clone();
    drop(cache.remove_entries_for_client(&client));
    for credential in credentials {
        drop(cache.upsert_credential(credential));
    }
    Ok(())
}
