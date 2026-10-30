//! In-memory credential-cache replacement.

use super::{Error, Tokio, ccache_principal};
use crate::ccache;

impl Tokio {
    /// Replace this client's non-configuration entries in an existing ccache.
    ///
    /// X-CACHECONF metadata and entries for other clients are preserved. The
    /// ccache default principal is set to this client's principal.
    /// # Errors
    ///
    /// Returns [`Error::TimeOverflow`] when a session time does not fit the ccache
    /// time format.
    #[inline]
    pub fn update_ccache(&self, cache: &mut ccache::CCache) -> Result<(), Error> {
        let client = ccache_principal(&self.client);
        *cache.default_principal_mut() = client.clone();
        drop(cache.remove_entries_for_client(&client));
        for credential in self.ccache_credentials()? {
            drop(cache.upsert_credential(credential));
        }
        Ok(())
    }
}
