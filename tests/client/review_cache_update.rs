use super::*;

/// Ccache conversion failures preserve the caller's complete destination.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use super::*;

    /// Invalid session timestamps cannot partially replace an existing cache.
    #[test]
    fn ccache_update_preserves_destination_when_conversion_fails() -> Result<(), TestError> {
        // Given: existing client, metadata and unrelated entries with another default principal.
        let tgt = sample_tgt_session()?;
        let old_ticket = tgt.to_ccache_credential()?;
        let mut unrelated = old_ticket.clone();
        unrelated.client = ccache::Principal::new("OTHER.REALM", 1, vec!["other".to_owned()]);
        let mut metadata = old_ticket.clone();
        metadata.server = ccache::Principal::new(
            "X-CACHECONF:",
            0,
            vec!["krb5_ccache_conf_data".to_owned(), "fast_avail".to_owned()],
        );
        let mut destination = ccache::CCache::new(unrelated.client.clone());
        destination
            .credentials_mut()
            .extend([old_ticket, metadata, unrelated]);
        let original = destination.clone();
        let original_bytes = destination.to_bytes()?;
        let invalid_times = [
            UNIX_EPOCH
                .checked_sub(Duration::from_secs(1))
                .context("pre-epoch time")?,
            UNIX_EPOCH
                .checked_add(Duration::from_secs(u64::from(u32::MAX).saturating_add(1)))
                .context("overflow time")?,
            tgt.end_time
                .checked_add(Duration::from_millis(500))
                .context("fractional time")?,
        ];
        for end_time in invalid_times {
            let mut invalid = tgt.clone();
            invalid.end_time = end_time;
            let client = Tokio::from_tgt_session(Config::new(), KdcProtocol::Tcp, invalid);

            // When: conversion fails before a replacement can be committed.
            let failure = client
                .update_ccache(&mut destination)
                .err()
                .context("conversion fails")?;

            // Then: both the value and serialized form remain unchanged.
            assert!(matches!(failure, Error::TimeOverflow));
            assert_eq!(destination, original);
            assert_eq!(destination.to_bytes()?, original_bytes);
        }
        Ok(())
    }
}
