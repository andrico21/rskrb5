//! Supplemental credential count admission probes.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use rskrb5_ng::{error::Pac as PacError, pac::CredentialData};

    use crate::context::{Context as _, TestError};

    /// Pins count rejection before reading or reserving nonexistent descriptors.
    #[test]
    fn credentials_rejects_count_without_descriptor_extent() -> Result<(), TestError> {
        // Given: a bounded count without the corresponding fixed descriptors.
        let bytes = count_only(64);
        // When: the public parser admits the count.
        let error = CredentialData::parse(&bytes)
            .err()
            .context("missing extent rejected")?;
        // Then: count admission fails before descriptor decoding begins.
        assert!(matches!(
            error,
            PacError::UnreasonableNdrCount {
                count: 64,
                target: _
            }
        ));
        Ok(())
    }

    /// Pins empty credential data as a valid zero-allocation boundary.
    #[test]
    fn credentials_accepts_empty_count() -> Result<(), TestError> {
        // Given: an empty credential object.
        let bytes = count_only(0);
        // When: the public parser handles it.
        let data = CredentialData::parse(&bytes).context("empty credentials parse")?;
        // Then: no supplemental packages are returned.
        assert!(data.credentials.is_empty(), "zero count has no credentials");
        Ok(())
    }

    /// Builds the current single-count wire shape; conformance is a separate review item.
    fn count_only(count: u32) -> Vec<u8> {
        let mut bytes = vec![1, 0x10, 8, 0, 0xcc, 0xcc, 0xcc, 0xcc];
        bytes.extend_from_slice(&8_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0x0002_0000_u32.to_le_bytes());
        bytes.extend_from_slice(&count.to_le_bytes());
        bytes
    }
}
