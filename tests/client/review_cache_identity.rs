use super::*;

/// Structured cache identity regressions.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use super::*;

    /// Embedded separators do not alias a different component sequence.
    #[test]
    fn service_cache_preserves_component_boundaries() -> Result<(), TestError> {
        let tgt = current_tgt_session(1, 60)?;
        let mut ticket = tgt.clone();
        ticket.service = Principal::new("TEST.GOKRB5", 2, ["HTTP", "a\0b"]);
        let mut client = Tokio::from_tgt_session(config_without_kdcs()?, KdcProtocol::Tcp, tgt);
        client.cache_service_ticket(ticket);
        assert!(
            client
                .cached_service_ticket(Principal::new("TEST.GOKRB5", 2, ["HTTP", "a", "b"]))
                .is_none()
        );
        Ok(())
    }
}
