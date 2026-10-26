use super::*;

/// INVALID credential usability regressions.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use super::*;

    /// INVALID tickets remain unusable inside their time window.
    #[test]
    fn cached_service_rejects_invalid_flag() -> Result<(), TestError> {
        let tgt = current_tgt_session(1, 60)?;
        let mut ticket = tgt.clone();
        ticket.service = sample_service_principal();
        ticket.ticket_flags =
            (u32::from_be_bytes(ticket.ticket_flags) | 0x0100_0000_u32).to_be_bytes();
        let mut client = Tokio::from_tgt_session(config_without_kdcs()?, KdcProtocol::Tcp, tgt);
        client.cache_service_ticket(ticket.clone());
        assert!(client.cached_service_ticket(ticket.service).is_none());
        Ok(())
    }
}
