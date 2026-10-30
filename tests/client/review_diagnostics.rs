use super::*;

/// Structured client diagnostics regressions.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use super::*;

    /// Pins that client diagnostics report the keytab and the KDC state.
    #[cfg(all(feature = "tokio", feature = "serde"))]
    #[test]
    fn tokio_client_diagnostics_reports_keytab_and_kdc_state() -> Result<(), TestError> {
        let client = Tokio::with_keytab(
            config_with_kdc()?,
            KdcProtocol::Auto,
            Principal::user("TEST.GOKRB5", "testuser1"),
            keytab_with_reply_key(1)?,
        );

        let diagnostics = runtime()?.block_on(client.diagnostics());

        assert_eq!(diagnostics.client, "testuser1");
        assert_eq!(diagnostics.realm, "TEST.GOKRB5");
        assert_eq!(diagnostics.protocol, "Auto");
        assert_eq!(diagnostics.credential_source, "keytab");
        assert!(!diagnostics.has_tgt);
        assert_eq!(diagnostics.tgt_session_count, 0);
        assert_eq!(diagnostics.service_ticket_cache_count, 0);
        assert_eq!(diagnostics.default_tkt_enctypes, [18_i32, 17_i32]);
        assert_eq!(diagnostics.preferred_preauth_types, [18_i32, 17_i32]);
        assert_eq!(diagnostics.keytab_enctypes, [18_i32]);
        assert_eq!(diagnostics.udp_kdcs, ["kdc.test.gokrb5:88"]);
        assert_eq!(diagnostics.tcp_kdcs, ["kdc.test.gokrb5:88"]);
        assert_eq!(
            diagnostics.errors,
            [
                "default_tkt_enctypes specifies 17 but this enctype is not available in the client's keytab",
                "preferred_preauth_types specifies 17 but this enctype is not available in the client's keytab",
            ]
        );
        assert!(!diagnostics.is_ok());

        let json = runtime()?
            .block_on(client.diagnostics_json())
            .context("diagnostics JSON renders")?;
        assert!(json.contains(r#""CredentialSource": "keytab""#));
        assert!(json.contains(r#""UDPKDCs": ["#));
        assert!(json.contains(r#""TCPKDCs": ["#));
        Ok(())
    }
}
