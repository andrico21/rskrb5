//! Independent section catalogue inventory assertions.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;

    use super::super::{realm_relations::REALM_RELATIONS, section_decode::SECTION_RELATIONS};

    /// All documented realm names and the admitted compatibility names have rows.
    #[test]
    fn realm_and_section_catalogues_are_complete() -> Result<(), Box<dyn Error>> {
        let expected = [
            "admin_server",
            "auth_to_local",
            "auth_to_local_names",
            "default_domain",
            "disable_encrypted_timestamp",
            "http_anchors",
            "kdc",
            "kpasswd_server",
            "master_kdc",
            "primary_kdc",
            "sitename",
            "v4_instance_convert",
            "v4_realm",
            "pkinit_anchors",
            "pkinit_cert_match",
            "pkinit_eku_checking",
            "pkinit_dh_min_bits",
            "pkinit_identities",
            "pkinit_kdc_hostname",
            "pkinit_pool",
            "pkinit_require_crl_checking",
            "pkinit_revoke",
            "pkinit_identity",
            "pkinit_allow_upn",
            "pkinit_indicator",
            "pkinit_require_freshness",
            "pkinit_win2k",
            "pkinit_draft9",
        ];
        assert_eq!(REALM_RELATIONS.len(), 28);
        assert_eq!(REALM_RELATIONS.map(|row| row.0), expected);
        assert_eq!(
            SECTION_RELATIONS.map(|row| row.0),
            [
                "domain_realm",
                "capaths",
                "appdefaults",
                "disable",
                "enable_only",
                "module"
            ]
        );
        let first = REALM_RELATIONS.first().ok_or("empty realm catalogue")?;
        assert_eq!(first.0, "admin_server");
        for (name, kind, default, consumer, rationale, test) in
            REALM_RELATIONS.iter().chain(SECTION_RELATIONS.iter())
        {
            assert_eq!(name, test);
            assert!(
                [kind, default, consumer, rationale]
                    .iter()
                    .all(|field| !field.is_empty()),
                "metadata for {name}"
            );
        }
        Ok(())
    }
}
