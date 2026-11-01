//! Independent checklist copied from todo 15 item 2, not derived from the table.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;

    use super::super::relations::RELATIONS;

    /// Exact order, names, count and metadata cover all 43 planned MIT relations.
    #[test]
    fn relations_match_todo_15_item_2() -> Result<(), Box<dyn Error>> {
        let expected = [
            "allow_des3",
            "allow_rc4",
            "allow_weak_crypto",
            "canonicalize",
            "ccache_type",
            "clockskew",
            "default_ccache_name",
            "default_client_keytab_name",
            "default_keytab_name",
            "default_rcache_name",
            "default_realm",
            "default_tgs_enctypes",
            "default_tkt_enctypes",
            "dns_canonicalize_hostname",
            "dns_lookup_kdc",
            "dns_lookup_realm",
            "dns_uri_lookup",
            "enforce_ok_as_delegate",
            "err_fmt",
            "extra_addresses",
            "forwardable",
            "ignore_acceptor_hostname",
            "k5login_authoritative",
            "k5login_directory",
            "kcm_mach_service",
            "kcm_socket",
            "kdc_default_options",
            "kdc_timesync",
            "noaddresses",
            "permitted_enctypes",
            "plugin_base_dir",
            "preferred_preauth_types",
            "proxiable",
            "qualify_shortname",
            "rdns",
            "realm_try_domains",
            "renew_lifetime",
            "request_timeout",
            "spake_preauth_groups",
            "ticket_lifetime",
            "udp_preference_limit",
            "verify_ap_req_nofail",
            "client_aware_channel_bindings",
        ];
        assert_eq!(RELATIONS.len(), 43);
        let first = RELATIONS.first().ok_or("empty relation catalogue")?;
        assert_eq!(first.0, "allow_des3");
        assert_eq!(RELATIONS.map(|row| row.0), expected);
        for (name, kind, default, consumer, rationale, test) in RELATIONS {
            assert_eq!(name, test);
            assert!(
                [kind, default, consumer, rationale]
                    .iter()
                    .all(|column| !column.is_empty()),
                "metadata for {name}"
            );
        }
        Ok(())
    }
}
