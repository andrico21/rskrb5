//! Missing identity facts must not select a different credential by fallback.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;

    use rskrb5_ng::config::{
        Config,
        parameters::{DefaultName, ExpansionContext, Failure},
    };

    /// Missing username/installation/SID facts are errors, not usable guessed names.
    #[test]
    fn missing_facts_fail_closed_for_every_credential_name() -> Result<(), Box<dyn Error>> {
        for token in ["username", "LIBDIR", "BINDIR", "SBINDIR", "USERID"] {
            for (relation, name) in [
                ("default_ccache_name", DefaultName::Ccache),
                ("default_keytab_name", DefaultName::Keytab),
                ("default_client_keytab_name", DefaultName::ClientKeytab),
            ] {
                let config = Config::parse(&format!(
                    "[libdefaults]\n {relation} = FILE:/%{{{token}}}/credential\n"
                ))?;
                let failure = name
                    .expand(&config.libdefaults, &ExpansionContext::default())
                    .err()
                    .ok_or("missing fact accepted")?;
                assert!(matches!(failure, Failure::Unavailable(missing) if missing == token));
                let mut context = ExpansionContext::default();
                context.username = Some("named-user");
                context.libdir = Some("lib");
                context.bindir = Some("bin");
                context.sbindir = Some("sbin");
                context.uid = Some(42);
                context.windows_sid = Some("S-1-5-21-example");
                if token != "USERID" || cfg!(any(target_os = "linux", windows)) {
                    let value = name.expand(&config.libdefaults, &context)?;
                    assert!(!value.contains("%{"), "all requested facts supplied");
                }
            }
        }
        Ok(())
    }

    /// Existing ambient consumers preserve the typed unavailable cause before file access.
    #[cfg(feature = "tokio")]
    #[test]
    fn ambient_unknown_identity_is_not_a_fallback() -> Result<(), Box<dyn Error>> {
        use rskrb5_ng::{
            TokioClient,
            client::transport::KdcProtocol,
            error::{Ccache, Client},
        };
        for token in ["username", "LIBDIR", "BINDIR", "SBINDIR"] {
            let config = Config::parse(&format!(
                "[libdefaults]\n default_ccache_name = FILE:/%{{{token}}}/cache\n"
            ))?;
            let failure = TokioClient::from_default_ccache_name(config, KdcProtocol::Tcp)
                .err()
                .ok_or("ambient fact guessed")?;
            assert!(
                matches!(failure, Client::CCache(Ccache::Expansion(Failure::Unavailable(missing))) if missing == token)
            );
        }
        Ok(())
    }
}
