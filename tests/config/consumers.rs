//! Profile-name expansion at existing credential consumers.

#[cfg(test)]
#[cfg(feature = "tokio")]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use crate::env as child_env;
    use core::error::Error;
    use rskrb5_ng::{
        Config, Principal, TokioClient,
        ccache::{CCache, Principal as CachePrincipal},
        client::transport::KdcProtocol,
        keytab::Keytab,
        service::Validator,
    };
    use rskrb5_ng::{
        config::parameters::Failure as ExpansionFailure,
        error::{Ccache as CacheFailure, Client as ClientFailure},
    };
    use std::{env, fs, process};

    /// Environment replacement bytes remain literal across all default loaders.
    #[test]
    fn ambient_templates_are_expanded_once() -> Result<(), Box<dyn Error>> {
        // Given a child whose temp directory contains token-shaped data.
        const TEST: &str = "consumers::tests::ambient_templates_are_expanded_once";
        if !child_env::in_child(TEST) {
            let directory = env::temp_dir().join(format!("b2-percent-{}-%{{uid}}", process::id()));
            fs::create_dir_all(&directory)?;
            let result = child_env::try_run_in_child(
                TEST,
                &[
                    ("TMPDIR", Some(directory.as_os_str())),
                    ("TEMP", Some(directory.as_os_str())),
                    ("TMP", Some(directory.as_os_str())),
                    ("KRB5CCNAME", None),
                    ("KRB5_KTNAME", None),
                    ("KRB5_CLIENT_KTNAME", None),
                ],
            );
            fs::remove_dir_all(directory)?;
            result?;
            return Ok(());
        }
        let directory = env::temp_dir();
        CCache::new(CachePrincipal::new("EXAMPLE", 1, vec!["user".to_owned()]))
            .save(directory.join("cache"))?;
        Keytab::new().save(directory.join("keytab"))?;
        let mut config = Config::new();
        config.libdefaults.default_ccache_name = "FILE:%{TEMP}/cache".to_owned();
        config.libdefaults.default_keytab_name = "FILE:%{TEMP}/keytab".to_owned();
        config.libdefaults.default_client_keytab_name = "FILE:%{TEMP}/keytab".to_owned();
        // When each existing ambient consumer falls back to the profile.
        let cache = TokioClient::from_default_ccache(config.clone(), KdcProtocol::Tcp)?;
        cache.save_default_ccache()?;
        cache.update_default_ccache()?;
        let service = Validator::from_default_keytab(&config)?;
        let client = TokioClient::with_client_keytab_from_default(
            config,
            KdcProtocol::Tcp,
            Principal::new("EXAMPLE", 1, vec!["user".to_owned()]),
        )?;
        // Then all accesses used the literal token-shaped directory.
        assert_eq!(cache.to_ccache()?.default_principal().realm, "EXAMPLE");
        drop(service);
        drop(client);
        Ok(())
    }

    /// Configured cache load/save/update all use the same expansion boundary.
    #[test]
    fn configured_cache_templates_reach_real_files() -> Result<(), Box<dyn Error>> {
        // Given a valid empty cache at the expanded, not literal, name.
        let path = env::temp_dir().join(format!("b2-cache-{}", process::id()));
        CCache::new(CachePrincipal::new("EXAMPLE", 1, vec!["user".to_owned()])).save(&path)?;
        let mut config = Config::new();
        config.libdefaults.default_ccache_name = format!("FILE:{}%{{null}}", path.display());
        // When loading, replacing and updating through configured-name consumers.
        let result = TokioClient::from_default_ccache_name(config, KdcProtocol::Tcp);
        if let Ok(client) = &result {
            client.save_default_ccache_name()?;
            client.update_default_ccache_name()?;
        }
        fs::remove_file(&path)?;
        // Then a literal %{null} filename was never required.
        let client = result?;
        assert_eq!(client.to_ccache()?.default_principal().realm, "EXAMPLE");
        Ok(())
    }

    /// Service, HTTP and client-keytab adapters resolve their configured names.
    #[test]
    fn configured_keytab_templates_reach_real_files() -> Result<(), Box<dyn Error>> {
        // Given an empty but valid keytab at the expanded path.
        let path = env::temp_dir().join(format!("b2-keytab-{}", process::id()));
        Keytab::new().save(&path)?;
        let mut config = Config::new();
        config.libdefaults.default_keytab_name = format!("FILE:{}%{{null}}", path.display());
        config.libdefaults.default_client_keytab_name =
            config.libdefaults.default_keytab_name.clone();
        // When invoking the existing high-level consumers.
        let service = Validator::from_default_keytab_name(&config);
        #[cfg(feature = "tower")]
        let http = rskrb5_ng::http::NegotiateLayer::from_default_keytab_name(&config);
        let client = TokioClient::with_client_keytab_from_config(
            config,
            KdcProtocol::Tcp,
            Principal::new("EXAMPLE", 1, vec!["user".to_owned()]),
        );
        fs::remove_file(&path)?;
        // Then every consumer successfully opens the expanded file.
        drop(service?);
        #[cfg(feature = "tower")]
        drop(http?);
        drop(client?);
        Ok(())
    }

    /// Unknown parameters fail at the consumer before any file is opened.
    #[test]
    fn unknown_templates_return_expansion_errors() -> Result<(), Box<dyn Error>> {
        // Given unsupported tokens in all three profile names.
        let mut config = Config::new();
        config.libdefaults.default_ccache_name = "FILE:%{typo}".to_owned();
        config.libdefaults.default_keytab_name = "FILE:%{typo}".to_owned();
        config.libdefaults.default_client_keytab_name = "FILE:%{typo}".to_owned();
        // When loading a configured cache.
        let failure = TokioClient::from_default_ccache_name(config, KdcProtocol::Tcp)
            .err()
            .ok_or("unknown token accepted")?;
        // Then expansion is causal, not a misleading file-not-found failure.
        assert!(
            matches!(failure, ClientFailure::CCache(CacheFailure::Expansion(ExpansionFailure::UnknownToken(token))) if token == "typo")
        );
        Ok(())
    }
}
