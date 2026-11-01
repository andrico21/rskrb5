//! MIT credential-name expansion contracts.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error as StdError;

    use rskrb5_ng::config::{
        Config,
        parameters::{DefaultName, ExpansionContext, Failure as Error, expand},
    };

    /// Distinct facts prevent aliasing unrelated tokens unnoticed.
    fn context() -> ExpansionContext<'static> {
        let mut context = ExpansionContext::default();
        context.temp = Some("/scratch");
        context.uid = Some(1234);
        context.euid = Some(5678);
        context.username = Some("effective-user");
        context.windows_sid = Some("S-1-5-21-1234");
        context.libdir = Some("/opt/krb/lib");
        context.bindir = Some("/opt/krb/bin");
        context.sbindir = Some("/opt/krb/sbin");
        context.userconfigdir = Some("C:\\Users\\test\\MIT\\Kerberos5");
        context.appdata = Some("C:\\Users\\test\\Roaming");
        context
    }

    /// Every supplied non-identity parameter expands to its independent fixture.
    #[test]
    fn documented_tokens_expand_when_context_is_supplied() -> Result<(), Box<dyn StdError>> {
        // Given explicit facts, including Windows directory facts on any host.
        for (token, expected) in [
            ("TEMP", "/scratch"),
            ("username", "effective-user"),
            ("null", ""),
            ("LIBDIR", "/opt/krb/lib"),
            ("BINDIR", "/opt/krb/bin"),
            ("SBINDIR", "/opt/krb/sbin"),
            ("USERCONFIGDIR", "C:\\Users\\test\\MIT\\Kerberos5"),
            ("USERCONFIG", "C:\\Users\\test\\MIT\\Kerberos5"),
            ("APPDATA", "C:\\Users\\test\\Roaming"),
        ] {
            // When expanding one parameter between literals.
            let result = expand(&format!("before%{{{token}}}after"), &context())?;
            // Then exactly that fact replaces the token.
            assert_eq!(result, format!("before{expected}after"));
        }
        Ok(())
    }

    /// Real, effective and USERID alias identities remain distinct on Linux.
    #[cfg(target_os = "linux")]
    #[test]
    fn identity_tokens_expand_when_linux() -> Result<(), Box<dyn StdError>> {
        // Given differing real and effective identities.
        let facts = context();
        // When expanding all identity tokens.
        let result = expand("%{uid}:%{euid}:%{USERID}", &facts)?;
        // Then USERID aliases the real identity, never the effective one.
        assert_eq!(result, "1234:5678:1234");
        Ok(())
    }

    /// The existing Linux-only uid/euid contract cannot be bypassed with context.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn uid_tokens_fail_when_platform_is_unsupported() -> Result<(), Box<dyn StdError>> {
        // Given even explicitly supplied numeric identities on another platform.
        for token in ["uid", "euid"] {
            // When attempting expansion.
            let result = expand(&format!("%{{{token}}}"), &context())
                .err()
                .ok_or("unsupported token expanded")?;
            // Then numeric process identity remains unsupported.
            assert!(matches!(result, Error::Unavailable(name) if name == token));
        }
        Ok(())
    }

    /// Windows USERID uses the supplied SID without enabling uid/euid.
    #[cfg(windows)]
    #[test]
    fn userid_expands_when_windows_sid_is_supplied() -> Result<(), Box<dyn StdError>> {
        // Given a SID rather than an environment username.
        let facts = context();
        // When resolving USERID.
        let result = expand("%{USERID}", &facts)?;
        // Then its security identifier is preserved.
        assert_eq!(result, "S-1-5-21-1234");
        Ok(())
    }

    /// Unknown, empty, prefix-only and mis-cased names are typed errors.
    #[test]
    fn unknown_tokens_fail_when_not_exactly_named() -> Result<(), Box<dyn StdError>> {
        // Given tokens outside the documented exact vocabulary.
        for token in ["missing", "", "TEM", "temp", "UID"] {
            // When expanding the unknown token.
            let result = expand(&format!("%{{{token}}}"), &context())
                .err()
                .ok_or("unknown token expanded")?;
            // Then the error retains the offending name.
            assert_eq!(result, Error::UnknownToken(token.to_owned()));
        }
        Ok(())
    }

    /// A missing closing brace never becomes a literal credential path.
    #[test]
    fn malformed_tokens_fail_when_unterminated() -> Result<(), Box<dyn StdError>> {
        // Given incomplete tokens after ordinary or expanded text.
        for template in ["%{", "prefix%{TEMP", "%{null}%{"] {
            // When expanding the template.
            let result = expand(template, &context())
                .err()
                .ok_or("unterminated token expanded")?;
            // Then syntax fails explicitly.
            assert_eq!(result, Error::UnterminatedToken);
        }
        Ok(())
    }

    /// MIT searches for `%{`; doubled percent signs are not an escape syntax.
    #[test]
    fn percent_signs_remain_literal_when_not_a_token() -> Result<(), Box<dyn StdError>> {
        // Given literal percents and a token preceded by another percent.
        let template = "%%|%|%x|%%{TEMP}|end%";
        // When expanding once.
        let result = expand(template, &context())?;
        // Then only the actual token is consumed.
        assert_eq!(result, "%%|%|%x|%/scratch|end%");
        Ok(())
    }

    /// Replacement data is never interpreted as more template syntax.
    #[test]
    fn replacements_remain_literal_when_they_contain_percent() -> Result<(), Box<dyn StdError>> {
        // Given a replacement containing both valid and malformed token text.
        let mut facts = context();
        facts.temp = Some("\u{e9}/%%/%{uid}/%{unknown}/%{");
        // When expanding adjacent parameters once.
        let result = expand("%{TEMP}%{null}%{TEMP}", &facts)?;
        // Then inserted percent signs and Unicode survive byte-for-byte.
        assert_eq!(
            result,
            "\u{e9}/%%/%{uid}/%{unknown}/%{\u{e9}/%%/%{uid}/%{unknown}/%{"
        );
        Ok(())
    }

    /// A missing fact is not silently replaced by an empty string.
    #[test]
    fn absent_facts_fail_when_requested() -> Result<(), Box<dyn StdError>> {
        // Given an entirely explicit empty context.
        let facts = ExpansionContext::default();
        // When requesting a missing directory.
        let result = expand("%{TEMP}", &facts)
            .err()
            .ok_or("missing fact expanded")?;
        // Then only null is allowed to mean empty.
        assert_eq!(result, Error::Unavailable("TEMP"));
        Ok(())
    }

    /// Literal templates and null need no ambient or caller identity facts.
    #[test]
    fn literals_expand_when_context_is_empty() -> Result<(), Box<dyn StdError>> {
        // Given templates that need no discovery.
        for (template, expected) in [("", ""), ("FILE:literal", "FILE:literal"), ("%{null}", "")] {
            // When expanding with no facts at all.
            let result = expand(template, &ExpansionContext::default())?;
            // Then literals and null are fully deterministic.
            assert_eq!(result, expected);
        }
        Ok(())
    }

    /// Each profile-name selection propagates typed expansion failure.
    #[test]
    fn profile_names_fail_when_selected_token_is_unknown() -> Result<(), Box<dyn StdError>> {
        // Given an invalid token in every parameterized relation.
        let config = Config::parse(
            "[libdefaults]\ndefault_ccache_name = FILE:%{typo}\ndefault_keytab_name = FILE:%{typo}\ndefault_client_keytab_name = FILE:%{typo}\n",
        )?;
        for name in [
            DefaultName::Ccache,
            DefaultName::Keytab,
            DefaultName::ClientKeytab,
        ] {
            // When resolving that name, not merely parsing the raw template.
            let result = name.expand(&config.libdefaults, &context());
            // Then no invalid token is silently used as a path.
            assert_eq!(result, Err(Error::UnknownToken("typo".to_owned())));
        }
        Ok(())
    }

    /// All three relations use first-wins profile selection and the same expander.
    #[test]
    fn profile_names_expand_when_selected_with_context() -> Result<(), Box<dyn StdError>> {
        // Given duplicate relations with distinct templates and a non-name relation.
        let config = Config::parse(
            "[libdefaults]\ndefault_ccache_name = FILE:%{TEMP}/cc\ndefault_ccache_name = FILE:wrong\ndefault_keytab_name = FILE:%{LIBDIR}/server\ndefault_client_keytab_name = FILE:%{BINDIR}/client\ndefault_realm = %{UNKNOWN}\n",
        )?;
        for (name, expected) in [
            (DefaultName::Ccache, "FILE:/scratch/cc"),
            (DefaultName::Keytab, "FILE:/opt/krb/lib/server"),
            (DefaultName::ClientKeytab, "FILE:/opt/krb/bin/client"),
        ] {
            // When resolving the selected profile name with explicit facts.
            let result = name.expand(&config.libdefaults, &context())?;
            // Then expansion is confined to that credential-name relation.
            assert_eq!(result, expected);
        }
        assert_eq!(config.libdefaults.default_realm, "%{UNKNOWN}");
        assert_eq!(config.libdefaults.default_ccache_name, "FILE:%{TEMP}/cc");
        Ok(())
    }
}
