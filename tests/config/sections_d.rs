//! Section-policy regressions for todo 15 D.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use core::error::Error;

    use rskrb5_ng::config::{Config, ParseMode};

    /// A realm cannot silently prohibit the timestamp mechanism still used by clients.
    #[test]
    fn encrypted_timestamp_disable_fails_closed() -> Result<(), Box<dyn Error>> {
        for mode in [ParseMode::Compatible, ParseMode::Strict] {
            for value in ["true", "on", "maybe"] {
                drop(
                    Config::parse_with_mode(
                        &format!(
                            "[realms]\n EXAMPLE = {{\n disable_encrypted_timestamp = {value}\n }}\n"
                        ),
                        mode,
                    )
                    .err()
                    .ok_or("timestamp restriction ignored")?,
                );
            }
        }
        Ok(())
    }

    /// Server sections produce strict errors even when empty.
    #[test]
    fn server_only_sections_are_not_silent() -> Result<(), Box<dyn Error>> {
        for section in ["kdcdefaults", "dbmodules", "logging"] {
            drop(
                Config::parse_with_mode(&format!("[{section}]\n"), ParseMode::Strict)
                    .err()
                    .ok_or("server section ignored")?,
            );
        }
        Ok(())
    }

    /// PKINIT enums are parsed even though authentication is unavailable.
    #[test]
    fn pkinit_invalid_enums_fail() -> Result<(), Box<dyn Error>> {
        for assignment in [
            "pkinit_eku_checking = invalid",
            "pkinit_dh_min_bits = 123",
            "pkinit_require_crl_checking = maybe",
            "pkinit_anchors = missing-prefix",
        ] {
            drop(
                Config::parse(&format!("[realms]\n EXAMPLE = {{\n {assignment}\n }}\n"))
                    .err()
                    .ok_or("malformed PKINIT accepted")?,
            );
        }
        Ok(())
    }
}
