//! Client principal tests: user and service name parsing and host-based services.
#![cfg(feature = "messages")]

/// Client principal tests: user and service name parsing and host-based services.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error;

    use pretty_assertions::assert_eq;
    use rskrb5_ng::client::{Error, Principal};

    /// Error type of the `Result`-returning tests.
    type TestError = Box<dyn error::Error>;

    /// Pins the parsing of user and service principal names, escapes included.
    #[test]
    fn principal_helpers_parse_user_and_service_names() -> Result<(), TestError> {
        assert_eq!(
            Principal::parse_user("testuser1@TEST.GOKRB5")
                .map_err(|cause| format!("user parses: {cause}"))?,
            Principal::user("TEST.GOKRB5", "testuser1")
        );
        assert_eq!(
            Principal::parse_user(r"user\@name@TEST.GOKRB5")
                .map_err(|cause| format!("escaped user parses: {cause}"))?,
            Principal::user("TEST.GOKRB5", "user@name")
        );
        assert_eq!(
            Principal::parse_user(r"user\/name@TEST.GOKRB5")
                .map_err(|cause| format!("escaped slash parses: {cause}"))?,
            Principal::user("TEST.GOKRB5", "user/name")
        );
        assert_eq!(
            Principal::parse_service("HTTP/host.test.gokrb5@TEST.GOKRB5")
                .map_err(|cause| format!("service parses: {cause}"))?,
            Principal::new("TEST.GOKRB5", 2, ["HTTP", "host.test.gokrb5"])
        );
        assert_eq!(
            Principal::parse_service(r"HTTP/host\@name@TEST.GOKRB5")
                .map_err(|cause| format!("escaped service parses: {cause}"))?,
            Principal::new("TEST.GOKRB5", 2, ["HTTP", "host@name"])
        );
        Ok(())
    }

    /// Pins that malformed user and service principal names are rejected.
    #[test]
    fn principal_helpers_reject_malformed_names() -> Result<(), TestError> {
        for value in [
            "",
            "testuser1",
            "@TEST.GOKRB5",
            "testuser1@",
            "testuser1@TEST.GOKRB5@EXTRA",
            r"testuser1\",
            "testuser1/extra@TEST.GOKRB5",
        ] {
            assert!(
                matches!(
                    Principal::parse_user(value)
                        .err()
                        .ok_or("malformed user rejected")?,
                    Error::InvalidPrincipalName {
                        value: _,
                        reason: _
                    }
                ),
                "{value:?}"
            );
        }

        for value in [
            "HTTP@TEST.GOKRB5",
            "HTTP/@TEST.GOKRB5",
            "HTTP/host.test.gokrb5@",
            "HTTP/host.test.gokrb5@TEST.GOKRB5@EXTRA",
            r"HTTP/host.test.gokrb5\",
        ] {
            assert!(
                matches!(
                    Principal::parse_service(value)
                        .err()
                        .ok_or("malformed service rejected")?,
                    Error::InvalidPrincipalName {
                        value: _,
                        reason: _
                    }
                ),
                "{value:?}"
            );
        }
        Ok(())
    }

    /// Pins the construction of host-based service principals and their rejected inputs.
    #[test]
    fn principal_helpers_create_host_based_services() -> Result<(), TestError> {
        assert_eq!(
            Principal::host_based_service("HTTP", "auth.cern.ch")
                .map_err(|cause| format!("host service builds: {cause}"))?,
            Principal::new("", 2, ["HTTP", "auth.cern.ch"])
        );
        assert_eq!(
            Principal::host_based_service_in_realm("HTTP", "auth.cern.ch", "CERN.CH")
                .map_err(|cause| format!("realm service builds: {cause}"))?,
            Principal::new("CERN.CH", 2, ["HTTP", "auth.cern.ch"])
        );
        assert!(matches!(
            Principal::host_based_service("", "auth.cern.ch")
                .err()
                .ok_or("empty service rejected")?,
            Error::InvalidPrincipalName {
                value: _,
                reason: _
            }
        ));
        assert!(matches!(
            Principal::host_based_service("HTTP", "")
                .err()
                .ok_or("empty host rejected")?,
            Error::InvalidPrincipalName {
                value: _,
                reason: _
            }
        ));
        assert!(matches!(
            Principal::host_based_service_in_realm("HTTP", "auth.cern.ch", "")
                .err()
                .ok_or("empty realm rejected")?,
            Error::InvalidPrincipalName {
                value: _,
                reason: _
            }
        ));
        Ok(())
    }

    /// Pins that host-based service names fold the DNS host to lower case.
    #[test]
    fn host_based_service_folds_dns_host_case() -> Result<(), TestError> {
        assert_eq!(
            Principal::host_based_service("HTTP", "AUTH.CERN.CH")
                .map_err(|cause| format!("host service builds: {cause}"))?,
            Principal::new("", 2, ["HTTP", "auth.cern.ch"])
        );
        assert_eq!(
            Principal::host_based_service_in_realm("HTTP", "Auth.Cern.Ch", "CERN.CH")
                .map_err(|cause| format!("realm service builds: {cause}"))?,
            Principal::new("CERN.CH", 2, ["HTTP", "auth.cern.ch"])
        );
        assert_eq!(
            Principal::parse_service("HTTP/AUTH.CERN.CH@CERN.CH")
                .map_err(|cause| format!("explicit parser runs: {cause}"))?,
            Principal::new("CERN.CH", 2, ["HTTP", "AUTH.CERN.CH"])
        );
        Ok(())
    }

    /// Pins that host-based service names keep the service and realm case.
    #[test]
    fn host_based_service_preserves_service_and_realm_case() -> Result<(), TestError> {
        let upper = Principal::host_based_service_in_realm("HTTP", "host.example.com", "CERN.CH")
            .map_err(|cause| format!("realm service builds: {cause}"))?;
        assert_eq!(upper.components.first().map(String::as_str), Some("HTTP"));
        assert_eq!(upper.realm, "CERN.CH");

        let lower = Principal::host_based_service_in_realm("http", "HOST.EXAMPLE.COM", "Cern.Ch")
            .map_err(|cause| format!("realm service builds: {cause}"))?;
        assert_eq!(lower.components.first().map(String::as_str), Some("http"));
        assert_eq!(
            lower.components.get(1).map(String::as_str),
            Some("host.example.com")
        );
        assert_eq!(lower.realm, "Cern.Ch");
        Ok(())
    }
}
