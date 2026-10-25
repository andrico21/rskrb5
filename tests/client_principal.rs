#![expect(missing_docs, reason = "lint-migration: upstream baseline at ee9cb04")]
#![cfg(feature = "messages")]

use pretty_assertions::assert_eq;
use rskrb5::client::{Error, Principal};

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::expect_used,
        clippy::missing_panics_doc,
        clippy::tests_outside_test_module,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn principal_helpers_parse_user_and_service_names() {
    assert_eq!(
        Principal::parse_user("testuser1@TEST.GOKRB5").expect("user parses"),
        Principal::user("TEST.GOKRB5", "testuser1")
    );
    assert_eq!(
        Principal::parse_user(r"user\@name@TEST.GOKRB5").expect("escaped user parses"),
        Principal::user("TEST.GOKRB5", "user@name")
    );
    assert_eq!(
        Principal::parse_user(r"user\/name@TEST.GOKRB5").expect("escaped slash parses"),
        Principal::user("TEST.GOKRB5", "user/name")
    );
    assert_eq!(
        Principal::parse_service("HTTP/host.test.gokrb5@TEST.GOKRB5").expect("service parses"),
        Principal::new("TEST.GOKRB5", 2, ["HTTP", "host.test.gokrb5"])
    );
    assert_eq!(
        Principal::parse_service(r"HTTP/host\@name@TEST.GOKRB5").expect("escaped service parses"),
        Principal::new("TEST.GOKRB5", 2, ["HTTP", "host@name"])
    );
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::expect_used,
        clippy::missing_panics_doc,
        clippy::rest_pattern_accessible_field,
        clippy::tests_outside_test_module,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn principal_helpers_reject_malformed_names() {
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
                Principal::parse_user(value).expect_err("malformed user rejected"),
                Error::InvalidPrincipalName { .. }
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
                Principal::parse_service(value).expect_err("malformed service rejected"),
                Error::InvalidPrincipalName { .. }
            ),
            "{value:?}"
        );
    }
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            feature = "default",
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        ),
        all(
            not(feature = "default"),
            not(feature = "evaluation"),
            not(feature = "http"),
            feature = "messages",
            not(feature = "serde"),
            not(feature = "spnego"),
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::expect_used,
        clippy::missing_panics_doc,
        clippy::rest_pattern_accessible_field,
        clippy::tests_outside_test_module,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn principal_helpers_create_host_based_services() {
    assert_eq!(
        Principal::host_based_service("HTTP", "auth.cern.ch").expect("host service builds"),
        Principal::new("", 2, ["HTTP", "auth.cern.ch"])
    );
    assert_eq!(
        Principal::host_based_service_in_realm("HTTP", "auth.cern.ch", "CERN.CH")
            .expect("realm service builds"),
        Principal::new("CERN.CH", 2, ["HTTP", "auth.cern.ch"])
    );
    assert!(matches!(
        Principal::host_based_service("", "auth.cern.ch").expect_err("empty service rejected"),
        Error::InvalidPrincipalName { .. }
    ));
    assert!(matches!(
        Principal::host_based_service("HTTP", "").expect_err("empty host rejected"),
        Error::InvalidPrincipalName { .. }
    ));
    assert!(matches!(
        Principal::host_based_service_in_realm("HTTP", "auth.cern.ch", "")
            .expect_err("empty realm rejected"),
        Error::InvalidPrincipalName { .. }
    ));
}

/// Fork-authored host-based service principal tests: DNS host case folding.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
mod fork_tests {
    use core::error;

    use pretty_assertions::assert_eq;

    use super::*;

    /// Error type of the `Result`-returning tests.
    type TestError = Box<dyn error::Error>;

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
