//! Service-authority regressions run in isolated child processes.

use core::error::Error;
use std::{env, process::Command};

use super::{
    kdc_addr, kpasswd_addr, latest_kdc_addr, old_kdc_addr, resdom_kdc_addr, short_kdc_addr,
};

/// Every service keeps literal IPv6 intact and applies its selected port.
#[test]
fn service_authorities_preserve_ipv6() -> Result<(), Box<dyn Error>> {
    // Given an isolated child environment with distinct service ports.
    if env::var_os("RSKRB5_T4_ENDPOINT_CHILD").is_some() {
        let host = env::var("TEST_KDC_ADDR")?;
        let expected_host = env::var("RSKRB5_T4_EXPECTED_HOST")?;
        for (actual, port) in [
            (kdc_addr(), "1088"),
            (short_kdc_addr(), "1058"),
            (old_kdc_addr(), "1078"),
            (latest_kdc_addr(), "1098"),
            (resdom_kdc_addr(), "1188"),
            (kpasswd_addr(), "1464"),
        ] {
            // When each environment-backed helper selects an authority.
            let expected = if host == "[::1]:2088" {
                host.clone()
            } else {
                format!("{expected_host}:{port}")
            };
            // Then the explicit authority wins, otherwise the service port is retained.
            assert_eq!(actual, expected);
        }
        return Ok(());
    }
    for (host, expected) in [
        ("::1", "[::1]"),
        ("2001:db8::1:2", "[2001:db8::1:2]"),
        ("[::1]:2088", "[::1]"),
        ("127.0.0.1", "127.0.0.1"),
        ("kdc.example", "kdc.example"),
    ] {
        let mut command = Command::new(env::current_exe()?);
        let _: &mut Command = command
            .args([
                "endpoints::tests::service_authorities_preserve_ipv6",
                "--exact",
                "--nocapture",
            ])
            .env("RSKRB5_T4_ENDPOINT_CHILD", "1")
            .env("RSKRB5_T4_EXPECTED_HOST", expected);
        for name in [
            "TEST_KDC_ADDR",
            "TEST_SHORT_KDC_ADDR",
            "TEST_OLD_KDC_ADDR",
            "TEST_LATEST_KDC_ADDR",
            "TEST_RESDOM_KDC_ADDR",
            "TEST_KPASSWD_ADDR",
        ] {
            let _: &mut Command = command.env(name, host);
        }
        for (name, port) in [
            ("TEST_KDC_PORT", "1088"),
            ("TEST_SHORT_KDC_PORT", "1058"),
            ("TEST_OLD_KDC_PORT", "1078"),
            ("TEST_LATEST_KDC_PORT", "1098"),
            ("TEST_RESDOM_KDC_PORT", "1188"),
            ("TEST_KPASSWD_PORT", "1464"),
        ] {
            let _: &mut Command = command.env(name, port);
        }
        let output = command.output()?;
        assert!(
            output.status.success(),
            "authority child failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "child must execute one test"
        );
    }
    Ok(())
}
