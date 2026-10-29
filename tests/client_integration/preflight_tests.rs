//! Required-mode failures are observed in isolated test processes.

use core::error::Error;
use std::{env, net::TcpListener, process::Command};

use super::{integration_enabled, required_command_available};

/// Execute the gate in a child while the parent asserts the process outcome.
fn required_fixture(required: bool) -> Result<(), Box<dyn Error>> {
    let name = if required {
        "preflight::tests::required_closed_fixture_fails"
    } else {
        "preflight::tests::optional_closed_fixture_skips"
    };
    if env::var_os("RSKRB5_T4_PREFLIGHT_CHILD").is_some() {
        let _enabled = integration_enabled()?;
        return Ok(());
    }
    // Given a closed loopback endpoint and an isolated requested integration run.
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    drop(listener);
    let output = Command::new(env::current_exe()?)
        .args([name, "--exact", "--nocapture"])
        .env("RSKRB5_T4_PREFLIGHT_CHILD", "1")
        .env("INTEGRATION", "1")
        .env("INTEGRATION_REQUIRED", if required { "1" } else { "0" })
        .env("TEST_KDC_ADDR", address.to_string())
        .output()?;
    // When the fixture preflight runs, then required mode cannot pass a skip.
    assert_eq!(
        output.status.success(),
        !required,
        "child output: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("running 1 test"),
        "child must run exactly one test"
    );
    Ok(())
}

/// Requested but unavailable fixtures fail required integration runs.
#[test]
fn required_closed_fixture_fails() -> Result<(), Box<dyn Error>> {
    required_fixture(true)
}

/// Optional integration runs retain their explicit skip behavior.
#[test]
fn optional_closed_fixture_skips() -> Result<(), Box<dyn Error>> {
    required_fixture(false)
}

/// A missing requested executable cannot turn required mode into a passing skip.
#[test]
fn required_missing_executable_fails() -> Result<(), Box<dyn Error>> {
    // Given an isolated required run with a nonexistent executable.
    if env::var_os("RSKRB5_T4_COMMAND_CHILD").is_some() {
        let _available = required_command_available("rskrb5-nonexistent-fixture-command")?;
        return Ok(());
    }
    // When the preflight result becomes the child test's result.
    let output = Command::new(env::current_exe()?)
        .args([
            "preflight::tests::required_missing_executable_fails",
            "--exact",
            "--nocapture",
        ])
        .env("RSKRB5_T4_COMMAND_CHILD", "1")
        .env("INTEGRATION_REQUIRED", "1")
        .env("PATH", "")
        .output()?;
    // Then the child fails rather than passing without exercising the fixture.
    assert!(
        !output.status.success(),
        "missing required executable passed"
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("running 1 test"),
        "child must run one test"
    );
    Ok(())
}
