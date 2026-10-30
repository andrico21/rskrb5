//! Availability gates for explicitly requested live fixtures.

use core::error::Error;
use std::{
    env,
    io::{self, Write as _},
    process::{Command, Stdio},
};

use super::{endpoints::kdc_addr, tests::tcp_reachable};

/// Returns whether the privileged tests run: integration on, `TESTPRIVILEGED=1` and `kinit` found.
///
/// Reports a skip on stderr.
pub(super) fn privileged_integration_enabled() -> Result<bool, Box<dyn Error>> {
    if env::var("TESTPRIVILEGED").as_deref() != Ok("1") {
        writeln!(
            io::stderr(),
            "skipping privileged Docker KDC integration test; set TESTPRIVILEGED=1 to enable"
        )?;
        return Ok(false);
    }
    if !integration_enabled()? {
        return Ok(false);
    }
    if !required_command_available("kinit")? {
        writeln!(
            io::stderr(),
            "skipping privileged Docker KDC integration test; set a PATH-accessible kinit binary to enable"
        )?;
        return Ok(false);
    }
    Ok(true)
}

/// Check the primary KDC for tests that need only that fixture.
pub(super) fn integration_enabled() -> Result<bool, Box<dyn Error>> {
    integration_enabled_for(&[(kdc_addr(), "primary KDC")])
}

/// Check only the fixtures used by the selected test.
///
/// Reports an optional skip on stderr. `INTEGRATION_REQUIRED=1` instead fails
/// when an explicitly requested fixture is unavailable.
pub(super) fn integration_enabled_for(
    endpoints: &[(String, &str)],
) -> Result<bool, Box<dyn Error>> {
    if env::var("INTEGRATION").as_deref() != Ok("1") {
        writeln!(
            io::stderr(),
            "skipping Docker KDC integration test; set INTEGRATION=1 to enable"
        )?;
        return Ok(false);
    }
    for (endpoint, label) in endpoints {
        if !tcp_reachable(endpoint, label)? {
            writeln!(
                io::stderr(),
                "skipping Docker KDC integration test; cannot reach {label} endpoint at {endpoint}"
            )?;
            return unavailable(&format!("cannot reach {label} endpoint at {endpoint}"));
        }
    }
    Ok(true)
}

/// Returns whether the `kvno` tests run: the privileged tests run and `kvno` is found.
pub(super) fn privileged_kvno_integration_enabled() -> Result<bool, Box<dyn Error>> {
    if !privileged_integration_enabled()? {
        return Ok(false);
    }
    if !required_command_available("kvno")? {
        writeln!(
            io::stderr(),
            "skipping privileged Docker KDC kvno tests; set a PATH-accessible kvno binary to enable"
        )?;
        return Ok(false);
    }
    Ok(true)
}

/// Returns whether `program --version` can be started from `PATH`.
fn command_available(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// Report an unavailable requested prerequisite without hiding required runs.
pub(super) fn unavailable(reason: &str) -> Result<bool, Box<dyn Error>> {
    if env::var("INTEGRATION_REQUIRED").as_deref() == Ok("1") {
        Err(io::Error::other(format!(
            "required integration fixture unavailable: {reason}"
        ))
        .into())
    } else {
        Ok(false)
    }
}

/// Check a requested MIT executable, failing required runs when it is missing.
fn required_command_available(program: &str) -> Result<bool, Box<dyn Error>> {
    if command_available(program) {
        Ok(true)
    } else {
        unavailable(&format!("missing executable {program}"))
    }
}

/// Required-mode subprocess regressions.
#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[path = "preflight_tests.rs"]
mod tests;
