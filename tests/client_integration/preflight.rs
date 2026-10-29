//! Availability gates for explicitly requested live fixtures.

use core::error::Error;
use std::{
    env,
    io::{self, Write as _},
    process::{Command, Stdio},
};

#[cfg(feature = "spnego")]
use super::tests::http_service_reachable;
use super::{
    endpoints::{
        kdc_addr, kpasswd_addr, latest_kdc_addr, old_kdc_addr, resdom_kdc_addr, short_kdc_addr,
    },
    tests::tcp_reachable,
};

/// Returns whether the privileged tests run: integration on, `TESTPRIVILEGED=1` and `kinit` found.
///
/// Reports a skip on stderr.
pub(super) fn privileged_integration_enabled() -> Result<bool, Box<dyn Error>> {
    if !integration_enabled()? {
        return Ok(false);
    }
    if env::var("TESTPRIVILEGED").as_deref() != Ok("1") {
        writeln!(
            io::stderr(),
            "skipping privileged Docker KDC integration test; set TESTPRIVILEGED=1 to enable"
        )?;
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

/// Returns whether the Docker tests run: `INTEGRATION=1` and every fixture reachable.
///
/// Reports an optional skip on stderr. `INTEGRATION_REQUIRED=1` instead fails
/// when an explicitly requested fixture is unavailable.
pub(super) fn integration_enabled() -> Result<bool, Box<dyn Error>> {
    if env::var("INTEGRATION").as_deref() != Ok("1") {
        writeln!(
            io::stderr(),
            "skipping Docker KDC integration test; set INTEGRATION=1 to enable"
        )?;
        return Ok(false);
    }
    let endpoints = [
        (kdc_addr(), "primary KDC"),
        (old_kdc_addr(), "legacy KDC"),
        (latest_kdc_addr(), "AES-SHA2 KDC"),
        (resdom_kdc_addr(), "resource KDC"),
        (short_kdc_addr(), "short-ticket KDC"),
    ];
    for (endpoint, label) in endpoints {
        if !tcp_reachable(&endpoint, label)? {
            writeln!(
                io::stderr(),
                "skipping Docker KDC integration test; cannot reach {label} endpoint at {endpoint}"
            )?;
            return unavailable(&format!("cannot reach {label} endpoint at {endpoint}"));
        }
    }
    if env::var("TEST_KPASSWD").as_deref() == Ok("1") && !tcp_reachable(&kpasswd_addr(), "kpasswd")?
    {
        writeln!(
            io::stderr(),
            "skipping Docker KDC integration test; cannot reach kpasswd endpoint at {}",
            kpasswd_addr()
        )?;
        return unavailable("cannot reach requested kpasswd endpoint");
    }
    #[cfg(feature = "spnego")]
    if !http_service_reachable()? {
        return unavailable("cannot reach HTTP fixture");
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
fn unavailable(reason: &str) -> Result<bool, Box<dyn Error>> {
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
