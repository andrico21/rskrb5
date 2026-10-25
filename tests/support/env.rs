//! Runs one test in a child test process with a changed environment.
//!
//! A test that needs environment variables re-executes its own test binary,
//! filtered to itself, with the variables set or removed on the child
//! process. No test mutates the environment of a running test process.

use std::{env, ffi::OsStr, process::Command};

/// Marks the child process and names the one test it runs.
const CHILD_TEST_ENV: &str = "RSKRB5_TEST_CHILD";

/// Returns whether this process is the child run of `test_path`.
pub(crate) fn in_child(test_path: &str) -> bool {
    env::var_os(CHILD_TEST_ENV) == Some(test_path.into())
}

/// Runs the test `test_path` alone in a child process of this test binary.
///
/// Each `(key, Some(value))` sets `key` and each `(key, None)` removes `key`
/// in the child environment. `test_path` is the libtest name of the test,
/// as printed by `--list`.
///
/// # Panics
///
/// Panics if the child cannot be started, if it fails, or if it does not
/// run and pass exactly one test, so a misspelled `test_path` fails.
pub(crate) fn run_in_child(test_path: &str, env: &[(&str, Option<&OsStr>)]) {
    let failure = try_run_in_child(test_path, env).err();
    assert!(failure.is_none(), "{}", failure.unwrap_or_default());
}

/// Runs the test `test_path` alone in a child process of this test binary.
///
/// The environment is changed as in [`run_in_child`].
///
/// # Errors
///
/// Returns the report of the child run if the child cannot be started, if it
/// fails, or if it does not run and pass exactly one test, so a misspelled
/// `test_path` fails.
pub(crate) fn try_run_in_child(
    test_path: &str,
    env: &[(&str, Option<&OsStr>)],
) -> Result<(), String> {
    let run = env::current_exe().and_then(|executable| {
        let mut command = Command::new(executable);
        let _: &mut Command =
            command.args([test_path, "--exact", "--nocapture", "--test-threads=1"]);
        for &(key, value) in env {
            let _: &mut Command = match value {
                Some(set) => command.env(key, set),
                None => command.env_remove(key),
            };
        }
        let _: &mut Command = command.env(CHILD_TEST_ENV, test_path);
        command.output()
    });

    match run {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if output.status.success() && stdout.contains("test result: ok. 1 passed;") {
                return Ok(());
            }
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!(
                "child run of {test_path} did not pass exactly one test ({}):\n\
                 --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
                output.status
            ))
        }
        Err(error) => Err(format!(
            "child run of {test_path} did not pass exactly one test (the child test process did not start: {error})"
        )),
    }
}
