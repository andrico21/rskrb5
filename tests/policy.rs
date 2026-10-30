//! Autonomous public policy API regression tests; no network or ambient inputs.

/// Typed rejection propagation.
#[cfg(test)]
#[path = "policy/rejections.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod rejections;
