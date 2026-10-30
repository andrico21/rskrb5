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

/// MIT expression resolution without profile-parser wiring.
#[cfg(test)]
#[path = "policy/expressions.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod expressions;

/// Property-based ordered-list regression coverage.
#[cfg(test)]
#[path = "policy/ordering.rs"]
mod ordering;

/// Profile and common runtime policy integration.
#[cfg(test)]
#[path = "policy/profile.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod profile;

/// Repeated-relation security constraints.
#[cfg(test)]
#[path = "policy/repeated.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod repeated;
