//! Checks of the MIT krb5 parity manifest `docs/mit-krb5-parity.toml`, of the committed
//! todo index `docs/parity-todo-index.toml` it cites, and of the Markdown generated from
//! it. The manifest names repository tests, symbols and documents, so these tests read
//! them from the checkout at run time and fail closed on anything they cannot find.

include!("parity_manifest/feature.rs");

/// Typed view of the manifests and the todo index.
#[cfg(test)]
#[path = "parity_manifest/model.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod model;

/// Lexical scans of the checkout.
#[cfg(test)]
#[path = "parity_manifest/sources.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod sources;

/// Shared Markdown building blocks.
#[cfg(test)]
#[path = "parity_manifest/render.rs"]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
mod render;

/// Row consistency rules.
#[cfg(test)]
#[path = "parity_manifest/rules.rs"]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod rules;

/// Manifest-independent audits.
#[cfg(test)]
#[path = "parity_manifest/audit.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod audit;

/// Markdown rendering of the MIT manifest.
#[cfg(test)]
#[path = "mit_parity_manifest/markdown.rs"]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
mod markdown;

/// MIT manifest, index and Markdown tests.
#[cfg(test)]
#[path = "mit_parity_manifest/checks.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod checks;
