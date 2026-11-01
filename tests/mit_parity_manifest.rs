//! Checks of the MIT krb5 parity manifest `docs/mit-krb5-parity.toml`, of the committed
//! todo index `docs/parity-todo-index.toml` it cites, and of the Markdown generated from
//! it. The manifest names repository tests, symbols and documents, so these tests read
//! them from the checkout at run time and fail closed on anything they cannot find.

#[cfg(test)]
use core::error::Error;

/// Error type of the manifest helpers and tests.
#[cfg(test)]
type TestError = Box<dyn Error>;

/// One `[[feature]]` row of the manifest.
#[cfg(test)]
struct Feature {
    /// Source row id, such as `MIT-client-1`.
    id: String,
    /// Inventory area, the middle segment of the id.
    area: String,
    /// Upstream tag the row is pinned to.
    upstream_ref: String,
    /// Upstream capability text.
    capability: String,
    /// `implemented`, `partial`, `absent`, `rejected`, `omitted` or `out-of-scope`.
    status: String,
    /// Strongest evidence class backing the named tests.
    evidence: String,
    /// What is still missing, or why nothing is in scope.
    missing: String,
    /// Public Rust items delivering the row.
    rust_symbols: Vec<String>,
    /// `path::function` names of the tests proving the row.
    test_names: Vec<String>,
    /// Cargo features the named symbols need.
    cargo_features: Vec<String>,
    /// Deliberate divergence from MIT behavior.
    divergence: String,
    /// `ALREADY`, `WP-NN`, `POL-01`, `D1`, `D2` or `D13`.
    disposition: String,
    /// Closing plan and todo number, absent for `ALREADY` and `D1` rows.
    closing: Option<(i64, i64)>,
    /// Contributing todos, such as `P2-4`.
    contributors: Vec<String>,
    /// `RejectedFeature` variant of a rejected row.
    rejection: Option<String>,
    /// `docs/<file>.md#<anchor>` reference.
    doc_anchor: Option<String>,
}

/// Typed view of the manifest and the todo index.
#[cfg(test)]
#[path = "mit_parity_manifest/model.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod model;

/// Lexical scans of the checkout.
#[cfg(test)]
#[path = "mit_parity_manifest/sources.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod sources;

/// Markdown rendering of the manifest.
#[cfg(test)]
#[path = "mit_parity_manifest/render.rs"]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
mod render;

/// Row consistency rules.
#[cfg(test)]
#[path = "mit_parity_manifest/rules.rs"]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod rules;

/// Manifest, index and Markdown tests.
#[cfg(test)]
#[path = "mit_parity_manifest/checks.rs"]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod checks;
