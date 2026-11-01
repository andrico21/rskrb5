//! Tests of the MIT parity manifest, its todo index and its generated Markdown.

use crate::{
    Spec, TestError,
    audit::{check_evidence, check_markdown, check_shape, check_summary},
    markdown::markdown,
    model::{manifest, todo_index},
    rules::check_rules,
};

/// The MIT manifest and its generated Markdown.
const MIT: Spec = Spec {
    manifest: "docs/mit-krb5-parity.toml",
    markdown: "docs/mit-krb5-parity.md",
    prefix: "MIT",
    upstream_ref: "krb5-1.22.2-final",
    generate: markdown,
};
/// Areas of the MIT inventory, the middle segment of each id.
const AREAS: [&str; 14] = [
    "client", "preauth", "crypto", "ccache", "keytab", "config", "dns", "gss", "admin", "pac",
    "authz", "plugin", "trace", "removed",
];

/// Ids are unique and well formed, and every enumerated field holds a known value.
#[test]
fn rows_are_well_formed_with_known_values() -> Result<(), TestError> {
    // Given the manifest rows.
    let (_, features) = manifest(MIT.manifest)?;
    // When each row's id and enumerated fields are read.
    // Then malformed or unknown values fail.
    check_shape(&MIT, &AREAS, &features);
    for feature in &features {
        let grouped = feature.parity_area.is_some() || !feature.related.is_empty();
        assert!(!grouped, "{}: gokrb5-only fields on an MIT row", feature.id);
    }
    Ok(())
}

/// Dispositions, statuses and closing todos follow the manifest rules.
#[test]
fn dispositions_statuses_and_closing_todos_are_consistent() -> Result<(), TestError> {
    // Given the manifest rows and the committed todo index.
    let (_, features) = manifest(MIT.manifest)?;
    let todos = todo_index()?;
    // When each row is checked against the rules.
    // Then any inconsistent row fails.
    for feature in &features {
        check_rules(feature, &todos);
    }
    Ok(())
}

/// Every named test, symbol, feature flag, rejection variant and anchor exists.
#[test]
fn named_evidence_exists_in_the_checkout() -> Result<(), TestError> {
    // Given the manifest rows.
    let (_, features) = manifest(MIT.manifest)?;
    // When each cited item is looked up lexically in the checkout.
    // Then a missing item fails closed.
    check_evidence(&features)
}

/// The summary counts equal the per-status row counts.
#[test]
fn summary_counts_match_rows() -> Result<(), TestError> {
    // Given the manifest summary and rows.
    let (table, features) = manifest(MIT.manifest)?;
    // When each status is counted.
    // Then every count and the total match.
    check_summary(&table, "summary", &features)
}

/// The committed Markdown equals the rendering of the manifest (CRLF-safe).
#[test]
fn markdown_matches_manifest() -> Result<(), TestError> {
    // Given the manifest.
    let (table, features) = manifest(MIT.manifest)?;
    // When the Markdown is generated again.
    // Then any drift fails and leaves the regenerated file for review.
    check_markdown(&MIT, &table, &features)
}
