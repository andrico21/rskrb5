//! Deterministic Markdown building blocks shared by the parity manifests.

use core::{fmt::Write as _, iter};

use toml::{Table, Value};

use crate::{Feature, TestError};

/// Status keys of a `[summary]` table, in rendering order.
pub(crate) const STATUSES: [&str; 6] = [
    "implemented",
    "partial",
    "absent",
    "rejected",
    "omitted",
    "out-of-scope",
];

/// Header of each feature table.
const HEADER: &str = "| ID | Capability | Status | Evidence | Disposition | Closing | Missing | Policy and divergence | Symbols | Features | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
";

/// Escapes a table cell; an empty cell renders as `-`.
pub(crate) fn cell(text: &str) -> String {
    if text.is_empty() {
        return "-".to_owned();
    }
    text.replace('|', "\\|").replace('\n', " ")
}

/// Renders a list of code spans.
fn codes(items: &[String]) -> String {
    let spans: Vec<String> = items.iter().map(|item| format!("`{item}`")).collect();
    cell(&spans.join(", "))
}

/// Renders the closing todo and contributors of a row.
fn closing(feature: &Feature) -> String {
    let mut parts: Vec<String> = feature
        .closing
        .iter()
        .map(|&(plan, todo)| format!("P{plan}-{todo}"))
        .collect();
    parts.extend(feature.contributors.iter().map(|todo| format!("+{todo}")));
    cell(&parts.join(" "))
}

/// Renders a `docs/<file>.md#<anchor>` reference as a link relative to `docs/`.
pub(crate) fn doc_link(anchor: &str) -> String {
    let link = anchor.strip_prefix("docs/").unwrap_or(anchor);
    format!("[{anchor}]({link})")
}

/// Renders the policy notes of a row.
fn policy(feature: &Feature) -> String {
    let mut notes = vec![feature.divergence.clone()];
    notes.extend(
        feature
            .rejection
            .iter()
            .map(|variant| format!("`RejectedFeature::{variant}`")),
    );
    notes.extend(feature.doc_anchor.iter().map(|anchor| doc_link(anchor)));
    notes.retain(|note| !note.is_empty());
    cell(&notes.join(" "))
}

/// Appends the per-status summary table of `[key]` to `out`.
pub(crate) fn summary(out: &mut String, manifest: &Table, key: &str) -> Result<(), TestError> {
    let counts = manifest
        .get(key)
        .and_then(Value::as_table)
        .ok_or_else(|| format!("missing [{key}]"))?;
    out.push_str("| Status | Rows |\n| --- | ---: |\n");
    for status in STATUSES.iter().copied().chain(iter::once("total")) {
        let count = counts
            .get(&status.replace('-', "_"))
            .and_then(Value::as_integer);
        writeln!(
            out,
            "| {status} | {} |",
            count.ok_or_else(|| format!("{key}.{status}"))?
        )?;
    }
    Ok(())
}

/// Appends one feature table per value of `group`, in row order, under `level` headings.
pub(crate) fn feature_tables(
    out: &mut String,
    features: &[Feature],
    level: &str,
    group: fn(&Feature) -> &str,
) -> Result<(), TestError> {
    let mut current = None;
    for feature in features {
        if current != Some(group(feature)) {
            current = Some(group(feature));
            writeln!(out, "\n{level} {}\n", group(feature))?;
            out.push_str(HEADER);
        }
        writeln!(
            out,
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            feature.id,
            cell(&feature.capability),
            feature.status,
            feature.evidence,
            feature.disposition,
            closing(feature),
            cell(&feature.missing),
            policy(feature),
            codes(&feature.rust_symbols),
            codes(&feature.cargo_features),
            codes(&feature.test_names)
        )?;
    }
    Ok(())
}
