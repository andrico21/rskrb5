//! Deterministic Markdown rendering of the MIT parity manifest.

use core::{fmt::Write as _, iter};

use toml::{Table, Value};

use crate::{Feature, TestError};

/// Status keys of the `[summary]` table, in rendering order.
pub(crate) const STATUSES: [&str; 6] = [
    "implemented",
    "partial",
    "absent",
    "rejected",
    "omitted",
    "out-of-scope",
];

/// Fixed prose between the summary and the feature tables.
const SCOPE: &str = "<a id=\"scope\"></a>
## Scope

The manifest covers MIT's client and service library surface. D1 rows are
KDC, kadmind, database and C-ABI machinery: they are recorded as
`out-of-scope` and no API is provided for them. D2 rows are features MIT
removed or that are insecure by design: they are `rejected` with a typed
`error::RejectedFeature` and a section of
[the security policy](security-policy.md). D13 records the owner decision to
omit the legacy Windows `API:` credential cache.

Completion means the union of this manifest and
[the gokrb5 manifest](gokrb5-parity.md), not their intersection. Each row's
closing todo is the plan todo that makes it final; `P1-N` is plan 1 todo N
and `P2-N` is plan 2 todo N, listed in `docs/parity-todo-index.toml`.

<a id=\"rust-extension-points\"></a>
## Rust extension points

MIT loads C plugin modules from `plugin_base_dir` and `module` directives. This
crate loads no code: `module` is `Config::UnsupportedDynamicModule` in every
mode, and plan 2 todo 3 adds statically registered Rust providers in place of
the C plugin interfaces.
";

/// Header of each per-area feature table.
const HEADER: &str = "| ID | Capability | Status | Evidence | Disposition | Closing | Missing | Policy and divergence | Symbols | Features | Tests |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
";

/// Escapes a table cell.
fn cell(text: &str) -> String {
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

/// Renders the policy notes of a row.
fn policy(feature: &Feature) -> String {
    let mut notes = vec![feature.divergence.clone()];
    notes.extend(
        feature
            .rejection
            .iter()
            .map(|variant| format!("`RejectedFeature::{variant}`")),
    );
    notes.extend(feature.doc_anchor.iter().map(|anchor| {
        let link = anchor.strip_prefix("docs/").unwrap_or(anchor);
        format!("[{anchor}]({link})")
    }));
    notes.retain(|note| !note.is_empty());
    cell(&notes.join(" "))
}

/// Generates `docs/mit-krb5-parity.md` from the parsed manifest.
pub(crate) fn markdown(manifest: &Table, features: &[Feature]) -> Result<String, TestError> {
    let target = manifest
        .get("target")
        .and_then(Value::as_table)
        .ok_or("target")?;
    let field = |key: &str| {
        target
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("target.{key}"))
    };
    let summary = manifest
        .get("summary")
        .and_then(Value::as_table)
        .ok_or("summary")?;
    let mut out = String::from("# MIT krb5 parity\n\n");
    out.push_str("<!-- Generated from mit-krb5-parity.toml by tests/mit_parity_manifest.rs. Do not edit. -->\n\n");
    writeln!(
        out,
        "Target: MIT krb5 {} (`{}`, released {}), inventory of {}, statuses as of `{}`.\n",
        field("release")?,
        field("upstream_ref")?,
        field("release_date")?,
        field("inventory_date")?,
        field("manifest_commit_base")?
    )?;
    out.push_str("## Summary\n\n| Status | Rows |\n| --- | ---: |\n");
    for status in STATUSES.iter().copied().chain(iter::once("total")) {
        let count = summary
            .get(&status.replace('-', "_"))
            .and_then(Value::as_integer);
        writeln!(
            out,
            "| {status} | {} |",
            count.ok_or_else(|| format!("summary.{status}"))?
        )?;
    }
    writeln!(out, "\n{SCOPE}")?;
    let mut area = "";
    for feature in features {
        if feature.area != area {
            area = &feature.area;
            writeln!(out, "\n## {area}\n")?;
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
    Ok(out)
}
