//! Tests of the MIT parity manifest, its todo index and its generated Markdown.

use std::fs;

use toml::Value;

use crate::{
    Feature, TestError,
    model::{manifest, read, todo_index},
    render::{STATUSES, markdown},
    rules::check_rules,
    sources::{
        anchor_exists, cargo_features, check_test_name, declares, rejected_feature_variants,
        rust_sources,
    },
};

/// Upstream tag every row is pinned to.
const UPSTREAM_REF: &str = "krb5-1.22.2-final";
/// Areas of the MIT inventory, the middle segment of each id.
const AREAS: [&str; 14] = [
    "client", "preauth", "crypto", "ccache", "keytab", "config", "dns", "gss", "admin", "pac",
    "authz", "plugin", "trace", "removed",
];
/// Evidence classes a row may claim.
const EVIDENCE: [&str; 6] = [
    "unit",
    "fixture",
    "live-local",
    "live-ci",
    "unproven",
    "blocked",
];
/// Dispositions other than the work packages `WP-01`..`WP-20`.
const DISPOSITIONS: [&str; 5] = ["ALREADY", "POL-01", "D1", "D2", "D13"];

/// Whether `disposition` is a work package `WP-01`..`WP-20`.
fn is_work_package(disposition: &str) -> bool {
    disposition
        .strip_prefix("WP-")
        .filter(|digits| digits.len() == 2)
        .and_then(|digits| digits.parse::<u8>().ok())
        .is_some_and(|number| (1..=20).contains(&number))
}

/// Whether `id` is `MIT-<area>-<n>` with a positive `n` without leading zeros.
fn well_formed(feature: &Feature) -> bool {
    let number = feature
        .id
        .strip_prefix("MIT-")
        .and_then(|rest| rest.strip_prefix(feature.area.as_str()))
        .and_then(|rest| rest.strip_prefix('-'));
    let canonical = number.is_some_and(|digits| {
        !digits.starts_with('0') && digits.parse::<u16>().is_ok_and(|value| value > 0)
    });
    canonical && AREAS.contains(&feature.area.as_str())
}

/// Ids are unique and well-formed, and every enumerated field holds a known value.
#[test]
fn rows_are_well_formed_with_known_values() -> Result<(), TestError> {
    // Given the manifest rows.
    let (_, features) = manifest()?;
    let mut ids = Vec::new();
    for feature in &features {
        // When each row's id and enumerated fields are read.
        let disposition = feature.disposition.as_str();
        // Then malformed or unknown values fail.
        assert!(well_formed(feature), "{}: malformed id or area", feature.id);
        assert!(!ids.contains(&feature.id), "{}: duplicate id", feature.id);
        ids.push(feature.id.clone());
        assert_eq!(
            feature.upstream_ref, UPSTREAM_REF,
            "{}: upstream ref",
            feature.id
        );
        assert!(
            !feature.capability.trim().is_empty(),
            "{}: empty capability",
            feature.id
        );
        assert!(
            STATUSES.contains(&feature.status.as_str()),
            "{}: status",
            feature.id
        );
        assert!(
            EVIDENCE.contains(&feature.evidence.as_str()),
            "{}: evidence",
            feature.id
        );
        let known = DISPOSITIONS.contains(&disposition) || is_work_package(disposition);
        assert!(known, "{}: disposition {disposition}", feature.id);
    }
    Ok(())
}

/// Dispositions, statuses and closing todos follow the manifest rules.
#[test]
fn dispositions_statuses_and_closing_todos_are_consistent() -> Result<(), TestError> {
    // Given the manifest rows and the committed todo index.
    let (_, features) = manifest()?;
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
    // Given the manifest rows and the checkout's sources, features and rejection variants.
    let (_, features) = manifest()?;
    let sources = rust_sources("src")?;
    let flags = cargo_features()?;
    let variants = rejected_feature_variants()?;
    for feature in &features {
        // When each cited item is looked up lexically.
        for name in &feature.test_names {
            check_test_name(name)?;
        }
        // Then a missing item fails closed.
        for symbol in &feature.rust_symbols {
            assert!(
                declares(&sources, symbol),
                "{}: undeclared symbol {symbol}",
                feature.id
            );
        }
        for flag in &feature.cargo_features {
            assert!(
                flags.contains(flag),
                "{}: unknown Cargo feature {flag}",
                feature.id
            );
        }
        if let Some(variant) = &feature.rejection {
            assert!(
                variants.contains(variant),
                "{}: no RejectedFeature::{variant}",
                feature.id
            );
        }
        if feature.status == "rejected" {
            let anchor = feature.doc_anchor.as_deref().unwrap_or_default();
            assert!(
                anchor.starts_with("docs/security-policy.md#"),
                "{}: D2 anchor",
                feature.id
            );
            assert!(feature.rejection.is_some(), "{}: D2 variant", feature.id);
        }
        if let Some(anchor) = &feature.doc_anchor {
            assert!(
                anchor_exists(anchor)?,
                "{}: missing anchor {anchor}",
                feature.id
            );
        }
    }
    Ok(())
}

/// The summary counts equal the per-status row counts.
#[test]
fn summary_counts_match_rows() -> Result<(), TestError> {
    // Given the manifest summary and rows.
    let (table, features) = manifest()?;
    let summary = table
        .get("summary")
        .and_then(Value::as_table)
        .ok_or("summary")?;
    // When each status is counted.
    // Then every count and the total match.
    for status in STATUSES {
        let counted = features
            .iter()
            .filter(|feature| feature.status == status)
            .count();
        let stated = summary
            .get(&status.replace('-', "_"))
            .and_then(Value::as_integer);
        assert_eq!(
            stated.and_then(|count| usize::try_from(count).ok()),
            Some(counted),
            "summary.{status}"
        );
    }
    let total = summary.get("total").and_then(Value::as_integer);
    assert_eq!(
        total.and_then(|count| usize::try_from(count).ok()),
        Some(features.len()),
        "summary.total"
    );
    Ok(())
}

/// The committed Markdown equals the rendering of the manifest (CRLF-safe).
#[test]
fn markdown_matches_manifest() -> Result<(), TestError> {
    // Given the manifest and its committed Markdown, empty when absent.
    let (table, features) = manifest()?;
    let committed = read("docs/mit-krb5-parity.md").unwrap_or_default();
    // When the Markdown is generated again.
    let generated = markdown(&table, &features)?;
    // Then any drift fails and leaves the regenerated file for review.
    if committed != generated {
        let fresh = format!("{}/mit-krb5-parity.md", env!("CARGO_TARGET_TMPDIR"));
        fs::write(&fresh, &generated)?;
        assert_eq!(
            committed, generated,
            "docs/mit-krb5-parity.md drifted; regenerated copy at {fresh}"
        );
    }
    Ok(())
}
