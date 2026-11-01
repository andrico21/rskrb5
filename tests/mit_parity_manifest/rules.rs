//! Disposition, status, evidence and closing-todo rules of one manifest row.

extern crate alloc;

use alloc::collections::BTreeSet;

use crate::Feature;

/// Checks the disposition, status and closing-todo rules of one row.
pub(crate) fn check_rules(feature: &Feature, todos: &BTreeSet<(i64, i64)>) {
    let (id, status, disposition) = (
        &feature.id,
        feature.status.as_str(),
        feature.disposition.as_str(),
    );
    let finished_elsewhere = matches!(disposition, "ALREADY" | "D1");
    assert_eq!(
        disposition == "ALREADY",
        finished_elsewhere && status == "implemented",
        "{id}: ALREADY rows are implemented"
    );
    assert_eq!(
        disposition == "D1",
        status == "out-of-scope",
        "{id}: out-of-scope only with D1"
    );
    assert_eq!(
        disposition == "D13",
        status == "omitted",
        "{id}: omitted only with D13"
    );
    assert_eq!(
        matches!(disposition, "D2" | "POL-01"),
        status == "rejected",
        "{id}: rejected only with D2/POL-01"
    );
    assert_eq!(
        feature.closing.is_none(),
        finished_elsewhere,
        "{id}: closing todo presence"
    );
    if let Some(closing) = feature.closing {
        assert!(
            todos.contains(&closing),
            "{id}: closing todo {closing:?} not in the index"
        );
    }
    for contributor in &feature.contributors {
        let parsed = contributor
            .strip_prefix('P')
            .and_then(|rest| rest.split_once('-'));
        let pair = parsed.and_then(|(plan, todo)| Some((plan.parse().ok()?, todo.parse().ok()?)));
        assert!(
            pair.is_some_and(|key| todos.contains(&key)),
            "{id}: contributor {contributor}"
        );
    }
    let has_tests = !feature.test_names.is_empty();
    let unproven = matches!(feature.evidence.as_str(), "unproven" | "blocked");
    assert_eq!(
        has_tests, !unproven,
        "{id}: evidence status must match the named tests"
    );
    match status {
        "implemented" | "rejected" => assert!(has_tests, "{id}: {status} without a named test"),
        _ => assert!(
            !feature.missing.is_empty(),
            "{id}: {status} must say what is missing"
        ),
    }
    if status == "implemented" {
        assert!(
            feature.missing.is_empty(),
            "{id}: implemented rows miss nothing"
        );
    }
    if status == "partial" && feature.closing.is_some_and(|(plan, _)| plan == 1) {
        assert!(
            feature.missing.contains("P2-"),
            "{id}: missing must name a plan-2 contributor"
        );
    }
    if status == "rejected" || status == "omitted" {
        assert!(
            feature.doc_anchor.is_some(),
            "{id}: {status} rows need a documentation anchor"
        );
    }
}
