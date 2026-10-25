#![expect(missing_docs, reason = "lint-migration: upstream baseline at ee9cb04")]
#![cfg(feature = "evaluation")]

use rskrb5_ng::evaluation::{ASN1_FIXTURES, ASSESSMENTS, REPORTS, V8_CONTRACT, render_markdown};

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::missing_panics_doc,
        clippy::tests_outside_test_module,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn report_mentions_all_candidates_and_contract_areas() {
    let markdown = render_markdown();

    for report in REPORTS {
        assert!(markdown.contains(report.candidate.name()));
    }

    for area in V8_CONTRACT {
        assert!(markdown.contains(area.area));
    }

    for fixture in ASN1_FIXTURES {
        assert!(markdown.contains(fixture.gokrb5_constant));
    }
}

#[cfg_attr(
    any(
        all(
            feature = "default",
            feature = "evaluation",
            feature = "http",
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            feature = "tower",
            test
        ),
        all(
            feature = "default",
            feature = "evaluation",
            not(feature = "http"),
            feature = "messages",
            feature = "serde",
            feature = "spnego",
            feature = "tokio",
            not(feature = "tower"),
            test
        )
    ),
    expect(
        clippy::missing_panics_doc,
        clippy::tests_outside_test_module,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
#[test]
fn every_assessment_covers_only_known_contract_area_ids() {
    for assessment in ASSESSMENTS {
        for support in assessment.support {
            assert!(
                V8_CONTRACT.iter().any(|area| area.id == support.area_id),
                "{} references unknown area id {}",
                assessment.candidate.name(),
                support.area_id
            );
        }
    }
}
