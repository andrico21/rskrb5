//! Compatibility report tests: the rendered evaluation report and its contract-area ids.
#![cfg(feature = "evaluation")]

/// Compatibility report tests.
#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use rskrb5_ng::evaluation::{
        ASN1_FIXTURES, ASSESSMENTS, REPORTS, V8_CONTRACT, render_markdown,
    };

    /// Pins that the rendered report names every candidate, contract area and fixture.
    #[test]
    fn report_mentions_all_candidates_and_contract_areas() {
        for report in REPORTS {
            assert!(
                render_markdown().contains(report.candidate.name()),
                "report names candidate {}",
                report.candidate.name()
            );
        }

        for area in V8_CONTRACT {
            assert!(
                render_markdown().contains(area.area),
                "report names contract area {}",
                area.area
            );
        }

        for fixture in ASN1_FIXTURES {
            assert!(
                render_markdown().contains(fixture.gokrb5_constant),
                "report names fixture {}",
                fixture.gokrb5_constant
            );
        }
    }

    /// Pins that every assessment references only known contract-area ids.
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
}
