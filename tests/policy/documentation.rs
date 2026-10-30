use core::error::Error;
use std::fs;

/// Every catalogue entry must link a real packaged policy section.
#[test]
fn catalogue_policy_anchors_exist() -> Result<(), Box<dyn Error>> {
    // Given every policy link in the authoritative variant catalogue.
    let catalogue = include_str!("../../src/error/policy.rs");
    let document = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/security-policy.md"
    ))?;
    let mut count = 0_usize;
    // When resolving each linked anchor using line-based, CRLF-safe matching.
    for line in catalogue
        .lines()
        .filter(|line| line.contains("security-policy.md#"))
    {
        let anchor = line
            .split_once("security-policy.md#")
            .ok_or("anchor")?
            .1
            .split_once(')')
            .ok_or("link end")?
            .0;
        // Then missing sections cannot pass silently.
        assert!(
            document
                .lines()
                .any(|section| section.trim() == format!("<a id=\"{anchor}\"></a>")),
            "missing {anchor}"
        );
        count = count.saturating_add(1);
    }
    assert_eq!(count, 9);
    for anchor in ["policy", "residual-copies", "windows-api-ccache"] {
        assert!(
            document
                .lines()
                .any(|line| line.trim() == format!("<a id=\"{anchor}\"></a>")),
            "missing {anchor}"
        );
    }
    Ok(())
}

/// Serde preferences report removed IDs rather than silently dropping them.
#[cfg(feature = "serde")]
#[test]
fn serde_preferences_expose_ignored_ids() -> Result<(), Box<dyn Error>> {
    use rskrb5_ng::config::{ConfigDiagnostic, LibDefaults};
    // Given MIT's historical preference list serialized as configuration.
    let mut json = serde_json::to_value(LibDefaults::new())?;
    drop(json.as_object_mut().ok_or("object")?.insert(
        "preferred_preauth_types".to_owned(),
        serde_json::json!([17_i32, 16_i32, 15_i32, 14_i32]),
    ));
    // When serde admits the informational preference list.
    let defaults: LibDefaults = serde_json::from_value(json)?;
    // Then the same accessor as text parsing reports every ignored ID.
    assert!(matches!(
        defaults.diagnostics().as_ref(),
        [
            ConfigDiagnostic::IgnoredPreauthType { id: 15_i32 },
            ConfigDiagnostic::IgnoredPreauthType { id: 14_i32 }
        ]
    ));
    Ok(())
}
