//! Checks of the gokrb5 parity manifest in `docs/gokrb5-parity.toml` and of the
//! repository tooling it cites: the release and CI workflows and the fixture runner.
//! The tooling files are excluded from the package, so these tests read them from
//! the repository checkout at run time.

/// gokrb5 parity manifest and repository tooling tests.
#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    extern crate alloc;

    use alloc::collections::BTreeSet;
    use core::error;
    use std::{fs, path::Path};

    use toml::{Table, Value};

    /// Error type of the `Result`-returning tests.
    type TestError = Box<dyn error::Error>;

    /// Parity areas the manifest must describe.
    const REQUIRED_AREAS: [&str; 13] = [
        "config",
        "keytab",
        "ccache",
        "crypto",
        "messages",
        "kadmin-kpasswd",
        "client",
        "service",
        "gssapi-spnego",
        "pac",
        "docker-mit",
        "active-directory",
        "non-goals",
    ];
    /// Statuses a parity area may have.
    const ALLOWED_AREA_STATUSES: [&str; 7] = [
        "covered",
        "covered-with-gated-evidence",
        "covered-needs-ad-evidence",
        "partial",
        "needs-live-evidence",
        "blocked-on-lab",
        "intentionally-out-of-scope",
    ];
    /// Parity gates the manifest must describe.
    const REQUIRED_GATES: [&str; 7] = [
        "linux-docker-mit-full",
        "linux-docker-mit-kpasswd",
        "linux-docker-dns-srv",
        "linux-docker-privileged-ccache",
        "linux-docker-http-spnego",
        "active-directory-testad",
        "http-client-wrapper",
    ];
    /// Statuses a parity gate may have.
    const ALLOWED_GATE_STATUSES: [&str; 4] =
        ["proven", "unproven", "blocked-on-lab", "missing-api"];

    /// Pins the manifest's gokrb5 target, its required parity areas and its required gates.
    #[test]
    fn gokrb5_parity_manifest_has_expected_target_and_areas() -> Result<(), TestError> {
        let manifest: Table = include_str!("../docs/gokrb5-parity.toml").parse()?;

        check_target(&manifest)?;
        let area_ids = check_areas(&manifest)?;
        check_gates(&manifest, &area_ids)
    }

    /// Asserts the gokrb5 module, version, release date and release URL of the manifest target.
    fn check_target(manifest: &Table) -> Result<(), TestError> {
        let target = manifest
            .get("target")
            .and_then(Value::as_table)
            .ok_or("manifest has target table")?;
        assert_eq!(
            target.get("module").and_then(Value::as_str),
            Some("github.com/jcmturner/gokrb5/v8")
        );
        assert_eq!(
            target.get("version").and_then(Value::as_str),
            Some("v8.4.4")
        );
        assert_eq!(
            target.get("release_date").and_then(Value::as_str),
            Some("2023-02-25")
        );
        assert_eq!(
            target.get("release_url").and_then(Value::as_str),
            Some("https://github.com/jcmturner/gokrb5/releases/tag/v8.4.4")
        );
        Ok(())
    }

    /// Asserts every parity area and the required ones; returns the area ids.
    fn check_areas(manifest: &Table) -> Result<BTreeSet<String>, TestError> {
        let areas = manifest
            .get("area")
            .and_then(Value::as_array)
            .ok_or("manifest has area array")?;
        assert!(!areas.is_empty(), "manifest should describe parity areas");

        let mut ids = BTreeSet::new();
        for area_value in areas {
            let area = area_value.as_table().ok_or("area entry is a table")?;
            let id = area
                .get("id")
                .and_then(Value::as_str)
                .ok_or("area has id")?;
            assert!(ids.insert(id.to_owned()), "duplicate area id {id}");

            let status = area
                .get("status")
                .and_then(Value::as_str)
                .ok_or("area has status")?;
            assert!(
                ALLOWED_AREA_STATUSES.contains(&status),
                "area {id} has unknown status {status}"
            );

            let evidence = area
                .get("evidence")
                .and_then(Value::as_array)
                .ok_or("area has evidence array")?;
            assert!(!evidence.is_empty(), "area {id} should list evidence");

            let next = area
                .get("next")
                .and_then(Value::as_array)
                .ok_or("area has next array")?;
            if status != "covered" && status != "intentionally-out-of-scope" {
                assert!(
                    !next.is_empty(),
                    "area {id} with status {status} should list next work"
                );
            }
        }

        for id in REQUIRED_AREAS {
            assert!(ids.contains(id), "missing required parity area {id}");
        }
        Ok(ids)
    }

    /// Asserts every parity gate, the areas it proves, and the required gates.
    fn check_gates(manifest: &Table, area_ids: &BTreeSet<String>) -> Result<(), TestError> {
        let gates = manifest
            .get("gate")
            .and_then(Value::as_array)
            .ok_or("manifest has gate array")?;
        assert!(!gates.is_empty(), "manifest should describe parity gates");

        let mut gate_ids = BTreeSet::new();
        for gate_value in gates {
            let gate = gate_value.as_table().ok_or("gate entry is a table")?;
            let id = gate
                .get("id")
                .and_then(Value::as_str)
                .ok_or("gate has id")?;
            assert!(gate_ids.insert(id.to_owned()), "duplicate gate id {id}");
            check_gate(gate, id, area_ids)?;
        }

        for id in REQUIRED_GATES {
            assert!(gate_ids.contains(id), "missing required parity gate {id}");
        }
        Ok(())
    }

    /// Asserts the name, status, command, proved areas, flags, evidence and next work of gate `id`.
    fn check_gate(gate: &Table, id: &str, area_ids: &BTreeSet<String>) -> Result<(), TestError> {
        let name = gate
            .get("name")
            .and_then(Value::as_str)
            .ok_or("gate has name")?;
        assert!(!name.is_empty(), "gate {id} should have a non-empty name");

        let status = gate
            .get("status")
            .and_then(Value::as_str)
            .ok_or("gate has status")?;
        assert!(
            ALLOWED_GATE_STATUSES.contains(&status),
            "gate {id} has unknown status {status}"
        );

        if status != "missing-api" {
            let command = gate
                .get("command")
                .and_then(Value::as_str)
                .ok_or("gate with executable proof has command")?;
            assert!(!command.is_empty(), "gate {id} command should be non-empty");
        }

        let proved_areas = gate
            .get("proves")
            .and_then(Value::as_array)
            .ok_or("gate has proves array")?;
        assert!(
            !proved_areas.is_empty(),
            "gate {id} should list proved areas"
        );
        for proved_value in proved_areas {
            let area = proved_value
                .as_str()
                .ok_or("gate proves entries should be strings")?;
            assert!(
                area_ids.contains(area),
                "gate {id} proves unknown parity area {area}"
            );
        }

        for key in ["required_for_release", "required_for_parity"] {
            let _: bool = gate
                .get(key)
                .and_then(Value::as_bool)
                .ok_or_else(|| format!("gate {id} has boolean {key}"))?;
        }

        let evidence = gate
            .get("evidence")
            .and_then(Value::as_array)
            .ok_or("gate has evidence array")?;
        assert!(
            !evidence.is_empty(),
            "gate {id} should list current evidence"
        );

        let next = gate
            .get("next")
            .and_then(Value::as_array)
            .ok_or("gate has next array")?;
        assert!(!next.is_empty(), "gate {id} should list next work");
        Ok(())
    }

    /// Reads a repository file that the package excludes, relative to the manifest directory.
    fn repository_file(relative: &str) -> Result<String, TestError> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
        Ok(fs::read_to_string(&path)
            .map_err(|error| format!("read {}: {error}", path.display()))?)
    }

    /// Splits the `jobs:` section of a workflow into (job id, job body) pairs in file order.
    fn workflow_jobs(workflow: &str) -> Vec<(String, String)> {
        let mut jobs: Vec<(String, String)> = Vec::new();
        let mut in_jobs = false;
        for line in workflow.lines() {
            if !line.is_empty() && !line.starts_with([' ', '#']) {
                in_jobs = line == "jobs:";
                continue;
            }
            if !in_jobs {
                continue;
            }
            if let Some(key) = line
                .strip_prefix("  ")
                .and_then(|rest| rest.strip_suffix(':'))
                && !key.starts_with([' ', '#'])
            {
                jobs.push((key.to_owned(), String::new()));
            } else if let Some((_, body)) = jobs.last_mut() {
                body.push_str(line);
                body.push('\n');
            } else {
                // A comment or blank line before the first job belongs to no job.
            }
        }
        jobs
    }

    /// Returns the body of job `id` in `jobs`.
    fn job<'jobs>(jobs: &'jobs [(String, String)], id: &str) -> Result<&'jobs str, TestError> {
        jobs.iter()
            .find(|(name, _)| name == id)
            .map(|(_, body)| body.as_str())
            .ok_or_else(|| -> TestError { format!("workflow has no job {id}").into() })
    }

    /// Jobs of `.github/workflows/release.yml`.
    fn release_jobs() -> Result<Vec<(String, String)>, TestError> {
        Ok(workflow_jobs(&repository_file(
            ".github/workflows/release.yml",
        )?))
    }

    /// The tag lookup holds no secret and waits for no environment, so every green
    /// CI run reports its tag state without an approval prompt.
    #[test]
    fn release_find_tag_job_holds_no_secret_and_reports_untagged_runs() -> Result<(), TestError> {
        let jobs = release_jobs()?;
        let find_tag = job(&jobs, "find-tag")?;
        assert!(
            !find_tag.contains("secrets."),
            "find-tag must not read a secret"
        );
        assert!(
            !find_tag.contains("environment:"),
            "find-tag must not wait for an environment"
        );
        assert!(
            find_tag.contains("No vN.N.N tag points at"),
            "find-tag must report a run without a release tag"
        );
        assert!(
            find_tag.contains("tag: ${{ steps."),
            "find-tag must output the tag it found"
        );
        assert!(
            find_tag.contains("grep -E '^v[0-9]+"),
            "find-tag must accept only v-prefixed tags, the names the tag ruleset protects"
        );
        Ok(())
    }

    /// Publishing needs a tag found by `find-tag`, the reviewed `release` environment
    /// and a tagged commit that is on `main`.
    #[test]
    fn release_publish_job_requires_tag_environment_and_main_ancestry() -> Result<(), TestError> {
        let jobs = release_jobs()?;
        let publish = job(&jobs, "publish")?;
        for required in [
            "needs: find-tag",
            "if: needs.find-tag.outputs.tag != ''",
            "environment: release",
            "git merge-base --is-ancestor",
            "origin/main",
        ] {
            assert!(publish.contains(required), "publish job lacks `{required}`");
        }
        Ok(())
    }

    /// The registry token reaches only the reviewed publish job, and its upload step
    /// does not build the tagged tree (the token-free dry run verified it).
    #[test]
    fn release_registry_token_reaches_only_the_publish_upload() -> Result<(), TestError> {
        let jobs = release_jobs()?;
        let holders: Vec<&str> = jobs
            .iter()
            .filter(|(_, body)| body.contains("CARGO_REGISTRY_TOKEN"))
            .map(|(id, _)| id.as_str())
            .collect();
        assert_eq!(
            holders,
            ["publish"],
            "only the publish job may reference the registry token"
        );
        let publish = job(&jobs, "publish")?;
        assert!(
            publish.contains("cargo publish --locked --no-verify"),
            "the token-holding upload must not run the tagged tree's build scripts"
        );
        Ok(())
    }
}
