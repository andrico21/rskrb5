# Release authority, CI docs and fixture secrets: review dispositions

This file records the dispositions for the release workflow, the CI
documentation and the fixture-runner items of the review backlog. Full
commands, red runs and exit codes are in `task-38-rskrb5-ng-own-way.log`.

## Acceptance checkpoint

Every fixed item has a red run recorded before its fix. A scratch reversal of
only that item's fix hunks makes the named tests fail again; both results are in
the evidence log. Final acceptance is recorded under `TODO 38 FINAL ACCEPTANCE`
in the same log: STRICT, Windows clippy, FULL-TEST, DOCTEST, stable and nightly
docs, both nightly format checks, taplo, the workflow YAML parse, every gate
and the exact-once ID check of this table against the plan.
The tests read `.github/` and `scripts/` from the repository checkout. Both are
excluded from (or slated for exclusion from) the package, so these tests need
the repository, not an extracted crate. Todo 42 should exclude
`tests/gokrb5_parity_manifest.rs` from the package as well.

| ID | Status | Tests and commit | Behaviour change for CHANGELOG | Dismissal evidence |
| --- | --- | --- | --- | --- |
| run-2 lead `release.publish.crates-io-token.unprotected-tag-authorization` | fixed | `release_find_tag_job_holds_no_secret_and_reports_untagged_runs`, `release_publish_job_requires_tag_environment_and_main_ancestry`, `release_registry_token_reaches_only_the_publish_upload` (`tests/gokrb5_parity_manifest.rs`); commit `0a39c95` | The Release workflow has two jobs. `find-tag` holds no secret and no environment. When no `v`-prefixed tag points at the commit, it prints `No vN.N.N tag points at <sha>` and outputs an empty tag. It accepts only `v`-prefixed tags and fails when more than one tag matches. `publish` runs only when a tag was found, in the `release` environment, whose required reviewer is `andrico21`. It checks that the tag still points at the commit CI verified and that this commit is an ancestor of `origin/main`. The registry token is used only by the upload step, which runs `cargo publish --locked --no-verify` after the dry run has verified the tree without the token. The repository settings are listed below. | N/A |
| RSK-E0AFE152 | fixed | `parity_gates_correspond_to_fork_ci_jobs`, `manifest_and_runbooks_cite_only_fork_workflow_inputs` (`tests/gokrb5_parity_manifest.rs`), `python3 scripts/check-github-ad-gate.py --self-test`; commit `649d7f5` | `scripts/check-github-ad-gate.py --dispatch` reads `ci.yml` before making any GitHub call. While `workflow_dispatch` lacks the inputs the helper passes (`integration`, `test_ad`, `test_ad_dry_run`, `test_kpasswd`), it exits 2 and dispatches nothing. Previously it dispatched inputs the fork's workflow does not declare. Every parity gate in `docs/gokrb5-parity.toml` now names its fork CI job (`ci_job`). The five Docker MIT gates proven only by upstream runs have the new status `historical-upstream`, cite those runs with the attribution `historical upstream clelange/rskrb5` and are no longer `required_for_release`. The AD gate's command is the readiness check. `docs/gated-integration.md`, `docs/github-ad-gate-setup.md` and the `ci.yml` header state that the fork's CI has no Docker integration or AD job. The runbooks target `andrico21/rskrb5-ng`. | N/A |
| RSK-A8D595D8 | fixed | `fixture_runner_env_file_is_private_and_redacted` (`tests/gokrb5_parity_manifest.rs`, Unix), which runs `scripts/run-gated-integration.sh self-test`; commit `c567041` | The fixture runner writes its environment file to `target/gated-integration/gated-integration.env`. The directory is dedicated to the runner and set to mode 0700; a symlink or a directory owned by another user is refused. The file is staged under a fresh mode-0600 `mktemp` name and renamed into place, so an earlier permissive file is replaced, not rewritten. `env` prints every non-empty keytab `*_HEX`/`*_BASE64` value as `<redacted>`. `stop`, and `run` on exit, delete the file. `RSKRB5_INTEGRATION_ENV_FILE` is replaced by `RSKRB5_INTEGRATION_ENV_DIR`; the old variable now fails with exit 2. Docker access is probed only when a command first needs Docker. | N/A |

## Repository settings (applied by todo 38)

The todo text asks for both settings, so they were applied with `gh api`.
The commands, payloads and `GET` verifications are in the evidence log.

- **Environment `release`**:
  - `PUT repos/andrico21/rskrb5-ng/environments/release`.
  - Protection rule `required_reviewers` with the single reviewer `andrico21` (user id 44984087).
  - `prevent_self_review: false`: the owner is the only reviewer and also cuts the tag, so self-review prevention would deadlock every release.
  - `wait_timer: 0` and no deployment branch policy. A `workflow_run` job runs on the default-branch ref, so a tag-only policy would block it.
- **Tag ruleset "release tags"** (id 25943056):
  - `POST repos/andrico21/rskrb5-ng/rulesets`.
  - Target `tag`, enforcement `active`, condition `include: ["refs/tags/v*"]`.
  - Rules `creation`, `update` and `deletion`.
  - Bypass actor: `RepositoryRole` 5 (admin), mode `always`. Only repository admins may create, move or delete a `v*` tag.

## Owner actions (not applied)

- **Move `CARGO_REGISTRY_TOKEN` into the `release` environment.** It is still a repository secret, set on 2026-10-06; `gh secret list --env release` is empty. Moving it needs the token value, which only the owner holds. Steps:
  1. `gh secret set CARGO_REGISTRY_TOKEN --env release -R andrico21/rskrb5-ng`.
  2. `gh secret delete CARGO_REGISTRY_TOKEN -R andrico21/rskrb5-ng`.

  Until then, any workflow that a writer pushes to a branch can read the repository secret. The environment gate protects the token only once it is an environment secret.
- **Historical tags `v0.1.0` to `v0.2.2`** (the `rskrb5-patched` releases). These tags already exist. A manual CI re-run on one of their commits would make `publish` wait for approval. The reviewer rejects that deployment. The job would fail anyway at "Verify crate name and version", because those trees declare `rskrb5-patched`.

## Hand-off: stale CI references in files outside this todo's ownership

These files still describe the upstream dispatch jobs. Todo 38 does not own
them, so it records them here:

- `README.md` lines 146-157: the manual Docker-backed integration job and the `integration`/`test_kpasswd` dispatch inputs. Todo 42 rewrites the README.
- `docs/gokrb5-parity.md` lines 152-157 and 175-176: the gate table still says `proven`; the manifest now says `historical-upstream`. The table also has the dispatch instructions. Todo 42 updates this file.
- `docs/ad-integration.md` lines 93, 160-161, 177-196; `docs/publishing.md` line 73; `docs/samba-ad-feasibility.md` line 120: the hosted dispatch gate.
- `FORK-NOTES.md` lines 63-71: replaced by `PROVENANCE.md` in todo 42.
- `docs/ad-integration.md` line 210: names the old environment path `target/gated-integration.env`. The path is now `target/gated-integration/gated-integration.env`, and `env` output is redacted.
- `docs/release-notes.md` lines 10-24 and 106-110: upstream 0.2.0 release notes. These are legitimate history and need only an attribution.
