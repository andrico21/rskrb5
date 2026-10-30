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
excluded from the package, and so is `tests/gokrb5_parity_manifest.rs`
(`Cargo.toml` `exclude`), so these tests run only in the repository.

| ID | Status | Tests and commit | Behaviour change for CHANGELOG | Dismissal evidence |
| --- | --- | --- | --- | --- |
| run-2 lead `release.publish.crates-io-token.unprotected-tag-authorization` | fixed | `release_find_tag_job_holds_no_secret_and_reports_untagged_runs`, `release_publish_job_requires_tag_environment_and_main_ancestry`, `release_registry_token_reaches_only_the_publish_upload` (`tests/gokrb5_parity_manifest.rs`); commit `0a39c95` | The Release workflow has two jobs. `find-tag` holds no secret and no environment. When no `v`-prefixed tag points at the commit, it prints `No vN.N.N tag points at <sha>` and outputs an empty tag. It accepts only `v`-prefixed tags and fails when more than one tag matches. `publish` runs only when a tag was found, in the `release` environment, whose required reviewer is `andrico21`. It checks that the tag still points at the commit CI verified and that this commit is an ancestor of `origin/main`. The registry token is used only by the upload step, which runs `cargo publish --locked --no-verify` after the dry run has verified the tree without the token. The repository settings are listed below. Since 2026-10-29 (follow-up row FU-OPS-01) `CARGO_REGISTRY_TOKEN` is a secret of the `release` environment only, absent from the repository secrets; the environment deploys only at tags matching `[0-9]*.[0-9]*.[0-9]*`, without admin bypass. The two jobs are now the `release.yml` coordinator and `publish.yml` (FU-CI-06, below). | N/A |
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
  - Changed by the owner on 2026-10-29 (FU-OPS-01), after `publish.yml` moved the upload to a `workflow_dispatch` run at the tag ref: the only deployment policy is the tag pattern `[0-9]*.[0-9]*.[0-9]*`, and `can_admins_bypass` is `false`.
- **Tag ruleset "release tags"** (id 25943056):
  - `POST repos/andrico21/rskrb5-ng/rulesets`.
  - Target `tag`, enforcement `active`, condition `include: ["refs/tags/v*"]`.
  - Rules `creation`, `update` and `deletion`.
  - Bypass actor: `RepositoryRole` 5 (admin), mode `always`. Only repository admins may create, move or delete a `v*` tag.
  - Changed by the owner on 2026-10-29 (owner decision D14, tags without `v`): the condition is `include: ["refs/tags/[0-9]*.[0-9]*.[0-9]*"]`.

## Owner actions (not applied by todo 38)

- **Move `CARGO_REGISTRY_TOKEN` into the `release` environment.** Done by the owner on 2026-10-29 (FU-OPS-01): the environment secret was set at 2026-10-29T09:33:33Z and the repository secret list no longer has the name. When this lane closed it was still a repository secret, set on 2026-10-06, and `gh secret list --env release` was empty. Moving it needed the token value, which only the owner holds. Steps:
  1. `gh secret set CARGO_REGISTRY_TOKEN --env release -R andrico21/rskrb5-ng`.
  2. `gh secret delete CARGO_REGISTRY_TOKEN -R andrico21/rskrb5-ng`.

  Before the move, any workflow that a writer pushed to a branch could read the repository secret. The environment gate protects the token only as an environment secret.
- **Historical tags `v0.1.0` to `v0.2.2`** (the `rskrb5-patched` releases). These tags already exist. A manual CI re-run on one of their commits would make `publish` wait for approval. The reviewer rejects that deployment. The job would fail anyway at "Verify crate name and version", because those trees declare `rskrb5-patched`.

## Stale CI references in other documents (resolved)

When this lane closed, other documents still described the upstream dispatch
jobs. They were brought in line with this repository's CI by the
documentation todo (42):

- `README.md`: the manual Docker-backed integration job and its dispatch
  inputs are gone; the README points to the local runner and
  `docs/gated-integration.md`.
- `docs/gokrb5-parity.md`: the gate table matches the manifest
  (`historical-upstream` for the five Docker MIT gates) and no longer gives
  dispatch instructions.
- `docs/ad-integration.md`, `docs/ad-lab-provisioning.md` and
  `docs/samba-ad-feasibility.md`: no hosted dispatch gate is described as
  available, and `docs/ad-integration.md` names the runner's private
  environment file `target/gated-integration/gated-integration.env`.
- `FORK-NOTES.md` is replaced by `PROVENANCE.md`.
- `docs/publishing.md` and `docs/release-notes.md` (upstream history) moved
  to `docs/history/` with an attribution note; `docs/RELEASING.md` is the
  release procedure.

## Release workflow after the `6586b7a` review

The follow-up register ([`followup-6586b7a.md`](followup-6586b7a.md)) rows
FU-CI-05, FU-CI-06 and FU-CI-07 replace the single release workflow described
in the first row above. Release tags are `N.N.N` without a `v` (owner decision
D14). `release.yml` is now a secret-free coordinator that dispatches
`publish.yml` at the tag. `publish.yml` re-verifies the tag, the commit's
ancestry on `main` and the CI result in a token-free `verify` job that
verify-builds and packages the crate. Its `publish` job in the `release`
environment builds nothing: it requires the verified sha256, uploads with
`--no-verify`, and on a re-dispatch after an earlier upload creates the
missing GitHub release only when the published `.crate` has the tag's
sha256. The release toolchain uses the same `dtolnay/rust-toolchain` stable
revision as CI. [`../RELEASING.md`](../RELEASING.md) describes the flow and
the recovery.
