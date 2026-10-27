# Release authority, CI docs and fixture secrets: review dispositions

This file records the dispositions for the release workflow, the CI
documentation and the fixture-runner items of the review backlog. Full
commands, red runs and exit codes are in `task-38-rskrb5-ng-own-way.log`.

| ID | Status | Tests and commit | Behaviour change for CHANGELOG | Dismissal evidence |
| --- | --- | --- | --- | --- |
| run-2 lead `release.publish.crates-io-token.unprotected-tag-authorization` | fixed | `release_find_tag_job_holds_no_secret_and_reports_untagged_runs`, `release_publish_job_requires_tag_environment_and_main_ancestry`, `release_registry_token_reaches_only_the_publish_upload` (`tests/gokrb5_parity_manifest.rs`); commit recorded in the evidence log | The Release workflow has two jobs. `find-tag` holds no secret and no environment. When no `v`-prefixed tag points at the commit, it prints `No vN.N.N tag points at <sha>` and outputs an empty tag. It accepts only `v`-prefixed tags and fails when more than one tag matches. `publish` runs only when a tag was found, in the `release` environment, whose required reviewer is `andrico21`. It checks that the tag still points at the commit CI verified and that this commit is an ancestor of `origin/main`. The registry token is used only by the upload step, which runs `cargo publish --locked --no-verify` after the dry run has verified the tree without the token. The repository settings are listed below. | N/A |

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
