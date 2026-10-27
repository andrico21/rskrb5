# Releasing rskrb5-ng

This is the release-ready record for `rskrb5-ng` 0.3.0, the first release
under this name. Nothing is published yet: on 2026-10-27,
`https://crates.io/api/v1/crates/rskrb5-ng` answered 404 and no `v0.3*` tag
existed. Publishing needs the owner steps below, then one tag.

## How a release runs

The `Release` workflow ([`.github/workflows/release.yml`](../.github/workflows/release.yml))
runs after every completed `CI` run. It has two jobs:

1. `find-tag` holds no secret. For a successful push or dispatch CI run of
   this repository it looks for a `vN.N.N` tag on the run's commit. Without
   one it prints `No vN.N.N tag points at <sha>` and ends, and `publish` is
   skipped. Two matching tags fail the job.
2. `publish` runs only when a tag was found, in the `release` environment,
   so it waits for the owner's approval. Then it:
   - checks that the tag still points at the commit CI verified, and that the
     commit is an ancestor of `origin/main`;
   - checks that `Cargo.toml` names the package `rskrb5-ng` and that its
     version equals the tag without the `v`;
   - takes the release notes from the matching `CHANGELOG.md` section;
   - runs `cargo publish --dry-run --locked` without the token;
   - uploads with `cargo publish --locked --no-verify`, the only step that
     sees `CARGO_REGISTRY_TOKEN`; a version that is already on crates.io
     is reported and not released again;
   - creates the GitHub release for the tag, only when this run uploaded.

CI itself runs on the tag push as well, so a release tag gets the full CI
matrix first, including `cargo package --locked`, `cargo publish --dry-run
--locked`, the consumer build and `semver-checks` (a notice for this first
`rskrb5-ng` release, because no earlier `rskrb5-ng` version is published).

## Repository settings already in place

Applied by todo 38 of the rskrb5-ng plan and recorded in
[`review/release-ci.md`](review/release-ci.md); checked again on 2026-10-27
with `gh api`:

- environment `release`, protection rule `required_reviewers` with the single
  reviewer `andrico21` (`prevent_self_review: false`, because the owner is the
  only reviewer and also cuts the tag);
- tag ruleset "release tags" (id 25943056): active, target `refs/tags/v*`,
  rules `creation`, `update` and `deletion`, bypass for repository admins
  only.

## Owner steps before the first publish

1. **Create a crates.io API token** for the owner's crates.io account, with
   the scopes `publish-new` and `publish-update` and the crate scope
   `rskrb5-ng`. `publish-new` is needed because the crate doesn't exist yet.
2. **Store it as a secret of the `release` environment**, not as a
   repository secret:

   ```sh
   gh secret set CARGO_REGISTRY_TOKEN --env release -R andrico21/rskrb5-ng
   ```

3. **Delete the repository secret.** `CARGO_REGISTRY_TOKEN` is still a
   repository secret today (set on 2026-10-06 for `rskrb5-patched`; `gh secret
   list --env release` is empty). A repository secret is readable by any
   workflow a writer pushes to a branch, so the environment's reviewer gate
   protects the token only once it is an environment secret:

   ```sh
   gh secret delete CARGO_REGISTRY_TOKEN -R andrico21/rskrb5-ng
   ```

   The `publish` job reads `secrets.CARGO_REGISTRY_TOKEN` inside the `release`
   environment, so it picks up the environment secret without a workflow
   change.

crates.io Trusted Publishing can't replace the token for this first release:
a trusted publisher can only be configured for a crate that has already been
published manually ([RFC 3691](https://rust-lang.github.io/rfcs/3691-trusted-publishing-cratesio.html),
"A Trusted Publisher Configuration can only be created after an initial
manual publishing of a crate"). After 0.3.0 is on crates.io, the owner may
configure Trusted Publishing for this repository's `release.yml` and the
`release` environment, switch the upload step to the OIDC token exchange,
and revoke the API token.

## Cutting the release

1. Land the release commit on `main` with the version in `Cargo.toml` and a
   dated `## [0.3.0] - <date>` heading in `CHANGELOG.md`. Wait for CI on
   `main` to go green.
2. Tag that exact commit (repository admins only) and push the tag:

   ```sh
   git tag -a v0.3.0 <sha> -m "rskrb5-ng 0.3.0" && git push origin v0.3.0
   ```

3. CI runs on the tag. When it is green, `Release` starts, `find-tag` finds
   `v0.3.0`, and `publish` waits for approval in the `release` environment.
   Approve it in the Actions UI.
4. After the run: `https://crates.io/crates/rskrb5-ng` lists 0.3.0, and the
   GitHub release `v0.3.0` exists. A failed run can be repeated by re-running
   the CI workflow on the same commit.

## rskrb5-patched (optional, future)

`rskrb5-patched` 0.2.1 and 0.2.2 stay published, and `kpasswd-rs` still
depends on 0.2.1 through its vendored tree. Once consumers have moved to
`rskrb5-ng`, the owner may yank those versions or publish a final
`rskrb5-patched` release whose README points to `rskrb5-ng`. No such action
is planned or taken here.
