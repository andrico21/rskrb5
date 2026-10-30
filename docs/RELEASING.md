# Releasing rskrb5-ng

This is the release-ready record for `rskrb5-ng` 0.3.0, the first release
under this name. Nothing is published yet: on 2026-10-27,
`https://crates.io/api/v1/crates/rskrb5-ng` answered 404 and no `v0.3*` tag
existed. The repository settings below are in place (2026-10-29), so
publishing needs only one tag.

## How a release runs

Release tags are `N.N.N`, without a `v` (owner decision D14, 2026-10-29); the
historical `v0.1.0` to `v0.2.2` tags stay as they are and are never release
tags of `rskrb5-ng`. Two workflows split the release authority, and every
check they make lives in [`scripts/release-publish.sh`](../scripts/release-publish.sh),
whose `self-test` runs them on stubs:

1. The coordinator `Release`
   ([`.github/workflows/release.yml`](../.github/workflows/release.yml)) runs
   after every completed `CI` run and uses no secret and no deployment
   environment. For a successful push or dispatch CI run of this repository it
   looks for an `N.N.N` tag on the run's commit. Without one it prints
   `No N.N.N tag points at <sha>` and dispatches nothing; two matching tags
   fail the job. With one, and only in the CI run on the tag's own ref (the
   run on `main` for the same commit only reports the tag), it checks that the
   tag equals the `Cargo.toml` version and that the commit is on `main`, then
   runs `gh workflow run publish.yml --ref <tag>`.
2. `Publish` ([`.github/workflows/publish.yml`](../.github/workflows/publish.yml))
   runs only on `workflow_dispatch`, so it always runs at the dispatched tag
   ref, which the `release` environment's tag-only deployment policy admits.
   - Its `verify` job holds no secret and waits for no environment. It
     re-checks everything itself, because `publish.yml` can also be dispatched
     by hand: the ref is `refs/tags/N.N.N`, the tag equals the `Cargo.toml`
     version and points at the dispatched commit, the commit is an ancestor of
     `origin/main`, and a `CI` run of this repository for that commit,
     triggered by push or dispatch, concluded `success` (GitHub API). It then
     verify-builds and packages the crate (`cargo package --locked`) and
     uploads the `.crate` and its sha256 as the `verified-crate` artifact.
     All dependency build code of the release runs in this job.
   - Its `publish` job runs in the `release` environment, so it waits for the
     owner's approval, and it is the only job that sees
     `CARGO_REGISTRY_TOKEN`. It repeats the tag, version, commit and ancestry
     checks (the tag could have moved during the wait), downloads the
     artifact, re-packages without building (`cargo package --locked
     --no-verify`) and requires the verified sha256. Then:
     - if crates.io does not have the version, it uploads with
       `cargo publish --locked --no-verify`;
     - if crates.io has it, it downloads the published `.crate` and requires
       its sha256 to equal the tag's package; other bytes fail the job and no
       release is created;
     - only then does it create the GitHub release for the tag, with the notes
       of the matching `CHANGELOG.md` section, unless that release exists
       (`gh release view` first; never twice).
     No step of this job builds, tests or verify-packages anything, so no
     dependency build code runs on the runner that holds the token.

CI itself runs on the tag push as well, so a release tag gets the full CI
matrix first, including `cargo package --locked`, `cargo publish --dry-run
--locked`, the consumer build and `semver-checks` (a notice for this first
`rskrb5-ng` release, because no `rskrb5-ng` version is published; after a
publication, a commit that keeps a published version fails `semver-checks`
with "version already published; bump the version").

## Repository settings in place

Recorded in [`review/release-ci.md`](review/release-ci.md). The token location
and the deployment policy were set by the owner on 2026-10-29 (follow-up
register row FU-OPS-01) and checked with `gh api` on 2026-10-29 and again on
2026-10-30:

- environment `release`:
  - protection rule `required_reviewers` with the single reviewer `andrico21`
    (`prevent_self_review: false`, because the owner is the only reviewer and
    also cuts the tag);
  - deployment branches and tags "Selected": the only deployment policy is the
    tag pattern `[0-9]*.[0-9]*.[0-9]*` (type `tag`), so a job in this
    environment runs only at an `N.N.N` tag ref; `can_admins_bypass: false`;
  - secret `CARGO_REGISTRY_TOKEN` (set 2026-10-29T09:33:33Z), the owner's
    crates.io API token. This environment is its only location: the repository
    secret list doesn't contain the name, so only a job that runs in
    `release`, after the reviewer's approval and at an `N.N.N` tag, can read
    it;
- tag ruleset "release tags" (id 25943056): active, target
  `refs/tags/[0-9]*.[0-9]*.[0-9]*`, rules `creation`, `update` and
  `deletion`, bypass for repository admins only.

The `publish` job reads `secrets.CARGO_REGISTRY_TOKEN` inside the `release`
environment. To replace the token, store the new value with
`gh secret set CARGO_REGISTRY_TOKEN --env release -R andrico21/rskrb5-ng`;
never store it as a repository secret.

crates.io Trusted Publishing can't replace the token for this first release:
a trusted publisher can only be configured for a crate that has already been
published manually ([RFC 3691](https://rust-lang.github.io/rfcs/3691-trusted-publishing-cratesio.html),
"A Trusted Publisher Configuration can only be created after an initial
manual publishing of a crate"). After 0.3.0 is on crates.io, the owner may
configure Trusted Publishing for this repository's `publish.yml` and the
`release` environment, switch the upload step to the OIDC token exchange,
and revoke the API token.

## Cutting the release

1. Land the release commit on `main` with the version in `Cargo.toml` and a
   dated `## [0.3.0] - <date>` heading in `CHANGELOG.md`. Wait for CI on
   `main` to go green.
2. Tag that exact commit (repository admins only) and push the tag:

   ```sh
   git tag -a 0.3.0 <sha> -m "rskrb5-ng 0.3.0" && git push origin 0.3.0
   ```

3. CI runs on the tag. When it is green, `Release` finds `0.3.0` and
   dispatches `Publish` at `refs/tags/0.3.0`. `verify` runs at once; `publish`
   waits for approval in the `release` environment. Approve it in the Actions
   UI.
4. After the run: `https://crates.io/crates/rskrb5-ng` lists 0.3.0, and the
   GitHub release `0.3.0` exists.

## Recovering a failed run

Re-dispatch `Publish` at the tag; nothing else is needed:

```sh
gh workflow run publish.yml --ref 0.3.0 -R andrico21/rskrb5-ng
```

`verify` checks the tag and CI again and re-packages. `publish` then either
uploads (the earlier run failed before the upload) or, when the earlier run
uploaded and failed afterwards (for example while creating the GitHub
release), downloads the published `.crate`, requires the sha256 of this tag's
package, and creates the missing GitHub release once. A version on crates.io
whose bytes differ from the tag's package (an out-of-band publication) fails
the job; it is never certified by a release. Re-running the CI workflow is not
a recovery path: the coordinator dispatches from the CI run on the tag ref, so
re-run that run only if `Publish` was never dispatched.

## rskrb5-patched (optional, future)

`rskrb5-patched` 0.2.1 and 0.2.2 stay published, and `kpasswd-rs` still
depends on 0.2.1 through its vendored tree. Once consumers have moved to
`rskrb5-ng`, the owner may yank those versions or publish a final
`rskrb5-patched` release whose README points to `rskrb5-ng`. No such action
is planned or taken here.
