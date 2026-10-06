# `rskrb5-patched` - a temporary fork of `rskrb5`

This branch (`release/0.2.2`, pushed to `andrico21/rskrb5`) is the source of
the crates.io crate **`rskrb5-patched` 0.2.2**: upstream `rskrb5` `main` at
`6f4abc9` plus the changes below. It exists only so consumers can depend on a
registry version that carries them - every change is filed or planned upstream.
It is not affiliated with the upstream author, and it leaves consumers'
dependency graphs when upstream ships the same fixes.

Upstream: <https://github.com/clelange/rskrb5>. The fork's `main` carries
upstream's history plus this repository's two workflow files
(`.github/workflows/ci.yml`, `release.yml`); only `release/*` branches carry
changes.

## Releases

Cut through GitHub Actions, gated on CI: land the release commit on a
`release/*` branch, wait for CI to go green, then push the tag (`v0.2.2`) at
the same SHA. The `Release` workflow verifies the tag against the crate
version, dry-runs, publishes `rskrb5-patched` with the repository's
`CARGO_REGISTRY_TOKEN` secret, and opens the GitHub release. A re-run of CI on
the same SHA is the manual recovery path.

This branch is the 0.2.2 release commit (version bumped; `0.2.1` remains
published): pushing `v0.2.2` at its tip is the publish step. `docs/fix-plans/`
holds the detailed plans for the remaining audit findings.

## What it changes

| Change | Upstream, 2026-10-07 |
|---|---|
| Clippy lints reported by Rust 1.98 (so the other changes can pass CI) | **PR [#15](https://github.com/clelange/rskrb5/pull/15)** open |
| `hex` as a dev-dependency so the crate's own integration tests build | issue #12 - **PR [#16](https://github.com/clelange/rskrb5/pull/16)** open |
| `PA_FX_COOKIE`, `PA_AS_FRESHNESS` and `random_nonce` exported | issue #14 - **PR [#17](https://github.com/clelange/rskrb5/pull/17)** open |
| `ChangePasswordResult` and `PasswordChangeFailed` carry the result bytes as received (`text_raw`) instead of `String::from_utf8_lossy`, with the test fixtures completed | issue #2 - **PR [#18](https://github.com/clelange/rskrb5/pull/18)** open |
| `Config`/`LibDefaults` constructors that read no environment (`new_without_env`, `parse_without_env`) | issue #10 - PR to follow |
| `include`/`includedir` in `krb5.conf`, with depth/count/byte bounds and named errors; cycle detection for root files and directories; the scan cap enforced while scanning; non-UTF-8 `.conf` names read, MIT-style | issue #11 - PR to follow |
| The TGS-REQ builder returns the AP-REQ bytes and the authenticator subkey (RFC 6113 implicit FAST armor inputs) | issue #13 - PR to follow |
| TCP framing and preauth connection reuse: record mark + body written as one segment, `TCP_NODELAY`, pinned stream for the second AS phase (imported from PR [#19](https://github.com/clelange/rskrb5/pull/19)'s branch), plus an `Auto`-fallback pinning extension | **PR [#19](https://github.com/clelange/rskrb5/pull/19)** open (Tcp path); extension stacked as [Gittingc0dez/rskrb5#1](https://github.com/Gittingc0dez/rskrb5/pull/1) |
| AP-REQ replay identity canonicalized over the advisory name-type; a name-type-only replay is rejected (RFC 4120 section 3.2.3/6.2) | **PR [#20](https://github.com/clelange/rskrb5/pull/20)** open |
| Authenticator client realm bound to the ticket realm; `ValidatedApReq.client` is ticket-derived (intentional gokrb5 divergence, `docs/gokrb5-parity.md`) | **PR [#21](https://github.com/clelange/rskrb5/pull/21)** open |

The measurements and the acceptance procedure live in the consumer repository
(`kpasswd-rs`: `VENDORING.md`).

## Retirement

When an upstream release carries these fixes, `rskrb5-patched` 0.2.1 and 0.2.2
are yanked (`cargo yank --version 0.2.2 rskrb5-patched`, likewise for 0.2.1)
and consumers move back to `rskrb5`. No further versions are planned.

## Licensing

Apache-2.0, as upstream. `LICENSE` and `NOTICE` are retained; the modifications
are the changes above (Apache-2.0 section 4(b)).
