# `rskrb5-patched` - a temporary fork of `rskrb5`

This branch (`release/0.3.0`, pushed to `andrico21/rskrb5`) is the source of
the crates.io crate **`rskrb5-patched` 0.3.0**: upstream `rskrb5` `main` at
`6f4abc9` plus the changes below. It exists only so consumers can depend on a
registry version that carries them - every code change is filed or planned
upstream.
It is not affiliated with the upstream author, and it leaves consumers'
dependency graphs when upstream ships the same fixes.

Upstream: <https://github.com/clelange/rskrb5>. The fork's `main` carries
upstream's history plus this repository's two workflow files
(`.github/workflows/ci.yml`, `release.yml`); only `release/*` branches carry
changes.

## Releases

Cut through GitHub Actions, gated on CI: land the release commit on a
`release/*` branch, wait for CI to go green, then push the tag (`v0.3.0`) at
the same SHA. The `Release` workflow verifies the tag against the crate
version, dry-runs, publishes `rskrb5-patched` with the repository's
`CARGO_REGISTRY_TOKEN` secret, and opens the GitHub release. A re-run of CI on
the same SHA is the manual recovery path.

This branch is the 0.3.0 release commit (version bumped; `0.2.1` and `0.2.2`
remain published): pushing `v0.3.0` at its tip is the publish step. 0.3.0 is a
breaking release (new error variants, a second type parameter on
`NegotiateHttpError`, new public struct fields; see `CHANGELOG.md`).
`docs/fix-plans/` holds the detailed plans for the audit findings it closes.

Before tagging, confirm the lockfile is current: `cargo update --dry-run` on
the tag commit must print `Locking 0 packages`. If it locks anything, refresh
the lockfile (`cargo update`, bumping the matching `supply-chain/config.toml`
exemption so `cargo vet --locked` passes), commit, and wait for CI again.

To publish, tag the CI-green tip of `release/0.3.0`:

```sh
git tag v0.3.0 <sha> && git push origin v0.3.0
```

The plan that prepared this release deliberately does NOT run that command:
it stops with `release/0.3.0` pushed and CI green, and the tag is the
maintainer's step.

## CI

`.github/workflows/ci.yml` runs on floating `stable` (no toolchain pin, per
the core Version Policy). `nightly-2026-10-03` is used only for rustfmt, the
second rustdoc run, the fork-lines gate's formatting and fuzz; `1.99.0` only
for the MSRV build. Blocking jobs: `fmt`, `clippy`, `features-matrix` (K1 to
K7), `lib-feature-sets` (`cargo check --lib` without default features for
`messages`, `spnego`, `http` and `evaluation`, plus the compatibility-report
binary), `readme-commands` (the README `axum-negotiate` build and the
compatibility-report diff), `test` (Linux, macOS, Windows; at least 32
`test result: ok` lines), `i686` (check plus the ccache tests), `docs`,
`msrv`, `semver-checks`, `publish-dryrun`, `consumer`, `deny`, `audit`, `vet`,
`machete`, `taplo`, `docs-validate`, `lint-gates`, `fork-lines` and
`package`. Advisory (`continue-on-error`): `geiger`, `rustdoc-nightly-canary`,
`mutants` and `fuzz`. The prek hooks in `prek.toml` mirror the fast gates for
pre-push.

`mutants` and `fuzz` run only on `schedule` and `workflow_dispatch`. GitHub
fires `schedule` only on the default branch `main`, whose fuzz crate is the
0.2.0-era package with the `kpasswd_reply` target alone. So the release line's
fuzzing (`kpasswd_reply` and `ccache_parse`, 300 s each) and mutants run on
dispatch, once per release candidate before tagging:

```sh
gh workflow run CI -R andrico21/rskrb5 --ref release/0.3.0
gh run list -R andrico21/rskrb5 -w CI -b release/0.3.0 -e workflow_dispatch -L 1
```

## Lint profile

The crate builds under the strictest lint profile of the vendored Rust
guidelines (core Section 9, equal to rmcp-server-kit `b7f6b66`), with no
`allow` attributes. Inherited upstream violations are item-level
`lint-migration:` expectations in a manifest that can only shrink; fork code
passes the profile outright. [`docs/lint-baseline.md`](docs/lint-baseline.md)
describes the profile, the baseline, the gates, every authorized rewrite of
upstream lines, the rebaseline procedure for a new stable, and how the
release line diverges from each upstream PR branch.

Known item: `client::build_tgs_req_for_realm_with_confounder_and_subkey`
(fork commit `782dcb8`, issue #13) carries the only `deliberate:`
expectation without an upstream PR number, for `clippy::too_many_arguments`.
It goes away when the TGS subkey PR is filed and the API is settled upstream.

## Dependencies held back

`rust-version = "1.99"` and the lockfile holds the latest Rust 1.99-compatible
versions; `cargo update --dry-run 2>&1 | grep -c 'Locking 0 packages'` prints
1. Major (0.x minor) upgrades stay out of scope, because upstream code depends
on these APIs (project overlay deviation 6):

| Crate | Locked | Latest | Held by |
|---|---|---|---|
| `base64` | 0.22.1 | 0.23.1 | major |
| `getrandom` | 0.3.4 (plus 0.2 and 0.4 transitively) | 0.4.3 | major |
| `picky-krb` (optional, `evaluation`) | 0.12.3 | 0.13.0 | major, and the exact `pbkdf2` pin below |
| `rasn`, `rasn-kerberos` | 0.28.15 | 0.29.0 | major |
| `compcol` | 0.6.11 | 0.7.6 | major |
| `toml` (dev) | 0.9.12 | 1.1.8 | major |
| `pbkdf2` | `=0.13.0-rc.10` | 0.13.0 | exact pin, unchanged |

## Upgrading from 0.2

- **Toolchain:** `rust-version = "1.99"` (was 1.88).
- **New enum variants** on exhaustive enums, so exhaustive `match`es need new
  arms: `client::Error::{EnctypeNotRequested, EnctypeNotPermitted}`,
  `config::Error::{EnctypeNotPermitted, NoPermittedEnctypes}`,
  `kadmin::Error::UnauthenticatedSuccess` and
  `http::NegotiateHttpError::MutualAuthenticationNotProven`.
  `NegotiateHttpError<E>` becomes `NegotiateHttpError<E, B>`, where `B` is the
  response body type carried by the new variant.
- **New public fields:** `LibDefaults.permitted_enctypes_explicit` and
  `InitiatorContext.context_flags`. Struct literals must name them
  (`LibDefaults` also accepts `..Default::default()`). Programmatic configs
  that want the allowlist enforced set `permitted_enctypes_explicit`; with the
  flag set, an empty `permitted_enctype_ids` permits no enctype (requests
  fail with `EmptyEtypes`, session keys with `EnctypeNotPermitted`).
- **Fork-only API tightened by the lint pass:** `client::TgsFastRequestParts`
  is `#[non_exhaustive]`, and the two `build_tgs_req_for_realm_with_*subkey`
  functions take a generic `R: Into<String>` realm instead of
  `impl Into<String>`. Ordinary calls compile unchanged; a turbofish now sees
   the type parameter.
- **Authorized upstream-line lint rewrites (exception (p)):**
  `DEFAULT_TICKET_LIFETIME` (`src/client.rs`) and `ticket_lifetime`
  (`src/config.rs`) use `Duration::from_hours(24)`;
  `DEFAULT_MAX_CLOCK_SKEW` (`src/service.rs`) uses `Duration::from_mins(5)`.
  `keytab::Error::NoMatchingKey` patterns use explicit `field: _` bindings;
  redundant qualification prefixes are dropped in `src/client.rs` and
  `src/client/kpasswd.rs` (13 upstream lines each), and `std::io::ErrorKind`
  becomes `io::ErrorKind` in `src/client.rs` and `src/ccache.rs`.
  `Config::resolve_realm` gains `#[must_use]` and `#[inline]`, and its
  parameter is renamed `domain_name` to `dns_name`. The rename is
  source-compatible for callers; discarding the return value may now warn
  (or fail with warnings denied). `Config::json` returns
  `Result<String, serde_json::Error>` instead of the fully qualified
  `std::result::Result<…>` (same type), gains `#[inline]` and an `# Errors`
  section, and drops its 5 `lint-migration:` expectations (shrink only).
  These rewrites preserve runtime behavior;
  the exact authorization record is in `docs/lint-baseline.md`.
- **Behaviour changes:**
  - a config whose explicit `default_tkt_enctypes` or `default_tgs_enctypes`
    names an enctype outside an explicit `permitted_enctypes` fails to parse
    with `config::Error::EnctypeNotPermitted`, instead of being narrowed;
  - an explicit `permitted_enctypes` that resolves to no supported enctype
    fails to parse with `config::Error::NoPermittedEnctypes`, instead of
    meaning "no policy";
  - `des3-cbc-sha1` and `des3-hmac-sha1` mean enctype 16 (MIT), so an
    explicit list naming them now requests DES3 (subject to
    `allow_weak_crypto` and `permitted_enctypes`) instead of dropping it;
  - a KDC reply or session key outside the requested (or explicitly
    permitted) enctypes is rejected;
  - an unsigned kpasswd success is rejected and the stored password kept;
  - host-based SPNs carry a lower-cased host;
  - the HTTP send wrappers return an error when requested mutual
    authentication isn't proven;
  - renewal pacing, AS recovery and `[domain_realm]` matching change as listed
    in `CHANGELOG.md`.
- **Path-dependency consumers** (such as `kpasswd-rs`'s vendor tree) compile
  this crate with its own `[lints]` table and no lint cap. That build is
  verified warning-free, with warnings denied, for
  `default-features = false, features = ["tokio"]` and for the default
  features (CI job `consumer`). Other feature combinations aren't covered by
  the baseline and can fail a strict build; see O-7 in
  `docs/lint-baseline.md`.

## What it changes

| Change | Upstream, 2026-10-24 |
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
| AP-REQ replay cache also indexes a digest of the authenticator ciphertext, so an authenticator re-presented under a rewritten cleartext ticket `sname` (for example a keytab alias sharing the service key) is rejected | **PR [#20](https://github.com/clelange/rskrb5/pull/20)** open, updated with this commit |
| Ccache record counts bounded against the remaining input before reserving, so a malformed cache returns `Truncated` instead of aborting on a huge allocation | **PR [#22](https://github.com/clelange/rskrb5/pull/22)** open |
| kpasswd success accepted only with authenticated provenance: an unsigned KRB-ERROR code 0 is rejected (`kadmin::Error::UnauthenticatedSuccess`) and the stored password is kept | **PR [#23](https://github.com/clelange/rskrb5/pull/23)** open |
| `[libdefaults] clockskew` applied on the `Config`-driven acceptors (`ServiceValidator`, `NegotiateLayer`); plain constructors keep 300 s | **PR [#24](https://github.com/clelange/rskrb5/pull/24)** open |
| Host-based service principals fold the DNS host component to lower case (RFC 4120 section 6.2.1), so host-case variants share one SPN and one cached ticket | **PR [#25](https://github.com/clelange/rskrb5/pull/25)** open |
| `[domain_realm]` lookups fold DNS case, and a bare tag covers its subdomains (MIT krb5.conf(5)) | **PR [#26](https://github.com/clelange/rskrb5/pull/26)** open |
| AS/TGS reply and session-key enctypes bound to the requested list (`EnctypeNotRequested`); an explicit `permitted_enctypes` narrows requests and rejects out-of-list session keys (`EnctypeNotPermitted`), an explicit request list outside it is a parse error, and an explicit allowlist with no supported enctype fails closed (`NoPermittedEnctypes`); MIT's `des3-cbc-sha1`/`des3-hmac-sha1` names mean enctype 16; the explicit flag survives serde and include expansion | **PR [#27](https://github.com/clelange/rskrb5/pull/27)** open |
| Renewal series: refresh band from the current ticket life, auto-renewal paced when a refresh makes no progress, and AS recovery when a cached TGT is expired or its renewal is refused | **PR [#28](https://github.com/clelange/rskrb5/pull/28)** open |
| Requested mutual authentication fails closed in the response classifier and in the send wrappers (`NegotiateHttpError::MutualAuthenticationNotProven`) | **PR [#29](https://github.com/clelange/rskrb5/pull/29)** open |
| Lockfile refreshed to the latest Rust 1.99-compatible versions | fork only (lockfile) |

The measurements and the acceptance procedure live in the consumer repository
(`kpasswd-rs`: `VENDORING.md`).

## Retirement

When an upstream release carries these fixes, `rskrb5-patched` 0.2.1, 0.2.2
and 0.3.0 are yanked (`cargo yank --version 0.3.0 rskrb5-patched`, likewise for
0.2.2 and 0.2.1) and consumers move back to `rskrb5`. No further versions are
planned.

## Licensing

Apache-2.0, as upstream. `LICENSE` and `NOTICE` are retained; the modifications
are the changes above (Apache-2.0 section 4(b)).
