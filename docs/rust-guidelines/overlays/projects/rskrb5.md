# Project overlay: rskrb5-patched (the `rskrb5` fork)

**Load order:** core `RUST_GUIDELINES.md` ->
`overlays/domains/kerberos-credential-protocols.md` -> `overlays/domains/http-services.md`
-> this file.

`http-services.md` applies because the crate ships a server-side HTTP Negotiate Tower
layer (`NegotiateLayer`, which writes `401` challenge and reject responses) and an Axum
example that serves HTTP.

**Precedence:** strictest wins. Where the core, the two domain overlays, this file or a
sibling project's stricter practice that this file adopts pull apart, the stricter rule
applies. Nothing below weakens the core or a domain overlay (README, "The overlay
contract").

## The project (verified 2026-10-25)

Facts about the 0.3.0 line were measured on the branch `release/0.3.0` at `8f11734`,
pushed to `andrico21/rskrb5`.

- **What:** `andrico21/rskrb5`, a temporary fork of `clelange/rskrb5`.
  - It is published to crates.io as **`rskrb5-patched`**: 0.2.1 (2026-10-06), and 0.2.2 (2026-10-23, tag `v0.2.2` at `58b27bb`).
  - `release/0.3.0` carries version **0.3.0**, unpublished and untagged (`CHANGELOG.md` `[0.3.0] - 2026-10-24`). It is a breaking release; `FORK-NOTES.md` "Upgrading from 0.2" lists the changes.
  - The lib target stays `rskrb5`.
  - Its consumer is `kpasswd-rs`. It vendors 0.2.1 by sha256 as a **path dependency**, with `default-features = false, features = ["tokio"]`, and denies warnings. So this crate's `[lints]` table runs inside the consumer's build.
- **Base:** upstream `main` at `6f4abc9` plus:
  - the 0.2.1 series: Rust 1.98 clippy drift, `hex` dev-dependency, padata exports, verbatim kpasswd result bytes, environment-free `Config`/`LibDefaults`, `include`/`includedir`, the TGS authenticator subkey;
  - the 0.2.2 additions: AP-REQ replay identity (PR #20), authenticator realm binding (PR #21), the TCP framing/preauth stream (upstream PR #19 plus Gittingc0dez/rskrb5#1);
  - the 0.3.0 additions: the eight run-2 fix branches, proposed upstream as PRs #22 to #29 (ccache count bounds, authenticated kpasswd success, clockskew handoff, host-case SPN, domain-realm normalization, enctype policy, client renewal series, mutual-auth classification). The enctype-policy branch (PR #27, head `752832b`) also fails closed on an allowlist with no supported enctype (`cc8060c`) and maps MIT's `des3-cbc-sha1`/`des3-hmac-sha1` names to enctype 16 (`752832b`); merge `7b9ee1c` brings both into `release/0.3.0`.

  `FORK-NOTES.md` carries the table.
- **Branches:**
  - `main` = upstream history plus the two workflow files and the fuzz crate. `release.yml` runs from here, because it triggers on `workflow_run`; it publishes `--locked` (`79a28d3`).
  - `release/*` carries the series.
  - `fix/*` carries one upstream PR each, based on `6f4abc9`, upstream-shaped (no profile, stable rustfmt, `rust-version = "1.88"`).
- **Toolchain (`release/0.3.0`):**
  - edition 2024, `rust-version = "1.99"` (`7c95579`);
  - the core Section 9 profile in the root `Cargo.toml` `[lints]` tables and `.cargo/config.toml` `build.warnings = "deny"` (`473ca10`), `rustfmt.toml` run with `nightly-2026-10-03` (`8eb3977`), `clippy.toml`, `deny.toml` and `supply-chain/` (`62191fe`);
  - `src/lib.rs` has `#![forbid(unsafe_code)]`, and no `unsafe` remains in `tests/`: environment-dependent tests set variables in a child test process (`b61c3f2`);
  - no `allow` attribute anywhere (`allow_gate.py --enforce`);
  - one dev-dependency added, `proptest`, for the ccache, serde-flag and realm case-fold property tests.
- **CI (`release/0.3.0`, `7e05965`, extended in `e64de51`):** `ci.yml` runs on floating `stable`, with `nightly-2026-10-03` for rustfmt, the second rustdoc run, the fork-lines gate and fuzz, and `1.99.0` for the MSRV build.
  - Blocking: `fmt`, `clippy`, `features-matrix` (K1 to K7, including the consumer's `--no-default-features --features tokio`), `lib-feature-sets` (`cargo check --lib --no-default-features` with `messages`, `spnego`, `http` or `evaluation`, plus the compatibility-report binary), `readme-commands` (the README `axum-negotiate` build and the compatibility-report diff), `test` (Linux, macOS, Windows), `i686` (check plus the ccache tests), `docs`, `msrv`, `semver-checks`, `publish-dryrun`, `consumer`, `deny`, `audit`, `vet`, `machete`, `taplo`, `docs-validate`, `lint-gates`, `fork-lines`, `package`.
  - Advisory (`continue-on-error`): `geiger`, `rustdoc-nightly-canary`, `mutants` and `fuzz`. The last two run only on `schedule` and `workflow_dispatch`; `schedule` fires only on the default branch `main`, so the release line runs them by dispatch (`FORK-NOTES.md` "CI").
  - `fuzz/Cargo.toml` depends on the renamed package (`dd5e57d`); the fuzz targets are `kpasswd_reply` and `ccache_parse`.
- **Lint baseline (measured 2026-10-25 at `8f11734`):**
  - `python3 scripts/lint-ratchet/baseline_gate.py --report` prints `current 6514 / base 7396 entries` (7,396 at adoption in `473ca10`);
  - 2,728 lines of `.rs` files carry a `lint-migration:` reason (`rg -c 'lint-migration:' -g '*.rs'`, summed);
  - 2 `deliberate:` expectations (`http::NegotiateHttpError`, mirroring upstream PR #29, and exception (i) below), 84 core-sanctioned test-module expectations (45 `test code is not rendered API documentation`, 39 `a test fails by panicking`) and one crate-root `public facade` expectation.

  `docs/lint-baseline.md` records the measures, the gates and the authorized exceptions. Its section "Authorized upstream-line rewrites and exceptions" lists (a) to (p), including the one `deliberate:` expectation without an upstream PR number (exception (i), `client::build_tgs_req_for_realm_with_confounder_and_subkey`). Read them there; this file does not repeat them.
- **Feature sets:** the strict profile supports exactly the K1 to K7 sets. Advisory O-7 in [`docs/lint-baseline.md`](https://github.com/andrico21/rskrb5/blob/release/0.3.0/docs/lint-baseline.md#advisories) records which other sets pass the lib-only check and which fail; read it there.
- **Profile gap before adoption (measured 2026-10-23):** the core Section 9 profile at warn on `release/0.2.2` reported 7,906 distinct diagnostics, covering 104 lints in 54 files; 285 were on fork-authored lines.
- **Vendored rules:** committed on `release/0.3.0` at `docs/rust-guidelines/` (`7e21b25`): the core, the two domain overlays and this file, with `SHA256SUMS`. The root `RUST_GUIDELINES.md` index names the pin and the re-vendor procedure. CI checks the checksums, and `profile_eq.py --clippy-toml` checks `Cargo.toml` and `clippy.toml` against the vendored core.

## Project rules

1. **The core and both domain overlays apply in full.** A gap is a dated deviation below,
   phrased as a task, never permission.
2. **Lint posture, release line:**
   - the core Section 9 profile, unchanged, in the root `Cargo.toml`;
   - `clippy.toml` = the core sample, plus this crate's `allowed-duplicate-crates` (mirrored in `deny.toml` `[bans] skip`) and `doc-valid-idents`;
   - `rustfmt.toml` with `imports_granularity`/`group_imports`, formatted with the dated nightly that `rmcp-server-kit` uses;
   - `build.warnings = "deny"`;
   - no `#[allow]`/`#![allow]` anywhere.
3. **Upstream-origin code is not rewritten for lints.** "Upstream-origin" means lines identical to `6f4abc9` after formatting.
   - Each existing violation carries a generated `#[expect(<lint>, reason = "lint-migration: ...")]` on the **narrowest item**, under `cfg_attr` where it fires only in some builds.
   - Each one is listed in `scripts/lint-ratchet/baseline.toml`.
   - The list only shrinks, except in a `lint: rebaseline for Rust X.Y` commit made after a stable release adds lints.
   - This baseline is deviation 2 below, a task to burn down.
4. **Fork-authored code complies with no suppression.** That is every line that differs from upstream after formatting. Only two kinds of exception are allowed:
   - **Core-sanctioned item exceptions, with the core's own reason text:** test modules' `missing_errors_doc`/`missing_panics_doc`/`too_long_first_doc_paragraph` and `panic_in_result_fn`; `missing_copy_implementations` on secret types.
   - **Public API mirrored from an open upstream PR:** public items whose shape matches that PR carry `#[expect(<lint>, reason = "deliberate: <path> - mirrors upstream PR #N")]`, limited to lints whose fix would rename or re-shape that API. Those lints are `exhaustive_structs`, `exhaustive_enums`, `pub_use`, `module_name_repetitions`, `partial_pub_fields`, `error_impl_error`, `impl_trait_in_params`, `too_many_arguments`, `struct_excessive_bools`, `fn_params_excessive_bools` and `same_name_method`.

   Additive fixes are made, not expected: `#[inline]`, `#[must_use]`, docs, `const`. A differential gate against the formatted upstream tree enforces this in every CI feature configuration. A prose gate checks the core's non-lint rules (cancel-safety annotations, test docs, `Result`-returning tests, Drop audits, emptiness messages) on fork-touched items.
5. **No `unsafe` anywhere, tests included.** Environment-dependent tests set variables in a
   child test process.
6. **`fix/*` branches stay upstream-shaped.** They carry no fork profile, no fork identity and no lint-compliance commits. The release line carries those, and records its divergence from each PR in `docs/lint-baseline.md`.
7. **Toolchain:**
   - CI runs floating `stable` (core Version Policy), plus the dated nightly for rustfmt and rustdoc.
   - The release line raises `rust-version` to the latest stable it was verified on (1.99), proven by an MSRV job.
   - `fix/*` branches keep upstream's 1.88.
8. **Dependencies:** latest stable versions. Semver-compatible updates go in at every release. Major versions held back by upstream code are deviation 6.
9. **CI (release line), the core Section 12 list plus `rmcp-server-kit`'s stricter practice, all blocking:**
   - fmt; clippy and tests in every shipped feature configuration, including the consumer's `--no-default-features --features tokio`;
   - tests on Linux, macOS and Windows; the i686 check;
   - rustdoc `-D warnings` on stable and the dated nightly;
   - `cargo audit`, `cargo deny check`, `cargo vet --locked`, `cargo machete`, `cargo semver-checks`, `taplo fmt --check`, `cargo publish --dry-run --locked`;
   - the MSRV build;
   - a path-dependency consumer build with warnings denied;
   - the lint-ratchet, fork-lines and prose gates, the Section 9 completeness check, and the vendored-guideline checksum check.

   Advisory jobs: `cargo geiger`, a latest-nightly rustdoc canary, and scheduled `mutants`/`fuzz`.
10. **Releases go only through the tag-gated workflow.** It runs from `main` and publishes `--locked`. Every release that changes the public API is checked with `cargo semver-checks` against the last published version.
11. **Kerberos specifics on code this fork changes:**
    - An explicitly configured enctype request list that names an enctype outside an explicit `permitted_enctypes` is **rejected with the enctype named**, never silently narrowed.
    - Enctype tests assert on the **encoded** AS-REQ/TGS-REQ etype list.
    - Parsers the fork changes (ccache record counts) get fuzz targets and property tests.
    - Credential-mutating async functions the fork touches carry a `# Cancel safety` section saying **NOT cancel-safe**.
12. **The guideline files are excluded from the published crate.** So are the lint-ratchet scripts and `.cargo/config.toml`.

## Deviations to resolve (status 2026-10-25)

Each open item is a task. The alignment plan (`rskrb5-review-fixes-lint-alignment`) closed
1, 3, 4, 9 and 11 and the cancel-safety item of 7 on `release/0.3.0`, and started the
burn-down in 2. Closed items stay listed
with the commits that closed them, until the release line is published.

1. **Closed: the profile is adopted on `release/0.3.0`.** `473ca10` added the `[lints]` tables, `.cargo/config.toml` and the baseline; `8eb3977` added `rustfmt.toml`; `62191fe` added `clippy.toml`. `fix/*` branches stay without the profile (rule 6).
2. **Upstream-origin lint baseline.** `scripts/lint-ratchet/baseline.toml` holds 6,520 `lint-migration:` entries (`baseline_gate.py --report`: `current 6520 / base 7396 entries`), down from 7,396 at adoption. Task: burn the baseline down file by file; it never grows outside a toolchain rebaseline.
3. **Closed: CI meets rule 9 on `release/0.3.0`** (`7e05965`). The jobs are listed under "The project" above.
4. **Closed: no `unsafe` in test helpers** (rule 5). `b61c3f2` replaced the environment helpers with a child test process.
5. **Upstream prose-rule debt.** Upstream async functions (91 at `release/0.2.2`) lack cancel-safety annotations, and upstream tests lack docs and `Result` returns. The prose gate enforces only fork-touched items. Task: burn it down with upstream; issue #8 covers `change_password*`.
6. **Dependency majors held back by upstream code:** `base64` 0.23, `getrandom` 0.4, `picky-krb` 0.13, `rasn`/`rasn-kerberos` 0.29, `compcol` 0.7, dev `toml` 1.1, plus the `pbkdf2 = "=0.13.0-rc.10"` pre-release pin. `FORK-NOTES.md` "Dependencies held back" lists the locked and latest versions on `release/0.3.0`. Task: upgrade with upstream, or in a dedicated plan with consumer-impact notes.
7. **Kerberos-overlay gaps in upstream behaviour:**
   - the weak-enctype predicate misses `rc4-hmac`/DES3 (upstream #3);
   - RC4 is in the default enctypes (run-2 lead);
   - kpasswd re-sends after a possible commit (upstream #7, run-2 lead);
   - **Closed (`4cd7423`): `change_password*` cancel safety** (upstream #8). Every public async password-change entry point has a `# Cancel safety` section saying `NOT cancel-safe: this mutates credentials on the KDC`: `TokioClient::change_password*` (4, `src/client/kpasswd.rs`), `NegotiateClient::change_password*` (4, `src/client/negotiate.rs`), and the `TokioKdcTransport` kpasswd exchanges (`exchange_kpasswd_request*`, `exchange_kpasswd_result*`, `send_to_kpasswd_realm` and the private `send_to_kpasswd_realm_explicit`; 6, `src/client/transport.rs`). Check: `rg -c 'NOT cancel-safe: this mutates credentials on the KDC' src/client`;
   - zeroization gaps (upstream #1, #6);
   - ambient-environment constructors are kept for upstream parity; the environment-free ones exist since 0.2.1.

   Task: track the upstream issues and the 18 run-2 needs-validation leads.
8. **`http-services.md` on the Negotiate layer and the Axum example.** Their responses must not leak internals. The example should demonstrate the OWASP header and fingerprint-stripping layers that a composing application owns. Task: verify the layer's `401`/reject bodies, and harden the example.
9. **Closed: the ccache parser has a fuzz target and property tests** (rule 11). `86e380f` added `fuzz/fuzz_targets/ccache_parse.rs` and the `proptest` tests in `tests/ccache.rs`. The scheduled `mutants` job still covers only `src/kadmin.rs` and `src/client/transport.rs`; widen it when a green run shows headroom.
10. **Retirement.** When an upstream release carries the series:
    - yank every published `rskrb5-patched` version (0.2.1, 0.2.2, and 0.3.0 once published);
    - move `kpasswd-rs` back to `rskrb5`;
    - delete this overlay;
    - archive the repository.
11. **Closed: the explicit enctype allowlist failed open, and MIT's DES3 names were unknown** (Kerberos overlay, found 2026-10-25). An explicit `permitted_enctypes` that resolved to no supported enctype acted as no allowlist, and `des3-cbc-sha1`/`des3-hmac-sha1` did not mean enctype 16. `cc8060c` fails closed (`config::Error::NoPermittedEnctypes`); `752832b` maps the MIT names. Both are on `fix/enctype-policy` (upstream PR #27, head `752832b`) and reach `release/0.3.0` through merge `7b9ee1c`.

## Common alignment steps (every project)

- **Lint tables:** the core Section 9 profile, unchanged; project additions go on top.
- **`clippy.toml`:** the core sample; duplicates and proper nouns appended, each with a reason.
- **`.cargo/config.toml`:** `[build] warnings = "deny"`.
- **CI:** the full core Section 12 list, including rustdoc `-D warnings` and `cargo machete`.
- **Guideline file:** a `RUST_GUIDELINES.md` pointer or vendoring index naming this overlay,
  with any vendored copy pinned and checksum-verified, never a partial copy.
