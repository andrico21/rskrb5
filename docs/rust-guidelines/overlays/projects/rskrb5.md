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

## The project (verified 2026-10-23)

- **What:** `andrico21/rskrb5`, a temporary fork of `clelange/rskrb5`.
  - It is published to crates.io as **`rskrb5-patched`**: 0.2.1 (2026-10-06), and 0.2.2 (2026-10-23, tag `v0.2.2` at `58b27bb`).
  - The lib target stays `rskrb5`.
  - Its consumer is `kpasswd-rs`. It vendors 0.2.1 by sha256 as a **path dependency**, with `default-features = false, features = ["tokio"]`, and denies warnings. So this crate's `[lints]` table runs inside the consumer's build.
- **Base:** upstream `main` at `6f4abc9` plus:
  - the 0.2.1 series: Rust 1.98 clippy drift, `hex` dev-dependency, padata exports, verbatim kpasswd result bytes, environment-free `Config`/`LibDefaults`, `include`/`includedir`, the TGS authenticator subkey;
  - the 0.2.2 additions: AP-REQ replay identity (PR #20), authenticator realm binding (PR #21), the TCP framing/preauth stream (upstream PR #19 plus Gittingc0dez/rskrb5#1).

  `FORK-NOTES.md` carries the table.
- **Branches:**
  - `main` = upstream history plus the two workflow files. `release.yml` runs from here, because it triggers on `workflow_run`.
  - `release/*` carries the series.
  - `fix/*` carries one upstream PR each, based on `6f4abc9`, upstream-shaped.
  - Eight medium/low fix branches (run-2 audit) are implemented and pushed, but not yet released or proposed upstream.
- **Toolchain (today):**
  - edition 2024, `rust-version = "1.88"`;
  - no `[lints]` table, `clippy.toml`, `rustfmt.toml`, `.cargo/config.toml`, `deny.toml` or `supply-chain/`;
  - `src/lib.rs:38` has `#![forbid(unsafe_code)]`, but the test helpers in `tests/common/mod.rs` and `tests/client_ad_integration.rs` mutate the environment in `unsafe` blocks.
  - Four upstream `allow` attributes exist (`src/client.rs` ×2, `src/kadmin.rs`, `tests/common/mod.rs`).
- **CI:**
  - `ci.yml` runs on Ubuntu stable only: fmt, a no-default-features check, advisory clippy, tests, docs, package; plus scheduled advisory `mutants` and `fuzz`. The fork dropped upstream's macOS/Windows/1.88 test legs and its i686 check.
  - `release.yml` publishes on a `vN.N.N` tag, gated on CI, without `--locked`.
  - `fuzz/Cargo.toml` names the dependency `rskrb5`, so it no longer resolves after the package rename.
- **Profile gap (measured 2026-10-23):** the core Section 9 profile at warn on `release/0.2.2` reports 7,906 distinct diagnostics. They cover 104 lints in 54 files; 285 are on fork-authored lines.
- **Vendored rules:** none committed yet. A cached copy of the core, the two domain overlays, this file and the README is staged at `docs/rust-guidelines/` with `SHA256SUMS`, plus a root `RUST_GUIDELINES.md` index naming the pin. It lands on `release/0.3.0` with the alignment plan.

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

## Deviations to resolve (status 2026-10-23)

Each is a task. The approved alignment plan (`release/0.3.0`, plan
`rskrb5-review-fixes-lint-alignment`) closes 1, 3, 4 and 9 and opens the burn-down in 2.

1. **The profile is not adopted on any branch** (no lint tables, `clippy.toml`, `rustfmt.toml` or `.cargo/config.toml`). Task: the alignment plan.
2. **Upstream-origin lint baseline.** About 7,600 diagnostics on upstream-origin lines will be carried as `lint-migration:` expectations. Task: burn the baseline down file by file; it never grows outside a toolchain rebaseline.
3. **CI is below rule 9.** Fork CI lacks the clippy gate, the feature matrix, the OS matrix, i686, MSRV, audit, deny, vet, machete, semver-checks, taplo, the publish dry-run and the gates. Task: the alignment plan.
4. **`unsafe` in test helpers** (rule 5). Task: the alignment plan.
5. **Upstream prose-rule debt.** Upstream async functions (91 at `release/0.2.2`) lack cancel-safety annotations, and upstream tests lack docs and `Result` returns. The prose gate enforces only fork-touched items. Task: burn it down with upstream; issue #8 covers `change_password*`.
6. **Dependency majors held back by upstream code:** `base64` 0.23, `getrandom` 0.4, `picky-krb` 0.13, `rasn`/`rasn-kerberos` 0.29, `compcol` 0.7, dev `toml` 1.1, plus the `pbkdf2 = "=0.13.0-rc.10"` pre-release pin. Task: upgrade with upstream, or in a dedicated plan with consumer-impact notes.
7. **Kerberos-overlay gaps in upstream behaviour:**
   - the weak-enctype predicate misses `rc4-hmac`/DES3 (upstream #3);
   - RC4 is in the default enctypes (run-2 lead);
   - kpasswd re-sends after a possible commit (upstream #7, run-2 lead);
   - `change_password*` cancel safety is undocumented (upstream #8);
   - zeroization gaps (upstream #1, #6);
   - ambient-environment constructors are kept for upstream parity; the environment-free ones exist since 0.2.1.

   Task: track the upstream issues and the 18 run-2 needs-validation leads.
8. **`http-services.md` on the Negotiate layer and the Axum example.** Their responses must not leak internals. The example should demonstrate the OWASP header and fingerprint-stripping layers that a composing application owns. Task: verify the layer's `401`/reject bodies, and harden the example.
9. **Mutants scope** (`src/kadmin.rs`, `src/client/transport.rs`) and the single fuzz target are narrow. Task: add the ccache parser target (rule 11), and widen mutants when a green run shows headroom.
10. **Retirement.** When an upstream release carries the series:
    - yank every published `rskrb5-patched` version (0.2.1, 0.2.2, and 0.3.0 once published);
    - move `kpasswd-rs` back to `rskrb5`;
    - delete this overlay;
    - archive the repository.

## Common alignment steps (every project)

- **Lint tables:** the core Section 9 profile, unchanged; project additions go on top.
- **`clippy.toml`:** the core sample; duplicates and proper nouns appended, each with a reason.
- **`.cargo/config.toml`:** `[build] warnings = "deny"`.
- **CI:** the full core Section 12 list, including rustdoc `-D warnings` and `cargo machete`.
- **Guideline file:** a `RUST_GUIDELINES.md` pointer or vendoring index naming this overlay,
  with any vendored copy pinned and checksum-verified, never a partial copy.
