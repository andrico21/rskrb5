# Project overlay: rskrb5-ng

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

Facts were measured on `main` at `20798d6` in `andrico21/rskrb5-ng`.

- **What:** `rskrb5-ng`, a pure-Rust Kerberos 5 client and service library.
  - Package `rskrb5-ng`, version `0.3.0`; the lib target is `rskrb5_ng` (`Cargo.toml`
    `[package]` and `[lib]`).
  - Repository `andrico21/rskrb5-ng`, a standalone repository: `gh api
    repos/andrico21/rskrb5-ng` reports `"fork": false` and no parent. Development happens
    on `main`, the default branch.
  - It is an independent continuation of `rskrb5` (`clelange/rskrb5`). Upstream is not
    tracked: nothing is merged from it and nothing is proposed to it.
- **History:** the same code was published to crates.io as `rskrb5-patched` 0.2.1
  (2026-10-06) and 0.2.2 (2026-10-23). `rskrb5-ng` itself is not published (crates.io
  returns 404 for it).
- **Consumer:** `kpasswd-rs` vendors `rskrb5-patched` 0.2.1 as a **path dependency**
  (`crates/kpasswd-rs/Cargo.toml`: `default-features = false, features = ["tokio"]`) and
  denies warnings. So this crate's `[lints]` table runs inside the consumer's build.
- **Toolchain:** edition 2024, `rust-version = "1.99"` (stable 1.99.1 is current). CI runs
  floating `stable`, `nightly-2026-10-03` for rustfmt, the second rustdoc run and fuzz, and
  `1.99.0` for the MSRV build. `src/lib.rs` has `#![forbid(unsafe_code)]`;
  `.cargo/config.toml` sets `build.warnings = "deny"`.
- **Vendored rules:** `docs/rust-guidelines/` holds the core, the two domain overlays and
  this file with `SHA256SUMS`. The root `RUST_GUIDELINES.md` index names the pin and the
  re-vendor procedure. CI (`docs-validate`) checks the checksums, and
  `profile_eq.py --clippy-toml` checks `Cargo.toml` and `clippy.toml` against the vendored
  core.

## Project rules

1. **The core and both domain overlays apply in full.** A gap is a dated deviation below,
   phrased as a task, never permission.
2. **Lint profile:** the core Section 9 profile, unchanged, in the root `Cargo.toml`, with
   **zero generated exemptions**. Only six `expect` forms are sanctioned:
   - on `#[cfg(test)]` modules, `clippy::missing_errors_doc`, `clippy::missing_panics_doc`
     and `clippy::too_long_first_doc_paragraph` (only those that fire) with
     `reason = "test code is not rendered API documentation"`, and
     `clippy::panic_in_result_fn` with `reason = "a test fails by panicking"`;
   - `missing_copy_implementations` on a secret-holding type, with
     `reason = "secret material must not be implicitly copied"`;
   - `#![expect(clippy::pub_use, reason = "public facade")]` in `src/lib.rs` only;
   - `clippy::missing_const_for_fn` with `reason = "deliberate: <path> - <why it must not be const>"`;
   - `clippy::unused_async_trait_impl` with `reason = "deliberate: <path> - <foreign trait> mandates async"`;
   - in `src/lib.rs` only, `#![cfg_attr(test, expect(dead_code_pub_in_binary, reason =
     "public API: unused inside the unit-test harness"))]`.
3. **No `#[allow]`/`#![allow]`/`cfg_attr(.., allow(..))` and no `unsafe` anywhere,**
   tests included. Environment-dependent tests set variables in a child test process.
4. **Every feature closure lints and tests clean.** The closures are computed from the
   `[features]` table of `Cargo.toml`, never hand-listed. Each one passes
   `cargo clippy --all-targets -- -D warnings` and `cargo test`. Clippy with
   `--all-features --target x86_64-pc-windows-msvc` is clean too.
5. **The core's prose rules apply to all code:** cancel-safety sections, test docs,
   `Result`-returning tests, Drop audits and emptiness messages.
6. **Toolchain:** floating `stable` in CI (core Version Policy), never pinned;
   `rust-version` is the latest stable the crate was verified on, proven by an MSRV job.
7. **Dependencies** are at their latest major versions, with no pre-release pins.
8. **CI is the core Section 12 list plus `rmcp-server-kit`'s stricter practice,** all
   blocking: `fmt`; `clippy` and tests in every feature closure; `lib-feature-sets`;
   `readme-commands`; `test` on Linux, macOS and Windows; `i686`; `docs` (rustdoc
   `-D warnings` on stable and the dated nightly); `msrv`; `semver-checks`;
   `publish-dryrun`; `consumer` (the packaged crate as a path dependency with warnings
   denied, in the consumer's feature set and with default features); `deny`; `audit`;
   `vet`; `machete`; `taplo`; `docs-validate`; the lint gates; `package`. Advisory
   (`continue-on-error`): `geiger`, `rustdoc-nightly-canary`, and the scheduled `mutants`
   and `fuzz`.
9. **Releases go only through the tag-gated workflow.** `release.yml` runs after a green CI
   run, publishes only when a `vN.N.N` tag points at the commit, and publishes `--locked`.
   The tag is cut on a commit of `main`. Once a prior `rskrb5-ng` release exists,
   `cargo semver-checks` runs against it (`scripts/lint-ratchet/semver_baseline.py`; with
   none, it prints a notice and passes).
10. **Development files stay out of the published crate:** `RUST_GUIDELINES.md`,
    `docs/rust-guidelines/`, the lint scripts and `.cargo/` (`package.exclude`).
11. **Kerberos specifics:**
    - an explicitly configured enctype request list that names an enctype outside an
      explicit `permitted_enctypes` is **rejected with the enctype named**, never silently
      narrowed;
    - enctype tests assert on the **encoded** AS-REQ/TGS-REQ etype list;
    - every parser of attacker-controlled bytes has a fuzz target;
    - credential-mutating async functions carry a `# Cancel safety` section saying
      **NOT cancel-safe** (today 14 in `src/client`: `rg -c 'NOT cancel-safe: this mutates
      credentials on the KDC' src/client`).
12. **The frozen upstream PR heads are not maintained.** The `fix/*` branches and
    `rust-1-98-clippy-drift`, `hex-dev-dependency`, `export-padata-constants` and
    `kpasswd-verbatim-result-bytes` stay on the remote as they are, for the open upstream
    pull requests. They receive no commits and no deletion.
13. **Ambient inputs:** library code reads the environment only in named
    ambient-discovery constructors (`KRB5_CONFIG`, `KRB5CCNAME`, `KRB5_KTNAME`,
    `KRB5_CLIENT_KTNAME`). Each one is documented with an `# Ambient input` section and
    pinned by a guard test. There are no implicit reads anywhere else.
14. **A new stable Rust is adopted by procedure:** the core Section 9 profile is updated
    here by a reviewed commit, re-vendored, mirrored into `Cargo.toml`, and every new
    diagnostic is fixed directly. No exemption is added.

## Deviations to resolve (status 2026-10-25)

Each item is a task. "Todo N" refers to the owner's plan `rskrb5-ng-own-way`.

1. **Generated lint baseline** (rules 2 and 4). `scripts/lint-ratchet/baseline.toml` holds
   6,514 `lint-migration:` entries (`baseline_gate.py --report`: `current 6514 / base 7396
   entries`). CI still runs the transition gates (`baseline_gate.py`, `fork-lines`) and
   the K1 to K7 `features-matrix`, not the computed closures; other feature sets fail
   (advisory O-7 in `docs/lint-baseline.md`). There is no Windows clippy job. Task: burn
   the baseline to zero, then delete it and the transition machinery (todo 27), with every
   closure strict (todo 26) and the final pipeline (todo 28).
2. **Prose rules on upstream-origin code** (rule 5). `prose_gate.py` checks fork-touched
   items only. Task: whole-tree prose gate (todo 7), burned down by todos 8 to 21.
3. **Dependency majors held back** (rule 7): `base64` 0.22, `getrandom` 0.3, `rasn` and
   `rasn-kerberos` 0.28, `compcol` 0.6, `picky-krb` 0.12, dev `toml` 0.9, and the
   `pbkdf2 = "=0.13.0-rc.10"` pre-release pin. Task: todo 6.
4. **Implicit environment reads** (rule 13). `LibDefaults::new()` reads `UID` and `HOME`
   (`src/config.rs`), `%{uid}` expansion reads `UID` (`src/file_name.rs`), and the
   transport reads `RSKRB5_DNS_SERVER` (`src/client/transport.rs`). No constructor has an
   `# Ambient input` section yet (`rg -c '# Ambient input' src` finds none). Task: todos 35
   to 37.
5. **The new-stable procedure is not yet written in the repository** (rule 14).
   `docs/lint-policy.md` does not exist, and `docs/lint-baseline.md` still describes a
   rebaseline. Task: todo 27 replaces it with `docs/lint-policy.md`.
6. **Open review backlog.** The open review findings, audit leads and rule gaps, including
   the SPNEGO mechanism selection, are not yet fixed or dismissed. Task: todos 29 to 38,
   with the review index in todo 39.
7. **Parser fuzz coverage** (rule 11). Only `kpasswd_reply` and `ccache_parse` have fuzz
   targets. Task: todo 40.
8. **Mutation-testing scope.** The scheduled `mutants` job covers only `src/kadmin.rs` and
   `src/client/transport.rs`. Task: whole-crate scope, todo 41.
9. **Unpublished.** `rskrb5-ng` is not on crates.io. Publishing waits for the owner.
10. **`kpasswd-rs` still depends on `rskrb5-patched` 0.2.1.** Its migration to `rskrb5-ng`
    is the consumer's own task.

## Common alignment steps (every project)

- **Lint tables:** the core Section 9 profile, unchanged; project additions go on top.
- **`clippy.toml`:** the core sample; duplicates and proper nouns appended, each with a reason.
- **`.cargo/config.toml`:** `[build] warnings = "deny"`.
- **CI:** the full core Section 12 list, including rustdoc `-D warnings` and `cargo machete`.
- **Guideline file:** a `RUST_GUIDELINES.md` pointer or vendoring index naming this overlay,
  with any vendored copy pinned and checksum-verified, never a partial copy.
