# Lint policy

`rskrb5-ng` passes the strictest lint profile of the vendored Rust guidelines
outright. There is no baseline: no `lint-migration:` expectation, no `allow`
attribute, and no exception outside the six forms below. Every feature closure
builds, lints and tests clean, and so does Windows.

## Where the profile comes from

- The `[lints]` tables in the root [`Cargo.toml`](../Cargo.toml) are the TOML
  fence of core Section 9, "The profile", in the vendored
  [core guidelines](rust-guidelines/RUST_GUIDELINES.md). The pin and the
  re-vendor procedure are in the [vendoring index](../RUST_GUIDELINES.md).
  `profile_eq.py` compares the two as parsed TOML; any difference fails.
- [`clippy.toml`](../clippy.toml) is the core sample. Only
  `allowed-duplicate-crates` (each with a reason comment, matching the
  `[[bans.skip]]` names in [`deny.toml`](../deny.toml)) and `doc-valid-idents`
  may differ, and only by appending.
- [`.cargo/config.toml`](../.cargo/config.toml) sets
  `build.warnings = "deny"`. CI keeps `-D warnings` on clippy and rustdoc.
- [`rustfmt.toml`](../rustfmt.toml) is run with `nightly-2026-10-03`.
- The fuzz crate (`fuzz/Cargo.toml`) is a separate workspace without lint
  tables; `fuzz_lint.py` applies the root profile to it as command-line flags.
- On top of the core: the
  [Kerberos overlay](rust-guidelines/overlays/domains/kerberos-credential-protocols.md),
  the [HTTP services overlay](rust-guidelines/overlays/domains/http-services.md)
  and the [rskrb5-ng project overlay](rust-guidelines/overlays/projects/rskrb5-ng.md).
  Overlays may add rules and may not remove any.

## The six sanctioned exceptions

A lint that fires is fixed in code. The only `#[expect]`/`#![expect]`
attributes allowed anywhere in `src`, `tests`, `examples`, `benches` and
`fuzz/fuzz_targets`, including inside `cfg_attr`, are these, with exactly
these reason texts and on these item kinds:

| # | Lints | Reason | Where |
|---|---|---|---|
| 1 | any of `clippy::missing_errors_doc`, `clippy::missing_panics_doc`, `clippy::too_long_first_doc_paragraph` (only those that fire) | `test code is not rendered API documentation` | outer, on a `mod` under `#[cfg(test)]` |
| 1 | `clippy::panic_in_result_fn` | `a test fails by panicking` | outer, on a `mod` under `#[cfg(test)]` |
| 2 | `missing_copy_implementations` | `secret material must not be implicitly copied` | outer, on a secret-holding type (`struct`, `enum`, `union`) |
| 3 | `clippy::pub_use` | `public facade` | `#![expect(..)]` at the crate root of `src/lib.rs` only |
| 4 | `clippy::missing_const_for_fn` | `deliberate: <path> - <why it must not be const>` (`<path>` contains `::`) | outer, on a `fn` (core "Public API of a library") |
| 5 | `clippy::unused_async_trait_impl` | `deliberate: <path> - <foreign trait> mandates async` (`<path>` contains `::`) | outer, on a `fn` or `impl` (core checklist) |
| 6 | `dead_code_pub_in_binary` | `public API: unused inside the unit-test harness` | `#![cfg_attr(test, expect(..))]` at the crate root of `src/lib.rs` only |

Form 6 exists because the lint fires on public items inside the library's
unit-test binary, and rustc accepts its expectation only at crate level.

Form 3 covers Clippy's crate-wide `pub_use`; `facade_gate.py` separately
restricts public re-exports to the crate-root scope of `src/lib.rs`.

Opting an *excluded* lint in on one item with
`#[deny(lint, reason = "...")]` is encouraged where its intent applies (core
Section 9, "Per-item use of an excluded lint"). It is not an exception and
passes every gate. `#[allow]`, `#![allow]` and `cfg_attr(.., allow(..))` are
forbidden.

## Gates

All gate scripts live in [`scripts/lint-gates/`](../scripts/lint-gates/), use
the Python standard library only, and have a `--self-test` mode. CI runs them
in the `lint-gates` job of [`ci.yml`](../.github/workflows/ci.yml);
[`prek.toml`](../prek.toml) mirrors the fast ones as a pre-push hook.

| Command | What it enforces |
|---|---|
| `<script> --self-test`, for every script | each gate still detects what it claims to, on inline fixtures |
| `allow_gate.py --enforce` | no `allow` attribute anywhere, including nested `cfg_attr` lists and inner attributes |
| `exception_gate.py --enforce` | every `expect` is one of the six sanctioned forms above on a matching item; `lint-migration:`, `invariant:` and any other reason fail |
| (both gates) | fail closed on spelling the lexer cannot see through: `#`, `!` and `[` are read as separate tokens, so `# [allow(..)]` is still an attribute; a macro metavariable in or as an attribute (`#[$m]`, `#$t`), an `allow(..)`/`expect(..)` token tree passed to a macro, an attribute that does not start with a path, and `include!` or `#[path]` of anything but a relative `.rs` path without `..` are all reported |
| `profile_eq.py --clippy-toml` | `[lints]` equals the vendored core profile; `clippy.toml` equals the core sample apart from the two append-only keys |
| `completeness_check.py` | the profile is complete for the current stable: the rustc and `restriction` lints missing from `Cargo.toml` are exactly the documented exclusions |
| `facade_gate.py --enforce` | no `pub use` (or `pub(..) use`) outside the crate-root scope of `src/lib.rs`, cfg-disabled code included |
| `prose_gate.py --enforce` | the core's non-lint rules on every item of the whole tree (`--paths <globs>` narrows a local run; `facade_gate.py --paths` works the same way, and an empty selection selects nothing) |
| `feature_closures.py run` | every feature closure: `cargo clippy --all-targets <args> -- -D warnings`, then `cargo test <args>` |
| `feature_closures.py check-ci .github/workflows/ci.yml` | the matrix of the job whose id is `closures` lists exactly the computed closures, each once; the job is defined once, no other `closures:` key exists (no decoy job or matrix), the matrix has no `include`/`exclude`, the job has no `if`/`continue-on-error`, and its steps run exactly the strict clippy and test commands. Nothing may cap lints or swallow a failure: the job has no `env`, `defaults`, `shell`, `container` or `working-directory` and uses only the checkout, toolchain and cache actions; the workflow sets no `defaults` and no Cargo or rustc variable beyond `CARGO_TERM_COLOR`, `CARGO_INCREMENTAL`, `CARGO_NET_RETRY` and `RUST_BACKTRACE`; and `.cargo/config.toml` keeps `build.warnings = "deny"` with no `rustflags`, wrapper, `rustc` or Cargo/rustc `[env]` variable |
| `fuzz_lint.py --enforce` | the root profile on the nightly fuzz crate, in a disposable copy (without `--enforce` it reports the clippy result and exits 0, like every gate) |
| `fuzz_coverage.py --enforce` | the parser inventory of [`review/fuzz.md`](review/fuzz.md) exists and is not empty, lists every function the parser search finds, names only functions still defined in their source file, and names only targets of `fuzz/Cargo.toml` (`--coverage DIR` proves the mappings from coverage exports) |
| `gate_hygiene.py --enforce` | the gate scripts carry no dead work: every `argparse` option is read, and every module-level helper is used outside a `self_test` |

`rg -n 'lint-migration' src tests examples fuzz` must print nothing.
`semver_baseline.py` is not a lint gate: it drives `cargo semver-checks`
against the last published release (the `semver-checks` job).

### Prose gate

`prose_gate.py` ports rmcp-server-kit's prose gates and adds one Kerberos
overlay rule. Each check has an `--only` selector:

- `cancel-safety`: a production `async fn` documents `# Cancel safety` (or
  carries a `cancel-safe:` note just above it);
- `credential-mutating`: an async `change_password*`, `set_password*` or
  `exchange_kpasswd*` has a `# Cancel safety` section containing
  `NOT cancel-safe`;
- `test-docs`: every test has a `///` doc;
- `test-result`: a test with a propagation site returns `Result`;
- `drop-audit`: a production `impl Drop` has a `Drop audit` note;
- `emptiness-message`: `assert!(x.is_empty())` carries a message.

`test-result` requires `Result` only when the test body has a propagation site
([`prose_infallible.py`](../scripts/lint-gates/prose_infallible.py)).
Assertions (including error assertions) and known infallible construction or
ownership conversions don't count, because an unused `Ok(())` wrapper would
trigger `clippy::unnecessary_wraps`. Unknown calls, fallible calls nested in
conversions, `?`, `expect` and `unwrap` outside assertions still require it.

## Every closure, and Windows

`feature_closures.py list` computes the distinct closures of the `[features]`
table (`default` counts as a feature) and the canonical Cargo arguments for
each: 36 closures today. Each one must pass `cargo clippy --all-targets <args>
-- -D warnings` and `cargo test <args>`; `feature_closures.py run` runs both
for all of them. A consumer may therefore enable any feature combination under
its own strict lints. In CI each closure is one leg of the `closures` matrix,
written out statically and held equal to the computed list by `check-ci`.

Items used only under some features carry a precise `#[cfg(feature = ..)]`,
and Unix-only helpers carry `#[cfg(unix)]`, so nothing is dead or unused in any
closure or on Windows:

```bash
cargo clippy --all-targets --all-features --target x86_64-pc-windows-msvc -- -D warnings
```

CI runs the same clippy natively on `windows-latest` (the `clippy-windows`
job).

## A new stable toolchain

CI floats on `stable` (core Version Policy), so a new stable release can bring
new lints. The owner allows the executor to update the shared core. Then:

1. Run `python3 scripts/lint-gates/completeness_check.py`; it lists the new
   lints the profile doesn't cover.
2. In `andrico21/rust-guidelines`, make one commit that changes only the core
   Section 9 profile (each new lint at the level the core's inclusion rule
   gives), the Exclusions table (each excluded lint with its reason) and the
   "tracks stable through" line. Push it.
3. Re-vendor at the new pin ([`RUST_GUIDELINES.md`](../RUST_GUIDELINES.md))
   and mirror the profile into `Cargo.toml` `[lints]` (`profile_eq.py
   --clippy-toml` passes).
4. Fix every new diagnostic directly, in one `toolchain:` commit. No baseline
   exists, and none is ever added.
5. Once MSRV passes on the new stable, raise `rust-version` and the MSRV
   toolchain to it.

## Running the gates locally

- Run the scripts with `PYTHONDONTWRITEBYTECODE=1`, so no `__pycache__` is
  left in the tree for `cargo package`.
- Give each worktree its own `CARGO_TARGET_DIR`. Worktrees sharing one target
  directory can silently reuse stale test binaries.

## History

The 0.3 line first carried a generated, shrink-only `lint-migration:`
baseline for inherited upstream code, with differential and ratchet gates.
The baseline reached zero entries, and the machinery was then deleted. The
full transition record (the authorized upstream-line rewrites (a) to (p), the
removed gates and the divergence from the upstream PR branches) is
`docs/lint-baseline.md` at commit `856da18`:
`git show 856da18:docs/lint-baseline.md`.
