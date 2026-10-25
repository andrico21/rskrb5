# Lint profile, migration baseline and gates

This page describes how the `release/0.3.0` line enforces the strictest lint
profile on code it inherited from upstream `rskrb5` (`6f4abc9`) and on code
the fork wrote. Inherited violations are recorded one item at a time in a
baseline that can only shrink. Fork code gets no such allowance: two
differential gates check that it passes every rule outright.

Numbers on this page were measured on the release line at `f18676f`:

| Measure | Value |
|---|---|
| Baseline entries at adoption (`473ca10`) | 7,396 (74 files, 115 lints) |
| Baseline entries after the fork-code pass (`f18676f`) | 6,520 |
| Source lines carrying `lint-migration:` | 2,730 (one attribute can list several lints) |
| `deliberate:` expectations | 2 (table below) |
| Core-sanctioned test-module expectations | 45 `test code is not rendered API documentation`, 39 `a test fails by panicking` |
| Core-sanctioned facade expectations | 1 `public facade` (crate root) |
| `allow` attributes | 0 |

## Where the profile comes from

The `[lints]` tables in the root [`Cargo.toml`](../Cargo.toml) are the TOML
fence of core Section 9, "The profile", in the vendored
[core guidelines](rust-guidelines/RUST_GUIDELINES.md) at pin `8b52023`. That
fence equals rmcp-server-kit at `b7f6b66` (`Cargo.toml` lines 366 to 577)
when both are compared as parsed TOML, so no per-lint tie-break was needed.
The [vendoring index](../RUST_GUIDELINES.md) explains the pin and the
re-vendor procedure.

"Strictest union" means everything below applies at once, and where two
sources disagree the stricter rule wins:

- the core profile: every rustc group and allow-by-default lint, every
  rustdoc lint, Clippy `all`, `pedantic`, `nursery` and `cargo`, and 120 of
  135 `restriction` lints, all at `deny`, plus `unsafe_code = "forbid"`;
- the core's non-lint rules (cancel-safety notes, test docs, `Result`
  returning tests, Drop audits, emptiness messages);
- the [Kerberos overlay](rust-guidelines/overlays/domains/kerberos-credential-protocols.md)
  and the [HTTP services overlay](rust-guidelines/overlays/domains/http-services.md);
- the [rskrb5 project overlay](rust-guidelines/overlays/projects/rskrb5.md);
- rmcp-server-kit's gates, including its prose gates, ported as
  `prose_gate.py`.

One rmcp-server-kit rule is not adopted: its dash convention for prose. It is
an rmcp project overlay rule, not a core rule.

Supporting configuration:

- [`clippy.toml`](../clippy.toml): the core sample keys, plus the
  rskrb5-specific `allowed-duplicate-crates` (each with a reason comment,
  matching the `[[bans.skip]]` names in [`deny.toml`](../deny.toml)) and
  `doc-valid-idents`. `profile_eq.py --clippy-toml` allows only those two keys
  to differ from the core sample, and only by appending.
- [`.cargo/config.toml`](../.cargo/config.toml): `build.warnings = "deny"`,
  byte-identical to rmcp-server-kit's file.
- [`rustfmt.toml`](../rustfmt.toml): rmcp-server-kit's profile, run with
  `nightly-2026-10-03`.
- `fuzz/Cargo.toml` carries no lint tables. The fuzz crate is checked by the
  fork-lines gate with the profile passed as command-line flags.

## The lint-migration baseline

[`generate_baseline.py`](../scripts/lint-ratchet/generate_baseline.py)
writes the baseline. It runs one Clippy build per supported feature set
(K1 to K7 below) with `--all-targets`, plus `cargo doc` on stable and on
`nightly-2026-10-03`, all with lints capped at `warn`. It reads the JSON
messages and assigns each diagnostic to the compiler unit that produced it, so
it knows whether the diagnostic came from a test build or a normal build.

| Key | Cargo arguments |
|---|---|
| K1 | `--all-features` |
| K2 | (default features) |
| K3 | `--no-default-features` |
| K4 | `--features http` |
| K5 | `--features tower` |
| K6 | `--features evaluation` |
| K7 | `--no-default-features --features tokio` (the `kpasswd-rs` consumer set) |

Each diagnostic is placed on the narrowest item that contains it: a `use`
item, `fn`, `impl` block, associated `fn`, type, `const`, `static`, `mod`
declaration or `macro_rules!`. Diagnostics inside a macro invocation go on the
enclosing `fn` or `mod`. The generator emits one outer attribute per item and
predicate, with the reason `lint-migration: upstream baseline at <short sha>`:

- `#[expect(lint, reason = "...")]` when the lint fires in every build that
  compiles the file;
- `#[cfg_attr(<pred>, expect(lint, reason = "..."))]` otherwise. `<pred>` is an
  `any(...)` over the firing pairs, each pair an exact feature set (every one
  of the 8 package features listed as `feature = "x"` or `not(feature = "x")`)
  combined with `test` or `not(test)`. When a lint fires in every test build or
  every non-test build, the predicate simplifies to `test` or `not(test)`;
- `#[cfg_attr(doc, expect(...))]` for rustdoc-only lints.

Lints with the same predicate on one item are merged into one attribute.
Inner `#![...]` attributes are used only where no enclosing item exists: the
crate-level `dead_code_pub_in_binary` (exception (l) below), crate
documentation lints, and module-inner documentation lints. Module layout
diagnostics go on the owning `mod` declaration, not inside the module file.
`generate_baseline.py --report-placement` lists every inner attribute and why
the locator chose it.

The manifest [`scripts/lint-ratchet/baseline.toml`](../scripts/lint-ratchet/baseline.toml)
has one `[[baseline]]` entry per `(file, item, lint, predicate)` with a
`count` of attribute occurrences. Line numbers are not part of the identity,
so edits elsewhere in a file don't disturb it. `--refresh-manifest` rebuilds
the manifest from the attributes in the tree and refuses to add an entry
unless `--rebaseline` is passed.

## Ratchet rules

[`baseline_gate.py`](../scripts/lint-ratchet/baseline_gate.py) enforces these:

- Every `lint-migration:` attribute in the tree matches a manifest entry by
  file, item, lint and predicate.
- The ratchet base is the most recent commit touching the manifest whose
  subject starts with `lint: rebaseline for Rust ` or
  `lint: adopt the rmcp-server-kit strictest profile`. Today that is
  `473ca10`.
- Every later commit that touches the manifest, and finally the working tree,
  may only remove entries or lower counts. An entry added after the base
  fails, including one removed earlier and restored later.
- One kind of re-keying counts as a move, not an addition (exception (m)
  below).
- Every other `expect` reason must be a `deliberate:` reason for an
  API-shaping lint, or one of the core-sanctioned pairs on a matching item.
  `invariant:` reasons and anything else fail.
- The gate prints the current and base entry counts.

## Gates

All gate scripts live in [`scripts/lint-ratchet/`](../scripts/lint-ratchet/),
use the Python standard library only, and have a `--self-test` mode. CI runs
them in [`ci.yml`](../.github/workflows/ci.yml); [`prek.toml`](../prek.toml)
mirrors the fast ones as pre-push hooks.

| Script | What it checks | CI job | prek hook |
|---|---|---|---|
| `allow_gate.py --enforce` | no `allow` attribute anywhere, including inside `cfg_attr` lists | `lint-gates` | `lint-gates` |
| `profile_eq.py --clippy-toml` | `[lints]` equals the vendored core profile; `clippy.toml` equals the core sample apart from the two append-only keys | `lint-gates` | `lint-gates` |
| `completeness_check.py` | the profile is complete for the current stable: the rustc and `restriction` lints missing from `Cargo.toml` are exactly the documented exclusions | `lint-gates` | `lint-gates` |
| `baseline_gate.py --enforce` | the ratchet rules above | `lint-gates` | `lint-gates` |
| `fork_lines_gate.py --enforce` | no lint diagnostic caused by fork code (below) | `fork-lines` | none (slow) |
| `prose_gate.py --enforce` | the core's non-lint rules on fork-touched items (below) | `fork-lines` | none (slow) |

### Fork-lines gate semantics

`fork_lines_gate.py` compares diagnostics between two disposable trees:

1. **Reference:** a detached worktree at `6f4abc9` with HEAD's `rustfmt.toml`,
   `clippy.toml` and `[lints]` copied in, formatted with nightly rustfmt, and
   every inherited `allow` attribute blanked. Two compile compensations apply
   to the reference only ([`fork_reference.py`](../scripts/lint-ratchet/fork_reference.py)):
   its `rust-version` is set to HEAD's `1.99`, so MSRV-gated lints such as
   `clippy::duration_suboptimal_units` fire the same way in both trees; and
   the `hex` dev-dependency that upstream's `tests/krb_priv.rs` needs is added,
   because `6f4abc9` doesn't compile its default-feature tests otherwise.
2. **HEAD copy:** every `lint-migration:` attribute blanked, keeping line
   numbers, so baseline attributes cannot hide a fork diagnostic.
3. Both trees are built in K1 to K7 with the compiler-unit mode recorded,
   plus `cargo doc`.
4. **Line mapping:** each HEAD file is compared with its reference file on
   whitespace-stripped lines, ignoring generated baseline lines. Unchanged
   lines map to the reference; inserted or replaced lines are fork lines.
   Files listed in [`moves.toml`](../scripts/lint-ratchet/moves.toml) are
   compared with the file their content came from (`tests/support/*.rs` from
   `tests/common/mod.rs`; `tests/support/env.rs` has no source and is all fork
   code).
5. A HEAD diagnostic is a fork violation unless the reference has the same
   lint, in the same configuration and mode, on the mapped reference line. So
   a diagnostic counts when it sits on a fork line, and also when it fires only
   because fork lines changed an upstream item (for example `too_many_lines`).
6. **Fuzz leg:** the fuzz crate is a separate workspace, so the profile is
   passed as `-D`/`-F`/`-A` flags and every diagnostic in
    `fuzz/fuzz_targets/` is a fork violation.
7. **Root facade only:** before Cargo runs, `facade_gate.py` rejects every
   fork-origin `pub use` or `pub(...) use` outside `src/lib.rs`'s own root
   scope, including cfg-disabled code, nested modules in `src/lib.rs`, and
   fork edits to multiline re-exports. Comments and strings are ignored;
   inherited imports are mapped against nightly-formatted upstream source.
   This source check enforces the former O-2 advisory despite Clippy's
   crate-wide facade expectation.

`--paths` limits the report to some files. `--report` prints and exits 0;
`--enforce` exits 1 on any violation.

### Line provenance through authorized rewrites

Some upstream lines were edited under the authorized exceptions below. The
gate must still treat them as upstream, or every inherited diagnostic on them
would turn into a fork violation. [`provenance.py`](../scripts/lint-ratchet/provenance.py)
handles this with a strict rule:

- Only the explicitly reviewed full SHAs in `REVIEWED_REWRITES` in
  `provenance.py`, reachable in `6f4abc9..HEAD`, carry upstream credit across
  an edit. There are nine: `5712724`,
  `52b8cdc`, `1cf7b68`, `4d3d3a2`, `20f6404`, `2091037`, `0a22457`,
  `7d8926e` and `cd371cc`.
- Credit passes only through `replace` hunks of those commits, matched by
  shared code identifiers at least three characters long, excluding Rust
  keywords and `std`, `core`, `alloc`. Comments and string literals cannot
  supply matching tokens. Sharing only `let`, `fn` or a short name gives no
  credit. Lines a rewrite commit inserts get no credit.
- `lint: bring fork-authored ...` commits are never treated as rewrites.

The ninth SHA, `cd371cc`, was reviewed as the (f)/(n)/(o) client-test Result
conversion and shadow rename described below; it is not an implicit extension
of the original eight import/derived-item rewrites. A future authorized rewrite
must be isolated from fork changes, reviewed against its parent, and then have
its full SHA added to `REVIEWED_REWRITES` in an explicit reviewed edit with
fixtures. A `lint: rewrite ` subject alone grants nothing. Later fork edits
lose credit, and even a credited line must have the same lint, configuration
and compiler mode as the reference to suppress a diagnostic.
Moved helper paths (`common::x` becoming
`<topic>::x`) are normalized in code only, so string literals stay significant.

### Prose gate

`prose_gate.py` ports rmcp-server-kit's `prose_gates.py`: `cancel-safety`,
`test-docs`, `test-result`, `drop-audit` and `emptiness-message`, each with
its `--only` selector. It adds `credential-mutating`: a fork-touched async fn
named `change_password*`, `set_password*` or `exchange_kpasswd*` needs a
`# Cancel safety` section containing `NOT cancel-safe` (Kerberos overlay).

It reports **fork-touched items** only: items whose span contains at least one
fork line under the mapping above. A generated baseline attribute never makes
an item fork-touched. `test-result` requires a `Result` return only when the
test body has a propagation site; assertions and known infallible calls don't
count ([`prose_infallible.py`](../scripts/lint-ratchet/prose_infallible.py)).

This no-propagation/infallible exemption deliberately relaxes the blanket
`Result`-returning-test requirement at core line 1938 for fork-authored tests
too, not just fork-touched upstream tests. Adding an unused `Ok(())` wrapper
where there is nothing to propagate would trigger `clippy::unnecessary_wraps`.
Assertions (including error assertions) and recognized infallible construction
or ownership conversions therefore do not require `Result`; unknown calls,
fallible calls nested inside conversions, `?`, `expect` and `unwrap` outside
assertions still require it. Test docs and the other prose checks still apply.

## Authorized upstream-line rewrites and exceptions

The plan forbids edits to upstream-origin lines, with the exceptions listed
here. Every edit below preserves public names, types, runtime behavior and
test assertions unless the entry says otherwise. Where an entry says "clippy
cannot baseline it", a minimal compiler reproduction proved that no
item-level `expect` is fulfilled on that item.

### (a) to (g): planned from the start

- (a) The nightly rustfmt formatting commit `8eb3977`.
- (b) Generated `lint-migration:` attributes.
- (c) The `unsafe` environment helpers (`EnvVarGuard` in
  `tests/common/mod.rs`, `EnvOverride` and its callers in
  `tests/client_ad_integration.rs`) replaced by a child-process re-exec
  (`b61c3f2`). `forbid(unsafe_code)` cannot be expected.
- (d) The upstream `allow` attributes removed: `src/kadmin.rs`
  `too_many_arguments` and `tests/common/mod.rs` `dead_code`. Their
  diagnostics are baselined. The two `too_many_arguments` allows in
  `src/client.rs` were not upstream: they came from fork commit `782dcb8`, so
  they were handled as fork code under (i).
- (e) The test edits of the seven fix branches.
- (f) A `///` doc, a `#[cfg(test)] mod` wrapper or a `Result` return on an
  upstream test, only when the prose gate counts that test as fork-touched.
- (g) Shared helpers of `tests/common/mod.rs` moved unchanged into
  `tests/support/<topic>.rs`, with matching `#[path]` declarations and
  call-site paths (recorded in `moves.toml`).

### (h) `std` to `core`/`alloc` imports and the public facade

Clippy reports `std_instead_of_core` and `std_instead_of_alloc` on `use`
items, but an `expect` on a `use` item is reported as a useless attribute and
the original diagnostic stays. Commit `5712724` rewrote the diagnosed upstream
`use` paths to `core::` or `alloc::`, split and regrouped imports where
needed, and added `extern crate alloc;` to crate roots that need it.

The same commit added `#![expect(clippy::pub_use, reason = "public facade")]`
to `src/lib.rs`, the core-sanctioned reason for a genuine facade module (core
Section 9; rmcp-server-kit uses it in `src/lib.rs` and `src/secret.rs`). See
the enforced root-facade source check above: this expectation covers the whole
crate, not only root re-exports. Seven upstream non-root sites are covered by
it instead of item-level baseline entries: `src/client.rs` (three grouped
sites after rustfmt), `src/spnego.rs`, `src/kadmin.rs`, `src/krb_error.rs`, and
`src/evaluation/mod.rs` (one each). New fork non-root re-exports are rejected.

### (i) The single deliberate exception without a PR number

`client::build_tgs_req_for_realm_with_confounder_and_subkey` is public API
from fork commit `782dcb8` ("Let a TGS authenticator carry a subkey"; issue
#13, upstream PR still to come). It takes eight arguments. Fixing
`too_many_arguments` would change its signature, and no open upstream PR can be
cited, so it carries exactly this expectation:

```rust
#[expect(
    clippy::too_many_arguments,
    reason = "deliberate: client::build_tgs_req_for_realm_with_confounder_and_subkey - public API from fork commit 782dcb8, upstream PR pending"
)]
```

`baseline_gate.py` accepts this reason form for this one symbol only (exact
reason, file, symbol, lint and public visibility; `eba155b`). Any other
`deliberate:` reason must name an upstream PR.

The private helper `build_tgs_req_for_realm_inner` had the same lint. It was
fixed in code instead: its authenticator inputs are grouped in the private
parameter struct `TgsAuthenticatorContext` (`eba155b`), with no public API
change.

Later, todo 17 changed `kdc_realm: impl Into<String>` into a generic
`R: Into<String>` on this function and on
`build_tgs_req_for_realm_with_subkey` (`clippy::impl_trait_in_params`).
Callers compile unchanged, but turbofish calls now see a type parameter;
[FORK-NOTES](../FORK-NOTES.md) lists it under "Upgrading from 0.2".

### (j) and (k) Items clippy cannot baseline

The general class: when clippy cannot baseline a lint on a derived, import or
other item, the fix is a minimal behavior-preserving rewrite of that upstream
item, never a wider or file-level expectation. Each rewrite is its own
`lint: rewrite ` commit:

| Commit | Rewrite |
|---|---|
| `52b8cdc` | Single-character lifetimes renamed on derived types (`clippy::single_char_lifetime_names` survives an item `expect` on derived code): `ConfigEntry` (`'cache`), `ConfigJson`, `LibDefaultsJson`, `RealmJson` (`'config`), `IncludeDirective` (`'line`), `NegotiateLayer`, `NegotiateService`, `ServiceValidator` (`'keytab`), `Reader`, `Tlv` (`'buffer`). Independently bound lifetimes in impls are unchanged. |
| `1cf7b68` | The public aliases `pub type Result<T> = std::result::Result<T, Error>;` in `src/lib.rs` and `src/http.rs` use `core::result::Result`. Same type, same name. |
| `4d3d3a2` | `src/evaluation/data.rs` imports `alloc::fmt` instead of `std::fmt`. |
| `20f6404` | 36 derived-field paths use imports for the same types (`crate::<module>::Error` to `<module>::Error`, `std::io::Error` to `io::Error`, `std::str::Utf8Error` to an imported `core::str::Utf8Error`, `http_types::header::InvalidHeaderValue` to an imported name, `BuiltKpasswdRequest.request` to `kadmin::Request`) in `ap_rep`, `ap_req`, `ccache`, `client/kpasswd`, `client`, `config`, `http`, `kdc_rep`, `kdc_req`, `keytab`, `krb_cred`, `krb_priv`, `krb_safe`, `messages`, `service`, `spnego` and `ticket`. Feature guards and `From` implementations are unchanged. |
| `2091037` | `NegotiateService`'s associated `Future` type uses `core::result::Result`. |
| `0a22457` | `ProbeOutcome`'s `Display` impl header names `core::fmt::Display`. |
| `7d8926e` | The HTTP test alias `MutualSendResult` uses `core::result::Result`. |

### Recorded upstream-line edits of the fork-code pass (p)

Todos 17 and 18 edited a few upstream lines whose diagnostics fire only
because of release-line changes. Exception **(p)**, user-acknowledged on
2026-10-25 when authorizing the final review fixes, explicitly records these
behavior-preserving classes under the same principle as (j)/(k):

- `src/client.rs` (13 lines) and `src/client/kpasswd.rs` (13 lines):
  `crate::spnego::`, `crate::messages::`, `crate::keytab::` and
  `crate::kadmin::` prefixes dropped where the release line already imports
  the module (`unused_qualifications`), `std::io::ErrorKind` to
  `io::ErrorKind`, `keytab::Error::NoMatchingKey { .. }` to explicit
  `field: _` bindings, and `DEFAULT_TICKET_LIFETIME` written as
  `Duration::from_hours(24)`.
- `src/ccache.rs`: `std::io::ErrorKind` to `io::ErrorKind`.
- `src/config.rs`: the `resolve_realm` parameter renamed from `domain_name` to
   `dns_name` (clears a `shadow_*` lint in the fork body; callers are
   source-compatible), plus `#[inline]` and `#[must_use]` on that public
   function; ignoring its return value can now warn under strict lints.
   `ticket_lifetime` is written as `Duration::from_hours(24)`.
- `src/service.rs`: `DEFAULT_MAX_CLOCK_SKEW` written as
  `Duration::from_mins(5)`.

The three `Duration` edits were made before the reference tree got HEAD's
`rust-version` (`464f163`). They are behavior-preserving and stay.

### (l) Crate-level `dead_code_pub_in_binary`

`dead_code_pub_in_binary` is a crate-level diagnostic: rustc accepts its
expectation only at crate level, even though its spans name public items in
submodules. It fires in the library's unit-test binary, where many public
items are unused. Narrowing visibility or adding dummy uses would change or
dodge the public API, so `src/lib.rs` carries one inner attribute, limited to
the firing builds:

```rust
#![cfg_attr(
    test,
    expect(
        dead_code_pub_in_binary,
        reason = "lint-migration: upstream baseline at ee9cb04"
    )
)]
```

Only crate-level diagnostics with no enclosing item may use inner attributes.
`--report-placement` lists this one.

### (m) Module-wrap re-keying and the 0.45 body-similarity rule

Wrapping a fork-touched upstream test in a `#[cfg(test)] mod` under (f)
changes its baseline key from `fn X` to `mod W::fn X`. When the file, lint,
predicate and count are the same, `baseline_gate.py` and
`generate_baseline.py --refresh-manifest` treat this as a move, not an
addition (`b9e1b3a`).

A verifier showed that a bare name match could launder credits onto a new
item with the same name, so the move is now proved against the source
([`baseline_sources.py`](../scripts/lint-ratchet/baseline_sources.py),
`f24901b`):

- the old site must disappear, and each source and destination must be unique;
- the wrapper module must be new;
- the moved body must match the old body with a `difflib` ratio of at least
  **0.45**, after blanking baseline attributes, comments and whitespace (the
  `?` rewrites of (n) and (o) change bodies, so equality is too strict);
- `use` re-keys keep their own count-preserving check in `baseline_moves.py`.

A wrap and a shrink in the same commit is rejected, because the move matcher
needs equal counts; split them into two commits. The shrink-only rule is
otherwise unchanged.

### (n) and (o) `?` rewrites in fork-touched upstream tests, and the shadow rename

Adding the `-> Result` return required by (f) makes
`clippy::unwrap_in_result` fire on every upstream `Result::expect` call in the
test, and no baseline addition is allowed. In the listed tests only, upstream
`Result::expect("m")`, `unwrap()` and `expect_err` call sites were rewritten to
`?` forms with the same message, typically
`.map_err(|cause| format!("m: {cause}"))?`, and `return;` became
`return Ok(());`. Assertions and test logic are unchanged, and no other
upstream line in those tests was touched.

(n) authorized 27 tests in todo 20's paths. After the gate fixes, 17 of them
needed the conversion and carry it on the release line:

- `tests/ccache.rs`: `saves_and_loads_ccache_from_env`
- `tests/client_ad_integration.rs`: `strict_ad_gate_rejects_missing_testad`,
  `strict_ad_gate_rejects_malformed_user_kdc_endpoint`
- `tests/config.rs`: `loads_config_path_list_from_env`,
  `load_default_prefers_krb5_config_env`
- `tests/http.rs`: `tower_service_loads_keytab_env`,
  `tower_layer_loads_keytab_env`,
  `tower_layer_loads_default_keytab_when_env_is_absent`,
  `tower_service_prefers_env_keytab_over_config_default`
- `tests/kadmin.rs`: `kpasswd_reply_decrypt_result_returns_parsed_error_result`,
  `kpasswd_reply_parses_krb_error_response_data`,
  `kpasswd_reply_decrypt_result_returns_krb_error_result`
- `tests/keytab.rs`: `saves_and_loads_keytab_from_env`
- `tests/pac.rs`: `rejects_tampered_pac_server_checksum`
- `tests/service.rs`: `validates_ap_req_from_keytab_env`,
  `validates_ap_req_from_default_keytab_when_env_is_absent`,
  `validates_ap_req_prefers_env_keytab_over_config_default`

The other 10 aren't fork-touched under the final gate (moved-helper paths and
authorized rewrites now map as upstream), so (f) and (n) don't apply and they
keep their upstream signatures and bodies. Where an earlier draft had
converted one of them, `b3222c8` restored the upstream text:
`tests/config.rs` `resolve_realm_matches_gokrb5_specificity`,
`tests/http.rs` `blocking_negotiate_http_client_returns_first_response_without_challenge`,
`tests/pac.rs` `parses_gokrb5_pac_container_and_buffers`,
`derives_ad_credentials_from_kerb_validation_info`,
`parses_signature_data_and_zeroes_checksum_bytes`,
`parses_component_buffers_directly`,
`verifies_pac_server_checksum_with_service_key`,
`extracts_pac_from_if_relevant_authorization_data`, and
`tests/service.rs` `rejects_ap_req_with_invalid_ticket_pac_checksum`,
`detects_ap_req_replay`.

(o) extended (n) to 13 tests of todo 19 (`cd371cc`):

- `tests/client/password_change.rs`:
  `tokio_client_changes_password_with_cached_changepw_ticket`,
  `negotiate_client_changes_password_with_cached_changepw_ticket`,
  `negotiate_client_changes_explicit_target_password`,
  `blocking_negotiate_client_changes_password_with_cached_changepw_ticket`,
  `tokio_client_changes_explicit_target_does_not_rotate_password_credentials`,
  `tokio_client_changes_password_updates_password_credentials`
- `tests/client/session_cache.rs`: `tokio_client_loads_from_ccache_env`,
  `tokio_client_uses_config_default_ccache_when_env_is_absent`,
  `tokio_client_prefers_env_default_ccache_over_config_name`,
  `tokio_client_loads_keytab_from_env`,
  `tokio_client_loads_client_keytab_from_env`,
  `tokio_client_loads_default_client_keytab_when_env_is_absent`,
  `tokio_client_prefers_env_client_keytab_over_config_name`

(o) also covers one rename. In four password-change tests the upstream outer
binding `let response = synthetic_tgs_rep(..)` is now `let tgs_rep = ..`
(with its `&response` uses on the adjacent lines), so the fork-authored kpasswd
reply binding no longer triggers `clippy::shadow_unrelated`. The tests are
`tokio_client_changes_password_with_cached_changepw_ticket`,
`negotiate_client_changes_password_with_cached_changepw_ticket`,
`negotiate_client_changes_explicit_target_password` and
`blocking_negotiate_client_changes_password_with_cached_changepw_ticket`.

## Expectations other than the baseline

The only `deliberate:` expectations, from
`rg -n 'reason = "deliberate:' src tests examples fuzz`:

| File | Item | Lint | Reason |
|---|---|---|---|
| `src/client.rs` | `client::build_tgs_req_for_realm_with_confounder_and_subkey` | `clippy::too_many_arguments` | public API from fork commit `782dcb8`, upstream PR pending (exception (i)) |
| `src/http.rs` | `http::NegotiateHttpError` | `clippy::exhaustive_enums` | mirrors upstream PR #29; `#[non_exhaustive]` would change the public type that PR adds a variant to |

To recount, use `rg -n 'reason = "deliberate:' src tests examples fuzz | wc -l`
(prints 2). Don't sum `rg -c` output by eye: `rg -c` prints one
`path:count` line per file, and counts matching lines, not matches.

Core-sanctioned pairs sit only on `#[cfg(test)]` modules (or a secret type,
none so far) with the core's exact reason text:
`missing_errors_doc`/`missing_panics_doc`/`too_long_first_doc_paragraph`
with `test code is not rendered API documentation`, and
`panic_in_result_fn` with `a test fails by panicking`.

## Advisories

- **O-7, predicates are exact feature sets.** Baseline predicates name every
  feature as on or off for K1 to K7. A feature combination outside the matrix
  (for example `--no-default-features --features messages`, or
  `--features serde`) can leave expectations unfulfilled or miss some, and
  fail a strict `clippy -D warnings`. Only K1 to K7 are supported under the
  strict profile. Path-dependency consumers compile without Cargo's registry
  lint cap and must use one of K1 to K7, not arbitrary subsets. Several
  `--no-default-features` combinations don't compile their tests at all.
  The library build alone (`cargo check --lib`, rustc lints, warnings denied)
  is wider: CI's `lib-feature-sets` job checks `messages`, `spnego`, `http`
  and `evaluation` without default features, plus the compatibility-report
  binary and the README `axum-negotiate` example. A sweep of all 255
  non-empty subsets of the 8 features (29 distinct feature closures) passes
  except the 64 subsets that enable `tower` without `default`: the upstream
  tower `Service` impl in `src/http.rs` (`single_use_lifetimes`,
  `unused_results`) is baselined only under the K1 and K5 predicates, and
  eliding its lifetime re-keys 6 baseline sites, a manifest addition the
  ratchet refuses.
- **FULL-TEST counts 32 `test result: ok` lines.** The compatibility report
  binary has no tests and is `test = false` (core "Binaries"), so the threshold
  is 32, not the pre-profile 33. No test was removed. CI's `test` job checks
  `>= 32`.
- **Use a fresh `CARGO_TARGET_DIR` per worktree.** Several worktrees of this
  crate sharing one target directory can silently reuse stale test binaries:
  fingerprints use modification times, and a fresh checkout is older than the
  outputs. Confirm `Compiling rskrb5-patched (<that worktree>)` in the log.
- **Python bytecode.** The gate scripts import each other. Run them with
  `PYTHONDONTWRITEBYTECODE=1`, or remove `scripts/lint-ratchet/__pycache__/`
  afterwards, so the tree stays clean for `cargo package`.
- **Upstream reference quirk.** At `6f4abc9`, `tests/krb_priv.rs` uses `hex`
  without the dev-dependency, so the reference tree needs the compensation
  described above. The fix is upstream PR
  [#16](https://github.com/clelange/rskrb5/pull/16).

## New stable toolchain: rebaseline procedure

CI floats on `stable` (core Version Policy), so a new stable release can turn
the gates red with new lints. When that happens:

1. Run `python3 scripts/lint-ratchet/completeness_check.py`.
2. Get any new lint into the core profile upstream
   (`andrico21/rust-guidelines`, by review), then re-vendor with the
   procedure in [`RUST_GUIDELINES.md`](../RUST_GUIDELINES.md).
3. Replace the local `[lints]` tables and `clippy.toml` keys with the
   re-vendored core (`profile_eq.py --clippy-toml` must pass). Set the
   intended new `rust-version` BEFORE generating diagnostics (overlay rule 7).
4. Run `python3 scripts/lint-ratchet/generate_baseline.py --generate --rebaseline`.
   It adds expectations for new upstream-origin diagnostics and removes the
   ones that became unfulfilled.
5. Fix new fork-line and prose violations.
6. Re-run the whole matrix: MATRIX (K1 to K7, clippy and tests), DOCS,
   CONSUMER, MSRV, the gates, PROSE, the guideline checksums and SUPPLY.
7. Commit with the subject `lint: rebaseline for Rust <version>`. It's the
   only commit kind allowed to add manifest entries, and it becomes the new
   ratchet base.

## Upstream sync and PR review changes

When a `fix/*` branch changes (review feedback, or an upstream rebase), merge
it into the release line again, re-run nightly rustfmt, then repeat the
fork-code compliance pass on the new fork lines: `fork_lines_gate.py` and
`prose_gate.py` with `--paths` for the touched files, fix what they report,
and re-run the gates. The `fix/*` branches themselves stay upstream-shaped:
stable rustfmt, no lint profile, no fork identity.

## Divergence from the upstream PR branches

Each row lists the release-only lint, formatting and test-helper commits that
touch the files of that PR's branch, from
`git log --oneline <PR branch tip>..release/0.3.0 -- <files the PR touches>`.
A PR's diff and the release line differ on those files by exactly these
commits, on top of the other fork changes.

| PR | Branch at tip | Files | Release-only commits on those files |
|---|---|---|---|
| [#15](https://github.com/clelange/rskrb5/pull/15) | `rust-1-98-clippy-drift` at `40c506d` | 24 | `8eb3977`, `b61c3f2`, `5712724`, `0a22457`, `473ca10`, `7d8926e`, `b1a7cbd`, `e5a2cf8`, `b3222c8` |
| [#16](https://github.com/clelange/rskrb5/pull/16) | `hex-dev-dependency` at `0f9a113` | 1 | `473ca10`, `8fa5033` |
| [#17](https://github.com/clelange/rskrb5/pull/17) | `export-padata-constants` at `017f23f` | 2 | `8eb3977`, `5712724`, `eba155b`, `20f6404`, `473ca10`, `cad0330`, `b1a7cbd` |
| [#18](https://github.com/clelange/rskrb5/pull/18) | `kpasswd-verbatim-result-bytes` at `d65a038` | 3 | `8eb3977`, `5712724`, `eba155b`, `0a22457`, `473ca10`, `1ff4d93`, `e5a2cf8` |
| [#19](https://github.com/clelange/rskrb5/pull/19) | `Gittingc0dez/main` at `9403abe` | 2 | `8eb3977`, `5712724`, `0a22457`, `473ca10`, `cad0330`, `e5a2cf8` |
| [#20](https://github.com/clelange/rskrb5/pull/20) | `fix/service-replay-name-type` at `b7fb459` | 2 | `8eb3977`, `b61c3f2`, `5712724`, `52b8cdc`, `20f6404`, `473ca10`, `1ff4d93`, `e5a2cf8`, `b3222c8` |
| [#21](https://github.com/clelange/rskrb5/pull/21) | `fix/service-authenticator-realm` at `920f9b0` | 3 | `8eb3977`, `b61c3f2`, `5712724`, `52b8cdc`, `20f6404`, `473ca10`, `1ff4d93`, `e5a2cf8`, `b3222c8` |
| [#22](https://github.com/clelange/rskrb5/pull/22) | `fix/ccache-count-bounds` at `fdf641a` | 2 | `8eb3977`, `b61c3f2`, `5712724`, `52b8cdc`, `20f6404`, `473ca10`, `1ff4d93`, `e5a2cf8` |
| [#23](https://github.com/clelange/rskrb5/pull/23) | `fix/kadmin-unsigned-success` at `a089831` | 6 | `8eb3977`, `b61c3f2`, `5712724`, `eba155b`, `20f6404`, `0a22457`, `473ca10`, `cad0330`, `1ff4d93`, `b1a7cbd`, `dd633cd`, `cd371cc`, `abbde7a`, `e5a2cf8` |
| [#24](https://github.com/clelange/rskrb5/pull/24) | `fix/config-clockskew-handoff` at `3e4c6c5` | 4 | `8eb3977`, `b61c3f2`, `5712724`, `eba155b`, `52b8cdc`, `1cf7b68`, `20f6404`, `2091037`, `473ca10`, `7d8926e`, `1ff4d93`, `e5a2cf8`, `b3222c8` |
| [#25](https://github.com/clelange/rskrb5/pull/25) | `fix/host-case-spn` at `5dd96f2` | 3 | `8eb3977`, `b61c3f2`, `5712724`, `473ca10`, `b1a7cbd`, `dd633cd`, `cd371cc`, `abbde7a`, `e5a2cf8` |
| [#26](https://github.com/clelange/rskrb5/pull/26) | `fix/domain-realm-normalization` at `20e48ab` | 3 | `8eb3977`, `b61c3f2`, `5712724`, `52b8cdc`, `20f6404`, `473ca10`, `1ff4d93`, `b1a7cbd`, `dd633cd`, `cd371cc`, `abbde7a`, `e5a2cf8` |
| [#27](https://github.com/clelange/rskrb5/pull/27) | `fix/enctype-policy` at `7c2c297` | 8 | `8eb3977`, `b61c3f2`, `5712724`, `eba155b`, `52b8cdc`, `20f6404`, `473ca10`, `cad0330`, `1ff4d93`, `b1a7cbd`, `e5a2cf8` |
| [#28](https://github.com/clelange/rskrb5/pull/28) | `fix/client-renewal-series` at `fbf4320` | 3 | `8eb3977`, `b61c3f2`, `5712724`, `eba155b`, `20f6404`, `473ca10`, `cad0330`, `b1a7cbd`, `dd633cd`, `cd371cc`, `abbde7a`, `8fa5033` |
| [#29](https://github.com/clelange/rskrb5/pull/29) | `fix/mutual-auth-classification` at `71cc63b` | 5 | `8eb3977`, `b61c3f2`, `5712724`, `eba155b`, `52b8cdc`, `1cf7b68`, `20f6404`, `2091037`, `473ca10`, `7d8926e`, `1ff4d93`, `e5a2cf8`, `b3222c8` |
| [Gittingc0dez/rskrb5#1](https://github.com/Gittingc0dez/rskrb5/pull/1) | `fix/tcp-preauth-pinning` at `b1153c7` | 2 | `8eb3977`, `5712724`, `0a22457`, `473ca10`, `cad0330`, `e5a2cf8` |

Commit legend:

| Commit | Subject |
|---|---|
| `8eb3977` | style: adopt the rmcp-server-kit rustfmt profile (nightly-2026-10-03) |
| `b61c3f2` | test: set environment variables in a child test process instead of unsafe set_var; split shared test helpers by use |
| `5712724` | lint: rewrite flagged std imports to core and alloc |
| `eba155b` | lint: fix baseline gate for the authorized deliberate exception |
| `52b8cdc` | lint: rewrite derived type lifetimes where clippy cannot baseline it |
| `1cf7b68` | lint: rewrite Result aliases where clippy cannot baseline it |
| `20f6404` | lint: rewrite derived field paths where clippy cannot baseline it |
| `2091037` | lint: rewrite associated Future result path where clippy cannot baseline it |
| `0a22457` | lint: rewrite Display impl path where clippy cannot baseline it |
| `473ca10` | lint: adopt the rmcp-server-kit strictest profile with a lint-migration baseline |
| `7d8926e` | lint: rewrite HTTP test Result alias where clippy cannot baseline it |
| `cad0330` | lint: bring fork-authored client code to the profile |
| `1ff4d93` | lint: bring fork-authored service, http, config and parser code to the profile |
| `b1a7cbd` | lint: bring fork-authored client tests to the profile |
| `dd633cd` | lint: wrap fork-touched client tests in test modules |
| `cd371cc` | lint: rewrite fork-touched client tests to return Result |
| `abbde7a` | lint: finish fork-authored client tests |
| `e5a2cf8` | lint: bring fork-authored service, http, config and parser tests to the profile |
| `b3222c8` | lint: restore upstream tests that need no fork changes |
| `8fa5033` | style: taplo fmt the lint profile tables |

## Acceptance notes from adoption

- The generator places crate documentation expectations before a disabling
  root `#![cfg]`, because rustc discards expectations that follow it in a
  disabled crate.
- No doctest needed a baseline line.
- At adoption (`473ca10`) the fork-lines report could not finish, because the
  reference tree lacked `hex`. The compensation above (`dc86a2e`) fixed that,
  and the gate reported zero violations on the converged tree (`f18676f`).
