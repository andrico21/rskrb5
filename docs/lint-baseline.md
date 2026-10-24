# Lint migration baseline

The root Cargo lint tables match the vendored core Section 9 profile and
rmcp-server-kit at `b7f6b66`. Generated expectations record the compiler-unit
feature and test-mode coverage; the manifest counts attribute occurrences,
not repeated diagnostics. The later fork-code compliance tasks remove their
entries rather than treating this initial migration as final fork compliance.

## Behavior-preserving preparatory rewrites

Compiler reproductions are retained in the maintainer's task-14 evidence log.
These rewrites preserve public names, types, signatures and runtime behavior:

- `5712724`: diagnosed `std` imports use their `core`/`alloc` equivalents;
  necessary `extern crate alloc` declarations and import grouping were added.
  The library facade uses the core-sanctioned `public facade` expectation.
- `eba155b`: the private TGS request helper groups authenticator inputs in
  `TgsAuthenticatorContext`. The existing public eight-argument function keeps
  its signature and the specifically authorized pending-PR deliberate reason.
- `52b8cdc`: derived-type lifetimes were alpha-renamed in `ConfigEntry`,
  `ConfigJson`, `LibDefaultsJson`, `RealmJson`, `IncludeDirective`,
  `NegotiateLayer`, `NegotiateService`, `Reader`, `ServiceValidator` and `Tlv`.
- `1cf7b68`: the public Result aliases in `src/lib.rs` and `src/http.rs` use
  `core::result::Result`.
- `4d3d3a2`: the evaluation data module imports `alloc::fmt`.
- `20f6404`: 36 derived-field paths use imports for the same error/request types
  in `ap_rep`, `ap_req`, `ccache`, `client/kpasswd`, `client`, `config`, `http`,
  `kdc_rep`, `kdc_req`, `keytab`, `krb_cred`, `krb_priv`, `krb_safe`, `messages`,
  `service`, `spnego` and `ticket`. Feature guards and From implementations remain.
- `2091037`: `NegotiateService`'s associated Future uses `core::result::Result`.
- `0a22457`: `ProbeOutcome`'s Display implementation names `core::fmt::Display`.
- The HTTP test's `MutualSendResult` alias uses `core::result::Result`.

These path and lifetime rewrites avoid compiler attribution failures proven by
minimal reproductions; no unrelated item or file-wide expectation substitutes
for item ownership.

## Crate and module ownership

`dead_code_pub_in_binary` requires crate-level lint control even when its spans
name public items in submodules. The generator maps it to the Cargo target's
source root and emits a test-conditioned inner expectation after root docs and
existing inner attributes. No public item is hidden or given dummy uses.

Crate documentation expectations precede a disabling root `#![cfg]`: rustc
discards expectations after that attribute in disabled crates. They remain
after leading docs and earlier non-disabling inner attributes. Module layout
diagnostics are placed on the owning `mod` declaration, not inside `mod.rs`.
Module-inner documentation diagnostics remain attached to those docs.

Complete observed test-only or non-test-only coverage simplifies to `test` or
`not(test)`; partial feature coverage retains explicit feature predicates. This
also prevents generated attributes inside functions from artificially exceeding
the function-line limit after rustfmt.

## Acceptance interpretation

The compatibility report binary has no unit tests and is explicitly `test = false`.
Consequently FULL-TEST has 32 successful result targets, rather than the plan's
pre-change 33; no actual test was removed or disabled by this adjustment.

The initial fork-lines report cannot finish its upstream default-feature leg:
`6f4abc9` references `hex` in `tests/krb_priv.rs` without enabling that dependency.
The failed report is retained, not presented as a clean differential gate.
Prose and fork compliance remain the subsequent plan tasks' responsibility.
