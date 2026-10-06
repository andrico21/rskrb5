# Config: consume `[libdefaults] permitted_enctypes` as an enctype allowlist

- Severity: medium (likelihood medium / impact medium / confidence high) — fingerprint `src/config.rs:permitted_enctype_ids/policy-never-consumed`
- Audit: run-2 findings.json record (`verdict: confirmed`) + `agents/vfy-src-config-rs-permitted-en/artifacts/permitted-enctype-check2.log:229-234` and `agents/hunt2-transport-config/artifacts/transport-config-checks-5.log:667`
- Status: planned; not implemented in the fork; no upstream PR yet

## Problem

`LibDefaults::refresh_enctype_ids` derives `permitted_enctype_ids` from
`[libdefaults] permitted_enctypes`, but no code path consumes the field for
behaviour: the effective request list comes only from
`default_tkt_enctypes`/`default_tgs_enctypes` and is copied verbatim into
`KDC-REQ-BODY.etype`, and the reply-acceptance helpers that import the
KDC-chosen session key take no policy at all. An operator who narrows
`permitted_enctypes` therefore still advertises excluded enctypes (the crate
defaults resolve to `[18,17,23]`, including RC4-HMAC 23) and accepts a returned
session key outside the allowlist.

## Root cause (verified against upstream 6f4abc9)

- `src/config.rs:312` — `pub permitted_enctype_ids: Vec<i32>,` — declared as the permitted enctype IDs implemented by the crate's crypto.
- `src/config.rs:369` — `permitted_enctype_ids: Vec::new(),` — initialised empty.
- `src/config.rs:451-457` — `refresh_enctype_ids` writes it from `permitted_enctypes` via `parse_supported_enctype_ids` (`:456-457`) after `[libdefaults] permitted_enctypes` is parsed at `src/config.rs:427`.
- Exhaustive search over `src/` finds only the declaration, the default initialiser, the sole write, the serde projection (`src/config.rs:883`, `:931-932`), and one test assertion (`tests/client_ad_integration.rs:671`). No behavioural reader exists in `src/client.rs`, `src/client/options.rs`, `src/client/transport.rs`, or `src/client/kpasswd.rs`.
- `src/client/options.rs:56` — `options.etypes = if defaults.default_tkt_enctype_ids.is_empty() { DEFAULT_TKT_ENCTYPES.to_vec() } else { defaults.default_tkt_enctype_ids.clone() };` — never intersected with `permitted_enctype_ids`; the TGS twin is at `src/client/options.rs:153`.
- `src/client.rs:1569` — `build_as_req` copies `options.etypes` into `KDC-REQ-BODY.etype`; `build_tgs_req_for_realm_with_confounder` (`src/client.rs:1903`) does the same. An empty list fails closed through `Error::EmptyEtypes` (`src/client.rs:1575`, `:1913`).
- `src/client.rs:2280` — `process_as_rep(request, bytes, reply_key)`: signature has no policy parameter; the session key is imported at `src/client.rs:2331` — `session_key: encryption_key_from_rasn(&enc_part.key),`. The TGS twin `process_tgs_rep_inner` (`src/client.rs:2423`) imports at `:2477`.
- `src/config.rs:20-29` — `DEFAULT_ENCTYPES`, filtered by `parse_supported_enctype_ids` (`:801`) which keeps `arcfour-hmac-md5`; the resolved default request list is `[18,17,23]`.

Fork deltas are line-number only: `permitted_enctype_ids` sits at
`src/config.rs:413,498,585,1060-1061,1110` and `Config::parse` is
`parse_without_env` at `src/config.rs:214` (upstream `Config::parse` at
`:151`); `src/client/options.rs:56,153` are identical in both trees;
`client.rs`/`transport.rs` are shifted by the upstream fork commits.

## Evidence (from the audit)

- `agents/vfy-src-config-rs-permitted-en/artifacts/permitted-enctype-check2.log:230` — `permitted_ids=[18] as_req_etypes=[18, 17, 23] outside_permitted=[17, 23] control_default_tkt_etypes=[18] control_default_tgs_etypes=[18] RESULT confirmed_divergence` (sandbox exit 0).
- `agents/hunt2-transport-config/artifacts/transport-config-checks-5.log:667` — same divergence with `tgs_req_etypes=[18, 17, 23] tgs_outside_permitted=[17, 23]`.
- Payloads: `[libdefaults]\n permitted_enctypes = aes256-cts-hmac-sha1-96\n[realms]\n` reproduces; the control additionally narrows `default_tkt_enctypes`/`default_tgs_enctypes`, which is what actually changes the request list.
- `tests/client_ad_integration.rs:671` — asserts `rc4_config.libdefaults.permitted_enctype_ids` reflects the parsed rc4-hmac policy, so the field is observable while no client behaviour consumes it.

## Proposed fix

1. In `AsReqOptions::from_libdefaults` (`src/client/options.rs:56`) and
   `TgsReqOptions::from_libdefaults` (`:153`), filter the effective request list
   to `defaults.permitted_enctype_ids` when it is non-empty. An all-filtered list
   then fails closed through the existing `Error::EmptyEtypes`.
2. Enforce the same set on reply acceptance in
   `exchange_as_req_with_config` / `exchange_tgs_req_with_config`
   (`src/client/transport.rs:449,478`), which already hold `&Config`: reject an
   AS/TGS reply whose imported session-key enctype is outside the permitted set.
   Add an `Error::EnctypeNotPermitted` variant.
3. Leave behaviour unchanged when `permitted_enctype_ids` is empty (a hand-built
   `LibDefaults`; the library constructors seed it from `DEFAULT_ENCTYPES`).

```rust
let requested = if defaults.default_tkt_enctype_ids.is_empty() {
    DEFAULT_TKT_ENCTYPES.to_vec()
} else {
    defaults.default_tkt_enctype_ids.clone()
};
options.etypes = if defaults.permitted_enctype_ids.is_empty() {
    requested
} else {
    requested
        .into_iter()
        .filter(|etype| defaults.permitted_enctype_ids.contains(etype))
        .collect()
};
// The identical guard belongs in TgsReqOptions::from_libdefaults (options.rs:153)
// with DEFAULT_TGS_ENCTYPES/default_tgs_enctype_ids.
// An empty result is rejected by the existing Error::EmptyEtypes check in
// build_as_req (src/client.rs:1575) and the TGS builder (src/client.rs:1913).
```

```rust
// In exchange_as_req_with_config / exchange_tgs_req_with_config, where &Config is already held:
let permitted = &config.libdefaults.permitted_enctype_ids;
let session = process_as_rep(request, &response, reply_key)?;
if !permitted.is_empty() && !permitted.contains(&session.session_key.etype) {
    return Err(Error::EnctypeNotPermitted(session.session_key.etype)); // dedicated named error
}
// TGS twin: same check on TgsRepSession::session_key after process_tgs_rep;
// optionally also check the decoded returned ticket's enc_part etype.
```

## Regression tests

- `tests/client/as_exchange.rs::as_req_etypes_are_intersected_with_permitted_enctypes` — build `LibDefaults` with `permitted_enctypes` narrowed and `default_tkt_enctypes` left at the defaults; assert `AsReqOptions::from_libdefaults(..).etypes` contains only permitted ids and that the excluded `17/23` are gone (fails before the change).
- `tests/client/as_exchange.rs::tgs_req_etypes_are_intersected_with_permitted_enctypes` — the `TgsReqOptions` twin.
- `tests/client/as_exchange.rs::all_permitted_etypes_filtered_fails_closed` — `permitted_enctypes` disjoint from `default_tkt_enctypes` yields `Error::EmptyEtypes` from `build_as_req`, not an empty request.
- `tests/client_transport.rs::reply_session_key_outside_permitted_enctypes_is_rejected` — an `exchange_as_req_with_config`/`exchange_tgs_req_with_config` reply whose session key is excluded now returns `Error::EnctypeNotPermitted`; a permitted reply is unchanged. Fixtures: the existing config-driven transport mock plus the parsed-`krb5.conf` helper already used at `tests/client_ad_integration.rs:671`.

## Verification

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --test client
cargo test --all-features --test client_transport
```

## Compatibility / notes

- Behaviour changes only when `permitted_enctypes` is narrower than the
  effective request list (the ordinary hardening case); default configurations
  whose `permitted_enctype_ids` already equals the resolved list are unchanged.
  Document that narrowing `permitted_enctypes` now also constrains requests and
  reply acceptance, matching MIT krb5 semantics.
- Overlaps with `medium-as-rep-enctype-downgrade.md`: both add a session-key
  policy check around `process_as_rep`/`process_tgs_rep_inner`. Land them so the
  request-list binding (that plan) and the operator allowlist (this plan) are two
  distinct checks — the former binds to `request.etypes`, the latter to
  `config.libdefaults.permitted_enctype_ids`; keep both, ideally in a shared
  helper to avoid duplicated error branches.
- Neither in-flight HIGH fix touches `src/config.rs`, `src/client/options.rs`,
  or the transport wrappers (both are in `src/service.rs`).

## Upstream route

- Fork-only first, then a PR against `clelange/rskrb5`. Independent, but sequence
  it with the AS-REP enctype plan (shared `process_as_rep` acceptance site).

## Risks / open questions

- The KDC peer must select the excluded enctype from the client's advertised
  list, and the reply must still decrypt under the reply key, so a pure network
  attacker cannot trigger this (a KDC- or key-holding actor is required). The
  finding's impact is a crypto-policy downgrade, not key disclosure.
- The `permitted_enctype_ids.is_empty()` exemption means a hand-built
  `LibDefaults` with no permitted set keeps current behaviour; that is
  deliberate (the finding notes the library constructors seed it), but confirm
  no in-tree construction path leaves both the permitted set and the request
  list empty in a way that silently disables the new filter.
- Whether to also validate the returned ticket's `enc_part` etype (not just the
  session key) is left open; the finding names only the two enforcement points
  implemented above.