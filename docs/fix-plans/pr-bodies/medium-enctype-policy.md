# client: bind reply enctypes to the request and enforce an explicit permitted_enctypes allowlist

- Target: `clelange/rskrb5` `main` (`6f4abc9`), branch `fix/enctype-policy`.
- Fixes #5. Related to #4, which this PR doesn't fix (see Notes).
- Commits:
  - `236c4ce` client: bind AS/TGS reply and session enctypes to the requested list
  - `6b64394` client: consume [libdefaults] permitted_enctypes as an enctype allowlist
  - `f8ffc5e` client: enforce permitted_enctypes only when configured explicitly
  - `79a15db` test: set the explicit permitted flag in the TGS intersection test
  - `31e5910` config: keep the explicit permitted_enctypes flag across serde round-trips
  - `7c2c297` config: reject an explicit enctype list outside permitted_enctypes instead of narrowing it

## Problem

There were two related gaps in how the client applies enctype policy.

**1. Replies weren't bound to the requested enctypes (#5).** When the first AS-REQ is answered directly with an AS-REP (an account without pre-authentication, or a caller that set `assume_preauthentication`), the client derived the reply key from the reply's own `enc_part.etype`. The keytab consumer also selected its key by the reply's `etype`/`kvno`. Neither path checked `AsReq.etypes`. `process_as_rep` and `process_tgs_rep_inner` then imported the returned session key without checking it against the request either. So a reply in an enctype the caller never asked for was accepted; RC4-HMAC (23) against a request listing only AES256 (18) was reproduced for both consumers.

**2. `[libdefaults] permitted_enctypes` was parsed and never used.** `permitted_enctype_ids` was filled in and then only reported. Request lists came from `default_tkt_enctypes`/`default_tgs_enctypes` alone, and the config-driven exchanges accepted any session-key enctype. An operator who narrowed `permitted_enctypes` still advertised the excluded enctypes (the shipped defaults resolve to `[18, 17, 23]`, RC4 included) and accepted a session key outside the allowlist.

Two constraints shape the fix for the second gap:

- The seeded default permitted list is gokrb5-derived and has no SHA2 enctypes, unlike MIT's. Enforcing it when the operator never set it would break valid SHA2-only configurations, so enforcement applies only when `permitted_enctypes` is set explicitly.
- When an operator sets both an explicit request list and an explicit `permitted_enctypes`, and the two disagree, quietly dropping the extra enctypes sends a narrower request than the operator wrote, with no signal. That conflict is a configuration error and should be reported as one.

RFC basis:

- RFC 4120 section 5.4.1: the `KDC-REQ-BODY` `etype` field "specifies the desired encryption algorithm to be used in the response".
- RFC 4120 section 3.1.3: the KDC uses the request's `etype` list to pick the AS-REP encryption and answers `KDC_ERR_ETYPE_NOSUPP` when it can't accommodate any of them. A compliant KDC never needs the client to accept an enctype outside its request on this path.
- MIT `krb5.conf(5)`: `permitted_enctypes` identifies the enctypes permitted for session keys and for ticket and authenticator encryption.

## Change

Reply binding (`236c4ce`):

- `password_initial_as_rep_session` and `keytab_initial_as_rep_session` reject a reply `enc_part.etype` outside the request's `KDC-REQ-BODY.etype` before they derive or select the reply key.
- `process_as_rep` and `process_tgs_rep_inner` reject an imported session key outside the request's list. On the TGS path only the new session key is checked; the TGS-REP encryption itself keeps using the TGT session-key enctype.
- New error: `rskrb5_ng::error::Client::EnctypeNotRequested(i32)`.

Allowlist (`6b64394`, `f8ffc5e`, `79a15db`):

- `LibDefaults` gains `permitted_enctypes_explicit: bool`, set when `[libdefaults] permitted_enctypes` is parsed.
- When the flag is set, `AsReq::from_libdefaults` and `TgsReq::from_libdefaults` narrow the request list to `permitted_enctype_ids`. An empty result fails closed through the existing `Error::EmptyEtypes`.
- When the flag is set, `exchange_as_req_with_config` and `exchange_tgs_req_with_config` reject a session key outside the allowlist with the new `rskrb5_ng::error::Client::EnctypeNotPermitted(i32)`.
- Without the flag, behaviour is unchanged, so SHA2 request lists keep working on the implicit default.

Serde (`31e5910`):

- `permitted_enctypes_explicit` round-trips through serde (`serde(default)`), so a deserialized `LibDefaults` keeps enforcing the operator's allowlist. JSON without the field deserializes as `false`.
- The field doc tells programmatic users (struct literal or `Default`) to set the flag together with `permitted_enctypes`/`permitted_enctype_ids` when they want the allowlist enforced.

Reject, never silently narrow (`7c2c297`):

- `Config::parse` fails when an explicit `default_tkt_enctypes` or `default_tgs_enctypes` names an enctype outside an explicit `permitted_enctypes`. The new `rskrb5_ng::error::Config::EnctypeNotPermitted { key, enctype }` names both, for example `[libdefaults] default_tkt_enctypes lists aes128-cts-hmac-sha1-96, which permitted_enctypes does not permit`.
- Repeated `[libdefaults]` sections are allowed, so the explicitness state spans the whole parse (a private parse-state struct, no new public field). The check runs once, on the final effective values after the last section:
  - a request list in one section is still checked against a `permitted_enctypes` line in a later one;
  - a later section can repair an earlier conflict.
- Request lists that nobody configured (the seeded defaults) aren't rejected. `from_libdefaults` keeps narrowing them to the allowlist, as its doc comment now says. Nobody asked for those entries, so narrowing them misleads no one.

## Tests

`tests/client/login_preauth.rs`:

- `initial_as_rep_outside_requested_enctypes_is_rejected`: password consumer, request `[18]`, AES128 (17) AS-REP, `EnctypeNotRequested(17)` after one transport call.
- `keytab_initial_as_rep_outside_requested_enctypes_is_rejected`: the keytab twin.

`tests/client/as_exchange.rs`:

- `process_as_rep_rejects_session_key_outside_requested_enctypes`.
- `as_req_etypes_are_intersected_with_permitted_enctypes`: decodes the encoded AS-REQ and asserts `req_body.etype == [18]`.
- `as_req_with_disjoint_permitted_enctypes_fails_closed`: programmatic construction with disjoint lists yields `EmptyEtypes`.
- `sha2_request_list_survives_the_implicit_permitted_set` and `config_with_sha2_tkt_enctypes_and_no_permitted_line_keeps_the_request_list` (controls: no explicit allowlist, SHA2 requests unchanged).
- `explicit_permitted_enctypes_reject_an_explicit_sha2_request_list`: an explicit SHA2 request list with an explicit AES256-only allowlist is a parse error naming `aes128-cts-hmac-sha256-128`.

`tests/client/tgs_exchange.rs`:

- `process_tgs_rep_rejects_session_key_outside_requested_enctypes`.
- `tgs_req_etypes_are_intersected_with_permitted_enctypes`: decodes the encoded TGS-REQ.
- `exchange_as_req_with_config_rejects_session_key_outside_permitted_enctypes` and `exchange_tgs_req_with_config_rejects_session_key_outside_permitted_enctypes`.

`tests/config.rs`:

- `permitted_enctypes_explicit_survives_a_serde_round_trip`, `implicit_permitted_enctypes_round_trip_stays_implicit` and `libdefaults_json_without_the_explicit_field_deserializes_as_implicit`.
- `explicit_tkt_enctypes_outside_permitted_fail_parsing_naming_the_enctype` and `explicit_tgs_enctypes_outside_permitted_fail_parsing_naming_the_enctype`.
- `implicit_default_enctypes_are_filtered_to_permitted`: the seeded request list parses and encodes as `[18]`.
- `explicit_tkt_list_in_an_earlier_libdefaults_section_is_still_validated` and `a_later_section_can_repair_an_earlier_conflict`, both of which also check the encoded AS-REQ list.

Fail-before evidence. Each mutation was applied to the branch tip on its own and then reverted:

| Mutation | Tests that fail |
|---|---|
| `enforce_requested_enctypes` always returns `Ok(())` | `process_as_rep_rejects_session_key_outside_requested_enctypes`, `initial_as_rep_outside_requested_enctypes_is_rejected`, `keytab_initial_as_rep_outside_requested_enctypes_is_rejected`, `process_tgs_rep_rejects_session_key_outside_requested_enctypes` |
| `ensure_permitted_enctype` always returns `Ok(())` and both `from_libdefaults` intersections are skipped | `as_req_etypes_are_intersected_with_permitted_enctypes`, `as_req_with_disjoint_permitted_enctypes_fails_closed`, `tgs_req_etypes_are_intersected_with_permitted_enctypes`, `exchange_as_req_with_config_rejects_session_key_outside_permitted_enctypes`, `exchange_tgs_req_with_config_rejects_session_key_outside_permitted_enctypes` |
| `permitted_enctypes_explicit` back to `serde(skip)` | `permitted_enctypes_explicit_survives_a_serde_round_trip` (the decoded flag is `false`) |
| Parse-time rejection removed | `explicit_tkt_enctypes_outside_permitted_fail_parsing_naming_the_enctype`, `explicit_tgs_enctypes_outside_permitted_fail_parsing_naming_the_enctype`, `explicit_tkt_list_in_an_earlier_libdefaults_section_is_still_validated`, `explicit_permitted_enctypes_reject_an_explicit_sha2_request_list` |
| Rejection run after each `[libdefaults]` section instead of once at the end | `a_later_section_can_repair_an_earlier_conflict` (fails with `EnctypeNotPermitted { key: "default_tkt_enctypes", enctype: "aes128-cts-hmac-sha1-96" }`) |

## Verification

All runs used stable Rust 1.99.1 on the branch tip.

- `cargo test --all-features --test config --test client`: ok.
- `cargo test --all-features --no-fail-fast`: 33 test targets ok, 0 failed.
- `cargo fmt --all -- --check`: clean.
- `cargo clippy --all-targets --all-features -- -D warnings -A clippy::chunks_exact_to_as_chunks`: the only diagnostics are the 3 `clippy::byte_char_slices` errors in `tests/kadmin.rs` that already fail on `main`. Clippy stops at that test crate, so a second run with `-A clippy::byte_char_slices` lints every target and is clean. CI on `main` stays red on `clippy::chunks_exact_to_as_chunks` and `clippy::byte_char_slices` until PR #15 lands. This change adds no diagnostic.

## Compatibility

Breaking API changes (none of these types is `#[non_exhaustive]`):

- `rskrb5_ng::error::Client` gains `EnctypeNotRequested(i32)` and `EnctypeNotPermitted(i32)`.
- `rskrb5_ng::error::Config` gains `EnctypeNotPermitted { key: &'static str, enctype: String }`.
- `LibDefaults` gains the public field `permitted_enctypes_explicit: bool`. Struct literals without `..Default::default()` need it.

Behaviour changes:

- A KDC reply or session key in an enctype the request didn't list is rejected. Compliant KDCs answer within the request list, so they're unaffected. This diverges from gokrb5, which accepts such replies.
- An explicit `permitted_enctypes` now narrows the seeded request lists and constrains the session key on the config-driven exchanges.
- A config whose explicit request list names an enctype outside its explicit `permitted_enctypes` no longer loads. Before, the conflict was silently ignored (and with only the allowlist part of this PR applied, it would have been silently narrowed). The error names the key and the enctype, so the fix is a one-line config edit.
- Configs without an explicit `permitted_enctypes` behave as before.

Serialized form: `LibDefaults` JSON gains `permitted_enctypes_explicit`. Older JSON without it still deserializes (as `false`).

## Series and merge order

- `src/client.rs`: this PR, then `fix/client-renewal-series`. They merge cleanly in either order (checked with `git merge-tree` on `6f4abc9`); this PR goes first because the renewal series exercises the exchange paths it changes.
- `src/config.rs`, `tests/config.rs`: this PR, then `fix/domain-realm-normalization`. Both append tests at the end of `tests/config.rs` and conflict textually there. I'll rebase `fix/domain-realm-normalization` once this lands.
- `src/client/transport.rs` is also touched by PR #19. The two merge cleanly.

## Notes

- #4 (the public enctype name fields aren't re-derived into the ID fields after assignment) isn't fixed here. This PR adds a third field in the same spirit: programmatic users who want the allowlist enforced must set `permitted_enctypes_explicit` next to `permitted_enctypes` and `permitted_enctype_ids`, and the field doc says so. A proper fix for #4 (setters, or deriving the IDs at use) would cover the flag too.
- The ticket `enc_part` etype isn't checked against the allowlist. The session key is what the client uses, and the ticket is opaque to it.
- The optional "require ENC-PA-REP when PA-REQ-ENC-PA-REP was sent" hardening (RFC 6806) is left out. It needs a compatibility decision of its own.
