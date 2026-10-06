# Client: bind the initial AS-REP reply key and session key to the requested enctypes

- Severity: medium (likelihood low / impact medium / confidence medium) — fingerprint `rskrb5/client/kdc-reply-requested-enctype-binding`
- Audit: run-2 findings.json record (`verdict: confirmed`) + `agents/vfy-rskrb5-client-kdc-reply-re/artifacts/vfy-enctype-r4:180-189` and `tools/prior-evidence/run-1-consolidated-probes-a42705.log:264`
- Status: planned; not implemented in the fork; no upstream PR yet

## Problem

When the first AS-REQ is answered directly with an AS-REP (a no-preauth account,
or a caller that enabled `assume_preauthentication`), the client derives the
reply key from the reply's own `enc_part.etype` — and, for the keytab consumer,
from the reply's `kvno`/`etype` — without intersecting `AsReqOptions.etypes`, and
`process_as_rep` imports the returned session key with no enctype-policy check at
all. A reply encrypted in an enctype the caller never requested is therefore
accepted; the run-2 probe reproduced RC4-HMAC (23) replies against requests
listing only AES-SHA1 (18), for both the password and keytab consumers, and
against the library default list `[20,19,18,17]`.

## Root cause (verified against upstream 6f4abc9)

- `src/client.rs:2216-2231` — `login_as_service_with_password`: untrusted KDC bytes that decode as an AS-REP are handed to `password_initial_as_rep_session` (`:2230`) instead of a preauth challenge. The keytab twin is at `src/client.rs:2255-2269`.
- `src/client.rs:3184` — `password_initial_as_rep_session`: `as_rep_reply_key_info(response)` yields `enc_part.etype`, which becomes the sole input to `derive_password_reply_key` (`:3196`); the request's etype list is never consulted.
- `src/client.rs:3277` — `keytab_initial_as_rep_session`: `as_rep_reply_key_info(response)` selects the keytab entry through `select_keytab_reply_key_for_etype` (`:3291`); the requested list is never consulted.
- `src/client.rs:3321` — `as_rep_reply_key_info(response)` reads `enc_part.etype`/`kvno` straight from the untrusted reply.
- `src/client.rs:2280` — `process_as_rep` imports the decrypted session key verbatim at `src/client.rs:2331` — `session_key: encryption_key_from_rasn(&enc_part.key),` — with no comparison against the request list. `process_tgs_rep_inner` (`src/client.rs:2423`) does the same at `:2477`.
- `src/client.rs:2357-2358` — the RFC 6806 check returns early unless the request carries `PA_REQ_ENC_PA_REP` and the reply sets `TICKET_FLAG_ENC_PA_REP`, so it is best-effort and can be stripped in transit.
- Contrast `select_preauth_key_info` (`src/client.rs:2523`), which intersects the KDC hints with `requested_etypes`; the `KeyEtypeMismatch` guard is vacuous on this path because the reply key was derived from the same reply etype.
- `src/client.rs:47` — `const DEFAULT_TKT_ENCTYPES: &[i32] = &[20, 19, 18, 17];` — the default requested list excludes RC4-HMAC (23). `src/client/options.rs:22` documents `etypes` as "Requested response encryption types"; `src/messages.rs:53` defines `PA-REQ-ENC-PA-REP`.

Fork deltas are line-number only (+163 in this region): `password_initial_as_rep_session` is `src/client.rs:3347`, `keytab_initial_as_rep_session` `:3440`, `as_rep_reply_key_info` `:3484`, `process_as_rep` `:2443` with the import at `:2494`, `process_tgs_rep_inner` `:2586` with the import at `:2640`, `login_as_service_with_password` `:2379`, `login_as_service_with_keytab` `:2418`. The async transport twins are `src/client/transport.rs:767,857` upstream and `:897,994` in the fork.

## Evidence (from the audit)

- `agents/vfy-rskrb5-client-kdc-reply-re/artifacts/vfy-enctype-r4:186` — password consumer: the wire AS-REQ carried etypes `[18]`, the mock KDC answered RC4-HMAC (23), and `login_as_service_with_password` returned `Ok` in one transport call with `session_key.etype=23`.
- `.../vfy-enctype-r4:184` — keytab consumer: the same out-of-list reply was accepted through `login_as_service_with_keytab` (keytab with etype-23 kvno-4 and etype-18 kvno-4 entries), `session_key.etype=23`.
- `.../vfy-enctype-r4:180` — defaults: with `AsReqOptions::new` the wire request carried `[20,19,18,17]` (no 23) and the RC4 reply was still accepted.
- `.../vfy-enctype-r4:182,189` — control: an ENC-PA-REP reply whose `PA-REQ-ENC-PA-REP` checksum covers different request bytes is rejected with `Error::FastNegotiationChecksumMismatch`; `test result: ok. 4 passed; 0 failed`.
- `tools/prior-evidence/run-1-consolidated-probes-a42705.log:264` — `requested=18 accepted=23 password_and_keytab; modern_integrity_control=rejected`.
- Payloads: AS-REQ `req-body` etype rewritten to `[23]` with `PA-REQ-ENC-PA-REP` removed; AS-REP with `enc_part.etype=23`, `kvno=4`, ENC-PA-REP flag clear, `EncASRepPart` carrying an etype-23 session key.

## Proposed fix

1. In `password_initial_as_rep_session` and `keytab_initial_as_rep_session`,
   reject an AS-REP whose `enc_part.etype` is not in the originating request's
   etype list (`request.message.0.req_body.etype`) before deriving or selecting
   the reply key.
2. In `process_as_rep` and `process_tgs_rep_inner`, reject an imported session
   key whose etype is not in the request's etype list; on the TGS path constrain
   only the new session key (the TGS-REP encryption key legitimately uses the TGT
   session-key enctype).
3. Optionally let callers that advertised `PA-REQ-ENC-PA-REP` fail closed when
   the reply does not echo ENC-PA-REP, behind an explicit compatibility opt-out.
   Prefer a dedicated `Error` variant over reusing `Error::UnsupportedEtype`.

```rust
// password_initial_as_rep_session / keytab_initial_as_rep_session: bind to the request's list.
let Some((etype, kvno)) = as_rep_reply_key_info(response) else {
    return Ok(None);
};
if !request.message.0.req_body.etype.contains(&etype) {
    return Err(Error::UnsupportedEtype(etype)); // prefer a dedicated EnctypeNotRequested variant
}

// process_as_rep / process_tgs_rep_inner: bind the imported session key.
let session_key = encryption_key_from_rasn(&enc_part.key);
if !request.message.0.req_body.etype.contains(&session_key.etype) {
    return Err(Error::UnsupportedEtype(session_key.etype));
}
```

## Regression tests

- `tests/client/login_preauth.rs::initial_as_rep_outside_requested_enctypes_is_rejected` — with `etypes=[18]` and a mock KDC answering the first request with an RC4-HMAC (23) AS-REP, `login_tgt_with_password` returns an error in one transport call (fails before the change). Reuse the existing `AssumedPreauthTransport`/`PreauthTransport` mocks and `keytab_with_reply_key`.
- `tests/client/login_preauth.rs::keytab_initial_as_rep_outside_requested_enctypes_is_rejected` — the keytab consumer with etype-23 and etype-18 entries.
- `tests/client/login_preauth.rs::default_enctypes_reject_rc4_initial_as_rep` — defaults `[20,19,18,17]` with an RC4 reply.
- `tests/client/as_exchange.rs::process_as_rep_rejects_session_key_outside_requested_enctypes` — unit form of the `process_as_rep` guard, alongside the existing `process_as_rep_validates_pa_req_enc_pa_rep_checksum` (`tests/client/as_exchange.rs:224`) and its reject control.
- Keep the RFC 6806 control asserting `Error::FastNegotiationChecksumMismatch` for a foreign-request checksum.

## Verification

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --test client
```

## Compatibility / notes

- Breaking change for a KDC (or an on-path attacker) that answers outside the
  requested list; correct KDCs that answer within
  `request.message.0.req_body.etype` are unaffected.
  Note the divergence from gokrb5 parity and add a release-note entry.
- Overlaps with `medium-permitted-enctypes-unconsumed.md`: both add a session-key
  acceptance check in `process_as_rep`/`process_tgs_rep_inner`. This plan binds
  to `request.message.0.req_body.etype`; that plan binds to
  `config.libdefaults.permitted_enctype_ids`. Keep them as two distinct checks
  (ideally in one shared helper) and land together to avoid two divergent
  error-branch styles on the same lines.
- Neither in-flight HIGH fix touches `src/client.rs` or
  `src/client/options.rs` (both are in `src/service.rs`).

## Upstream route

- Fork-only first, then a PR against `clelange/rskrb5`. Independent entry point
  but sequence with the permitted-enctypes plan (shared acceptance site).

## Risks / open questions

- Confidence is medium: the acceptance/import behaviour and the conditional RFC
  6806 gate were reproduced deterministically in the sandbox, but the deployment
  half (on-path attacker, direct-AS-REP account, weaker enctype enabled at a real
  KDC) could not be exercised offline and remains a stated condition.
- The TGS variant (`process_tgs_rep_inner`, `src/client.rs:2423`) is a KDC policy
  violation rather than an on-path vector, because the TGS request list is
  authenticated by the TGT AP-REQ; decide whether to constrain it in the same
  change or document it as defence in depth.
- Requiring `verified.is_some()`-style ENC-PA-REP enforcement is optional here;
  confirm the chosen fail-closed/opt-out shape does not break the existing
  `fast_negotiation = false` path (`tests/client/login_preauth.rs`) before
  enabling it by default.