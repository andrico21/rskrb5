# Requested mutual authentication is not enforced by HTTP completion classification
- Severity: medium — likelihood medium, impact medium, confidence not scored in the record (verdict: confirmed, independently reproduced) — fingerprint `src/http.rs:classify_negotiate_challenge:mutual-request-not-enforced`
- Audit: run-2 `findings.json` record (verdict `confirmed`) + `tools/prior-evidence/dep-repro-mutual-classify3-e8b575.log:180-186` and `agents/vfy-src-http-rs-classify-negot/artifacts/repro-mutual-classify3.log:180-186`
- Status: planned; not implemented in the fork; no upstream PR yet

## Problem
When the initiator asks for mutual authentication, `classify_negotiate_challenge` still
reports an accept-completed NegTokenResp with no response token as
`ClientNegotiateResponse::Accepted { ap_rep: None }`. It never consults the mutual-required
AP option that `init_sec_context_with_confounder` serialized into the AP-REQ and that
`InitiatorContext` retains, and the async/blocking 401-retry wrappers record that
classification while returning `Ok` for every outcome. A responder holding no Kerberos key
material (on-path attacker or hostile peer) is therefore classified as having completed a
requested mutual-authentication exchange, so a caller that treats `Accepted` (or the README
`into_response()` pattern) as sufficient can be spoofed.

## Root cause (verified against upstream 6f4abc9)
- `src/http.rs:554-556` — `let Some(response_token) = response.response_token else { return ClientNegotiateResponse::Accepted { ap_rep: None }; };` — the no-response-token path succeeds unconditionally, without consulting the requested AP options.
- `src/spnego.rs:1007` — `pub ap_req: rasn_kerberos::ApReq,` on `InitiatorContext` — the requested mutual-required option is retained but never read on the classification path.
- `src/spnego.rs:1141-1152` — `init_sec_context_with_confounder` writes `options.ap_option_bits` via `.with_ap_option_bits(...)` (`:1149`) and the GSS context flags into the authenticator checksum (`:1150-1152`), so a mutual request is real and caller-selectable (`InitiatorContextOptions` at `:944-950`; `CONTEXT_FLAG_MUTUAL` at `src/spnego.rs:49`).
- `src/ap_req.rs:88-96` — `pub fn ap_options_to_bits(...)` exists but has no production consumer (only `tests/ap_req.rs`), confirming nothing enforces the requested options.
- `src/http.rs:337-342` and `src/http.rs:400-405` — both wrappers call `classify_negotiate_response` and always return `Ok(NegotiateHttpResponse::negotiated(...))`; no classification — including `Accepted { ap_rep: None }`, `Rejected`, `InvalidToken` — surfaces as an authentication failure.
- `src/http.rs:173-175` — `into_response` returns only `self.response`, discarding the classification and context, which is exactly the pattern `README.md:74` documents.
- `src/spnego.rs:1054-1078` — `verify_ap_rep` is the correct control (decrypts under the service-ticket session key and requires the echoed authenticator `ctime`/`cusec`), but it is optional and unreachable from the no-token path.

Line drift: `src/http.rs`, `src/spnego.rs` and `src/ap_req.rs` are byte-identical between base `6f4abc9` and the fork, so every cited line is valid in both trees. (Fork `src/client.rs` line drift is unrelated.)

## Evidence (from the audit)
- `run-2/findings.json` (`classify_negotiate_challenge:mutual-request-not-enforced`) — no-response-token guard `src/http.rs:554` returns `Accepted { ap_rep: None }` at 555; wrappers return `Ok` at 338-342/401-405.
- `agents/vfy-src-http-rs-classify-negot/artifacts/repro-mutual-classify3.log:180-186` — `retained_ap_option_bits=0x20000000 mutual_requested=true` (180), `keyless_classification=Accepted { ap_rep: None }` (182), `explicit_verify_absent=Err(Spnego(MissingMechToken))` (183), a genuine AP-REP classifies `Accepted { ap_rep: Some(...) }` (184), a wrong-key AP-REP classifies `InvalidToken` (185), wrapper `200 OK ... wrapper_negotiation=Some(Accepted { ap_rep: None })` (186).
- `tests/http.rs:304-307` — the existing wrapper test asserts `negotiation == Some(Accepted { ap_rep: None })` for the accept-completed response, i.e. the unproven state is the success path; `tests/http.rs:462-468` asserts the same for the direct classifier with a default (non-mutual) context.
- `README.md:18` — advertises "AP-REP mutual auth" as implemented; `docs/gokrb5-parity.toml:107` claims only AP-REP verification coverage, no mutual-completion enforcement.

## Proposed fix
1. Add the `mutual-required` AP-option constant and, in `classify_negotiate_challenge` (`src/http.rs:518`), fail closed when the retained AP options request mutual but the peer returns no response token (`src/http.rs:554`).
2. Retain the requested GSS mutual signal (`CONTEXT_FLAG_MUTUAL` in `options.context_flags`) on `InitiatorContext`, or thread an explicit mutual-policy argument through `classify_negotiate_response` and both send wrappers, so both request forms are covered.
3. Keep the existing AP-REP verification for present tokens (`src/spnego.rs:1054`), and let wrapper consumers opt into an explicit authentication-failure result instead of silently discarding the classification in `into_response` (`src/http.rs:173`).
4. Update the `README.md:74` example and `docs/gokrb5-parity.toml` evidence text to state the mutual-completion policy.

```rust
/// RFC 4120 AP option `mutual-required`.
const AP_OPTION_MUTUAL_REQUIRED: u32 = 0x2000_0000;

// In classify_negotiate_challenge, replace the unconditional no-token success:
    let Some(response_token) = response.response_token else {
        if crate::ap_req::ap_options_to_bits(&context.ap_req.ap_options) & AP_OPTION_MUTUAL_REQUIRED != 0 {
            return ClientNegotiateResponse::InvalidToken {
                message: "mutual authentication was requested but the peer returned no AP-REP".to_owned(),
            };
        }
        return ClientNegotiateResponse::Accepted { ap_rep: None };
    };
// (plus retaining/consulting the requested GSS mutual flag, e.g. by storing the
// requested InitiatorContextOptions on InitiatorContext and taking an explicit
// mutual policy in classify_negotiate_response / the send wrappers.)
```

## Regression tests
- `tests/http.rs::classify_negotiate_response_rejects_missing_ap_rep_when_mutual_requested` (new) — build an `InitiatorContext` via `spnego::init_sec_context_with_confounder` with `InitiatorContextOptions::new().with_ap_option_bits(0x2000_0000)` (and separately `with_context_flags(..., CONTEXT_FLAG_MUTUAL, ...)`), feed `spnego::accept_completed_header()` (`tests/http.rs:462`), and assert the result is *not* `Accepted`; the same context without the mutual option keeps the existing `Accepted { ap_rep: None }` expectation (`tests/http.rs:465-468`).
- `tests/http.rs::negotiate_http_client_enforces_requested_mutual` — mirror the wrapper test at `tests/http.rs:236-307` with mutual options and assert the unproven completion is surfaced as a failure rather than `200 OK` + `Accepted { ap_rep: None }`.
- Keep the genuine-AP-REP (`Accepted { ap_rep: Some(_) }`) and wrong-key (`InvalidToken`) assertions from the current suite green.

## Verification
```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --test http
cargo test --all-features --test spnego
```

## Compatibility / notes
- Default callers request no mutual (`InitiatorContextOptions::new()` sets `ap_option_bits: 0`, `context_flags: [INTEG, CONF]`), so the default classification is unchanged; only explicit mutual opt-in becomes fail-closed. This is a behavioral change for callers that passed `mutual-required` and relied on `Accepted { ap_rep: None }`.
- If a policy argument is added, it is a public API addition to `classify_negotiate_response` / the send wrappers; keep the current signatures working via a conservative default.
- README/parity text must be updated in the same change (documented claim of mutual auth).
- The two in-flight HIGH fixes are both in `src/service.rs` and do not touch this code; this plan is independent of the three `src/client.rs` plans.

## Upstream route
- PR against `clelange/rskrb5` (base `6f4abc9`) is viable and self-contained. The only friction is the optional API-shape decision (retain flag vs explicit policy argument); implement the fail-closed guard first, then the policy knob, so the security fix ships regardless.

## Risks / open questions
- Servers that legitimately complete mutual auth without echoing an AP-REP are non-conforming (RFC 4120 §3.2.4); the fail-closed change could break interoperability with such peers only when the caller *requested* mutual, which is the intended contract.
- The GSS-flag form (`CONTEXT_FLAG_MUTUAL`) is currently only serialized into the authenticator checksum and is not retained on `InitiatorContext`; covering it requires storing the requested options (or passing a policy), which the audit records as the remaining design choice.
- `into_response` discarding the classification means callers may never observe the new failure unless the policy is exposed; whether to make `into_response` panic/return a `Result` is a public-API decision left open here.
