# http: fail closed when requested mutual authentication is not proven

- Target: `clelange/rskrb5` `main` (`6f4abc9`), branch `fix/mutual-auth-classification`.
- Commits:
  - `8b75cda` http: fail closed on a missing AP-REP when mutual authentication was requested
  - `71cc63b` http: fail the send wrappers closed when requested mutual authentication is not proven

## Problem

A caller can ask for mutual authentication in two ways: the AP option `mutual-required` (`with_ap_option_bits(0x2000_0000)`) or the GSS flag `CONTEXT_FLAG_MUTUAL`. Neither was enforced on the HTTP client side.

1. **Classifier.** `classify_negotiate_challenge` reported an accept-completed `NegTokenResp` without a response token as `ClientNegotiateResponse::Accepted { ap_rep: None }`. It never looked at the mutual request that `init_sec_context_with_confounder` serialized into the AP-REQ, and `InitiatorContext` didn't keep the requested GSS flags at all. A responder with no Kerberos key, on-path or hostile, was classified as having completed a requested mutual exchange.
2. **Send wrappers.** `send_with_negotiate_options` and `send_with_blocking_negotiate_options` returned `Ok` with the final response whenever the sender succeeded, and left the outcome only in `result.negotiation`. The documented `into_response()` pattern drops that classification. A caller who requested mutual authentication and checked only the HTTP status accepted:
   - a `200` without `WWW-Authenticate`;
   - a final non-Negotiate challenge;
   - a completion without an AP-REP;
   - a first response that never challenged at all, so no authenticated retry was even sent.

RFC basis:

- RFC 4120 section 3.2.4: when the client requests mutual authentication, the server answers with a KRB_AP_REP, and the client checks it (decrypting it and comparing the echoed time) before trusting the server.
- RFC 4121 section 4.1.1: `GSS_C_MUTUAL_FLAG` in the checksum's flags requests mutual authentication.
- RFC 4559 section 5: when the server authenticates the client, its final response can carry a `WWW-Authenticate: Negotiate` header with the GSS token. That token is where the AP-REP travels. Without it, the server hasn't proven anything.

## Change

Classifier (`8b75cda`):

- `InitiatorContext` keeps the requested GSS context flags in a new public field, `context_flags`.
- `classify_negotiate_challenge` returns `InvalidToken` for a completion without an AP-REP when either form of mutual request was made. Default contexts request neither and keep `Accepted { ap_rep: None }`. Genuine AP-REPs are verified as before.

Send wrappers (`71cc63b`):

- When the options request mutual authentication in either form, `send_with_negotiate_options` and `send_with_blocking_negotiate_options` return the new `NegotiateHttpError::MutualAuthenticationNotProven`, unless the final response carries an AP-REP that verifies against the initiator context.
- The error keeps the final response (boxed) for diagnostics, and the classification. `negotiation` is `None` when the first response never sent a Negotiate challenge, so no retry happened.
- To carry the response, `NegotiateHttpError<E>` becomes `NegotiateHttpError<E, B>`, where `B` is the response body type.
- Non-mutual calls behave exactly as before. `send_with_negotiate` and `send_with_blocking_negotiate` use default options, which never request mutual authentication; only their error type gains `B`. `classify_negotiate_response` itself is unchanged by the second commit.
- The four `send_*` doc comments, the README wrapper paragraph and the gokrb5 parity evidence text describe the fail-closed contract.

## Tests

In `tests/http.rs`:

- `classify_rejects_missing_ap_rep_when_mutual_requested`: the keyless accept-completed header classifies as `InvalidToken` for both mutual request forms, and the default context stays `Accepted { ap_rep: None }`.
- `negotiate_http_client_classifies_missing_ap_rep_as_failure_when_mutual_requested`: the async wrapper returns `MutualAuthenticationNotProven { negotiation: Some(InvalidToken { .. }) }`.
- `mutual_wrapper_rejects_final_response_without_www_authenticate`: `Some(NoAuthenticateHeader)`, with the `200` response kept in the error.
- `mutual_wrapper_rejects_a_non_negotiate_challenge`: a final `WWW-Authenticate: Basic`, `Some(NoNegotiateChallenge)`.
- `mutual_wrapper_rejects_unchallenged_first_response`: no challenge, so `negotiation` is `None`.
- `blocking_mutual_wrapper_rejects_a_missing_ap_rep`: the blocking wrapper.
- `mutual_wrapper_accepts_a_verified_ap_rep`: `Ok` with `Accepted { ap_rep: Some(_) }` for a genuine AP-REP built from the live `Authorization` header.
- `default_wrapper_still_accepts_a_missing_ap_rep`: `send_with_negotiate` and `send_with_blocking_negotiate` still return `Ok` for a completion without an AP-REP.

Both request forms (`with_ap_option_bits(0x2000_0000)` and `CONTEXT_FLAG_MUTUAL`) are each covered at least once.

Fail-before evidence:

- With both wrapper checks commented out (the variant kept), five tests fail: `negotiate_http_client_classifies_missing_ap_rep_as_failure_when_mutual_requested`, `mutual_wrapper_rejects_final_response_without_www_authenticate`, `mutual_wrapper_rejects_a_non_negotiate_challenge`, `mutual_wrapper_rejects_unchallenged_first_response` and `blocking_mutual_wrapper_rejects_a_missing_ap_rep`. The other 26 tests in `tests/http.rs` pass.
- With the classifier's mutual branch disabled, `classify_rejects_missing_ap_rep_when_mutual_requested` fails, along with the two wrapper tests that assert the `InvalidToken` classification (`negotiate_http_client_classifies_missing_ap_rep_as_failure_when_mutual_requested` and `blocking_mutual_wrapper_rejects_a_missing_ap_rep`).

## Verification

All runs used stable Rust 1.99.1 on the branch tip.

- `cargo test --all-features --test http`: 31 passed.
- `cargo test --all-features --no-fail-fast`: 33 test targets ok, 0 failed.
- `cargo fmt --all -- --check`: clean.
- `cargo clippy --all-targets --all-features -- -D warnings -A clippy::chunks_exact_to_as_chunks`: the only diagnostics are the 3 `clippy::byte_char_slices` errors in `tests/kadmin.rs` that already fail on `main`. Clippy stops at that test crate, so a second run with `-A clippy::byte_char_slices` lints every target and is clean. Library-only clippy with `--no-default-features --features http` and with `--no-default-features --features tokio` (same `-A clippy::chunks_exact_to_as_chunks` allowance) is clean too. CI on `main` stays red on `clippy::chunks_exact_to_as_chunks` and `clippy::byte_char_slices` until PR #15 lands. This change adds no diagnostic.

## Compatibility

Breaking API changes (none of these types is `#[non_exhaustive]`):

- `NegotiateHttpError<E>` becomes `NegotiateHttpError<E, B>` and gains the variant `MutualAuthenticationNotProven { negotiation: Option<ClientNegotiateResponse>, response: Box<Response<B>> }`. Code that names the type needs the body type, and exhaustive matches need a new arm.
- `InitiatorContext` gains the public field `context_flags: Vec<u32>`. Struct literals need it.

Behaviour changes:

- With mutual authentication requested, the classifier reports a completion without an AP-REP as `InvalidToken`, and the send wrappers return an error instead of an unproven `Ok`.
- Without a mutual request, nothing changes.
- A peer that completes a requested mutual exchange without sending an AP-REP doesn't conform to RFC 4120 section 3.2.4, and it now fails. That's the intended contract.

## Series and merge order

- `src/http.rs`, `tests/http.rs`: `fix/config-clockskew-handoff`, then this PR. They merge cleanly in either order (checked with `git merge-tree` on `6f4abc9`). The clockskew change is smaller and touches only the `NegotiateLayer` constructors, so merging it first keeps this rework reviewable on its own.
- No other open PR touches `src/spnego.rs`, `README.md` or `docs/gokrb5-parity.toml`.

## Notes

- `NegotiateHttpResponse` and `into_response()` are unchanged. A mutual caller now gets the failure as an `Err`, so dropping the classification in `into_response()` no longer hides it.
