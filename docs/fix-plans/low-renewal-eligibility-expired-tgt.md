# Expired-but-"renewable" cached TGT keeps the automatic paths on TGS RENEW
- Severity: low — likelihood medium, impact low, confidence not scored in the record (verdict: confirmed, independently reproduced) — fingerprint `rskrb5/client/renewal-eligibility-expired-ticket`
- Audit: run-2 `findings.json` record (verdict `confirmed`) + `agents/vfy-rskrb5-client-renewal-elig/artifacts/vfy-renewal-probe2` (promoted sandbox log, SANDBOX_EXIT=0)
- Status: planned; not implemented in the fork; no upstream PR yet

## Problem
`session_renewable_at` tests only `renew_till`, ignoring the ticket validity window and the
session's ticket flags, so an expired TGT with a future `renew_till` is classified as
refreshable. `affirm_login` and the refresh path through `ensure_tgt` then call `renew_tgt()`
(TGS RENEW); RFC 4120 §2.3 requires a conforming KDC to refuse renewal once the ticket
expired, and §3.3 states expired tickets are not accepted by the TGS, so the renewal error is
returned and the credential-backed AS `login()` is never attempted — even though a password
or keytab is still configured. Every caller-facing automatic path
(`affirm_login`, `refresh_tgt_if_needed`, `get_service_ticket`, and the auto-renewal loop)
keeps failing until an explicit `login()` is called.

## Root cause (verified against upstream 6f4abc9)
- `src/client.rs:3676-3680` — `session_renewable_at` is `session.renew_till.is_some_and(|renew_till| now < renew_till)`; `end_time` and `ticket_flags` are never consulted (session fields at `src/client.rs:202-216`).
- `src/client.rs:1097-1099` — `affirm_login`: `if session_renewable_at(&tgt, now) { return self.renew_tgt().await; }` — the renewal `Err` is returned to the caller and the `self.login().await` at `:1102` is unreachable in this state.
- `src/client.rs:1349-1351` — `ensure_tgt`: `if session_renewable_at(&tgt, now) { return Ok(self.renew_tgt().await?.clone()); }` — the `?` propagates the renewal error before the credential-aware fallbacks at `:1352-1354` and the credential-backed `login()` at `:1360`.
- `src/client.rs:1106-1143` — `login()` takes the stored password/keytab and performs the AS exchange; it is the recovery path the automatic branches skip.
- `src/client.rs:3636-3639` + `src/client.rs:1008-1030` — `session_usable_at` is `session_valid_at || session_renewable_at`, and `prune_unusable_sessions_at` retains the primary TGT while usable, so the expired-renewable session survives and every later automatic call repeats the doomed renewal.
- `src/client.rs:1414-1431` — calibration: `renew_cached_tgt_session_for_realm` already treats renewal as best-effort (`let Ok(renewed) = ... else { return Ok(None) };`), so propagating the renewal error in the primary/refresh paths is inconsistent with the fork's own pattern.
- `src/client.rs:1204-1215` — calibration: the cached-service-ticket path renews an expired renewable ticket only best-effort (`if session_renewable_at(...) && let Ok(renewed) = ...`) and otherwise falls through to a full TGS acquisition; the TGT paths have no equivalent fallback.

Line drift: in the fork the same functions sit at `affirm_login` `1130`, `refresh_tgt_if_needed` `1227`, `get_service_ticket` `1233`, `ensure_tgt` `1382`, `renew_cached_tgt_session_for_realm` `1453`, `login` `1145`, `prune_unusable_sessions_at` `1047`, `session_renewable_at` `3840`; bodies are byte-identical to base (fork `src/client.rs` is +164 lines earlier in the file).

## Evidence (from the audit)
- `agents/vfy-rskrb5-client-renewal-elig/artifacts/vfy-renewal-probe2` (`execution.observed_result`) — `VFY_RENEWABLE affirm_login=Err("KDC returned error code 32") refresh_tgt_if_needed=Err("KDC returned error code 32") tgs_requests=2 as_requests=0 other=0`; control `VFY_NONRENEWABLE ... tgs_requests=0 as_requests=1`; `VFY_AUTO_RENEWAL renew_requests_in_700ms=13 as_requests=0`. (Mock loopback TGS answered each TGS-REQ with KRB-ERROR 32, `KRB_AP_ERR_TKT_EXPIRED`.)
- `run-2/findings.json` (`renewal-eligibility-expired-ticket`, `evidence`) — `affirm_login` returns `self.renew_tgt().await` directly; `ensure_tgt` propagates with `?`; `session_renewable_at` is `renew_till`-only.
- `src/client.rs:1464` (calibration) — `renew_cached_tgt_session_for_realm` already treats renewal as best-effort, inconsistent with the primary/refresh paths.
- `tests/client/session_cache.rs:856` — `tokio_client_renews_expired_renewable_cached_service_ticket` proves the service-ticket fallback; there is no equivalent TGT-path test.

## Proposed fix
1. In `affirm_login` (`src/client.rs:1091`) and `ensure_tgt` (`src/client.rs:1343`), keep the renewal attempt but never let its failure suppress an available long-term credential: on `Err`, fall through to the credential-backed contract when `self.credentials.is_some()` (`affirm_login` falls to `self.login()`; `ensure_tgt` falls to its `login()` branch at `:1360`).
2. When the ticket is already outside its validity window (`!session_valid_at`) and a credential is configured, prefer the AS exchange over TGS RENEW, so the post-expiry renewal is not the only path.
3. Keep `session_renewable_at`'s retention semantics for cache-only clients (`src/client.rs:3676` unchanged), so a cache-only client can still renew inside the KDC clockskew grace period.
4. Leave `renew_tgt()` itself unchanged; only the automatic-caller fallbacks change.

```rust
// affirm_login / ensure_tgt: keep the renewal attempt, but never let its
// failure suppress an available long-term credential (ensure_tgt returns
// Ok(session.clone()) where affirm_login returns Ok(session)).
let has_credentials = self.credentials.is_some();
let expired = !session_valid_at(&tgt, now);
if session_renewable_at(&tgt, now) && !(expired && has_credentials) {
    match self.renew_tgt().await {
        Ok(session) => return Ok(session),
        Err(error) => {
            if !has_credentials {
                return Err(error);
            }
            // fall through to the credential-backed login() below
        }
    }
}
```

## Regression tests
- `tests/client/session_cache.rs::tokio_client_affirm_login_falls_back_to_as_for_expired_renewable_tgt` (new, runs under `--test client`) — bind the loopback TCP mock KDC (`tests/client.rs:1038-1089` helpers), build `TokioClient::from_tgt_session(...)` with an expired `end_time` and future `renew_till`, `.with_password_credential(...)`, answer each TGS-REQ with a rasn-encoded KRB-ERROR code 32, and assert `affirm_login()` succeeds via an AS-REQ (counters: `as_requests >= 1`, `tgs_requests <= 1`).
- Same fixture for `refresh_tgt_if_needed()` and `get_service_ticket(...)`, asserting all three paths reach the AS exchange instead of returning the renewal error.
- `tests/client/session_cache.rs::tokio_client_auto_renewal_uses_as_when_renewal_refused` — spawn auto-renewal against the mock refusing renewals and assert at least one AS-REQ appears (cf. the audit's `renew_requests_in_700ms=13 as_requests=0` baseline).
- Keep a cache-only control test: with `credentials == None` the renewal `Err` must still be returned (no AS login possible), preserving `session_renewable_at` retention semantics.

## Verification
```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --test client
```

## Compatibility / notes
- No public API change. Behavior change: automatic paths now recover via `login()` when a credential exists and the cached TGT cannot be renewed; cache-only clients keep the current `Err`.
- Recovery is already possible via an explicit `login()`, so this only removes the manual-workaround requirement.
- The two in-flight HIGH fixes are in `src/service.rs` and do not touch this code. This plan shares `src/client.rs` with `medium-renewal-window-auth-time.md` and `low-auto-renewal-busy-loop.md`; the eligibility fallback changes `affirm_login`/`ensure_tgt`, which the busy-loop plan's `refresh_tgt_if_needed` path traverses, so land them together or sequence eligibility first.

## Upstream route
- PR against `clelange/rskrb5` (base `6f4abc9`) is viable and self-contained; nothing depends on fork-only code. It can be split from the band/busy-loop plans since it only touches the `affirm_login`/`ensure_tgt` fallback order.

## Risks / open questions
- Requires a KDC that refuses the post-expiry renewal beyond its clockskew grace period (RFC 4120 §2.3; MIT applies a grace period per `kinit(1)`), so the triggered window is a ticket expired beyond that grace period — the probe used ten minutes past expiry. Inside the grace period the renewal may still succeed, which is acceptable.
- The `!(expired && has_credentials)` preference for the AS exchange changes KDC traffic shape for expired renewable TGTs; if any deployment relies on the renewal attempt first, the `Err`-fallback alone (step 1) is the strictly conservative subset and can ship alone.
- Whether the expired-renewable session should also be pruned once a credential exists (rather than retained by `session_usable_at`) is left open; retention is needed for the cache-only grace-period case, so the fallback must handle it rather than the prune.
