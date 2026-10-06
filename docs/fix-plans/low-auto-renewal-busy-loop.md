# Cache-only nonrenewable TGTs busy-loop auto-renewal with zero delay and no progress
- Severity: low — likelihood medium, impact low, confidence not scored in the record (verdict: confirmed, independently reproduced) — fingerprint `rskrb5/client/auto-renewal-success-without-progress`
- Audit: run-2 `findings.json` record (verdict `confirmed`) + `agents/vfy-rskrb5-client-auto-renewal/artifacts/verify-autorenewal3:177-183` and `agents/vfy-rskrb5-client-auto-renewal/artifacts/verify-autorenewal2:174-181`
- Status: planned; not implemented in the fork; no upstream PR yet

## Problem
For a client with no long-term credentials (`from_ccache` / `from_tgt_session`) whose cached
primary TGT is still time-valid but inside the refresh band and not currently renewable,
`ensure_tgt` returns the byte-identical session as a success. The refresh loop treats that
"due but not refreshable" outcome as a completed refresh: the pre-refresh delay is
`Duration::ZERO` while due, the sleep is skipped, and the caller's `retry_delay` is applied
only after an `Err`. The task therefore re-enters immediately and spins CPU-busy at roughly
a full core for the rest of the refresh band (measured 157 CPU ticks vs 143 for a dedicated
busy thread in 1.5 s; zero for the not-due control), degrading co-scheduled work in the
embedding service. `abort()`/`drop` (and clearing the TGT) still stop it at the next yield.

## Root cause (verified against upstream 6f4abc9)
- `src/client.rs:797-804` — the loop computes `session_refresh_delay_at(...)` for the TGT and `.unwrap_or(Duration::ZERO)`.
- `src/client.rs:805-807` — `if !delay.is_zero() { tokio::time::sleep(delay).await; }` — a zero delay means no sleep, and the only other awaits are two uncontended mutex locks and `refresh_tgt_if_needed` (which returns `Ready` in this state).
- `src/client.rs:813-816` — `retry_delay` is slept only in the `is_err()` branch, so the successful no-progress path has no pacing at all.
- `src/client.rs:3659-3662` — `session_refresh_delay_at` returns `Duration::ZERO` whenever `session_refresh_due_at` holds (due for any session with `remaining <= (end_time - auth_time)/6` or expired).
- `src/client.rs:1349-1351` and `src/client.rs:1352-1354` — a due, non-renewable cached TGT falls past the renewable branch to `if session_valid_at(&tgt, now) && self.credentials.is_none() { return Ok(tgt); }`, i.e. success with the unchanged session and no progress signal.
- `src/client.rs:3676-3680` — `session_renewable_at` tests only `renew_till`, so a TGT with absent/passed `renew_till` can never make progress.
- `src/client.rs:593-595` / `src/client.rs:647-650` — `from_ccache` and `from_tgt_session` construct the client with `credentials = None`.
- `src/client.rs:3581-3582` — `ccache_credential_session` maps `renew_till == 0` to `None`, so MIT-style nonrenewable ccaches load as nonrenewable and can reach the spin state.

Line drift: in the fork the same functions sit at `829` (loop), `1382`, `3805`, `3823`, `3840`, `632`, `686`, `3726`; bodies are byte-identical to base (fork `src/client.rs` is +164 lines earlier in the file). The `TokioClientAutoRenewal` handle is at `src/client.rs:410`, `abort` at `:417`, `Drop` at `:428` in base (fork `:456`/`:467`).

## Evidence (from the audit)
- `agents/vfy-rskrb5-client-auto-renewal/artifacts/verify-autorenewal3:179` — `ref_busy_thread_ticks_1500ms=143 due_proc_ticks_1500ms=157 control_proc_ticks_1500ms=0 after_abort_proc_ticks_500ms=0 finished_after_abort=true unchanged_after_1500ms=true still_due=true`.
- `agents/vfy-rskrb5-client-auto-renewal/artifacts/verify-autorenewal2:177` — `due_cpu_in_1500ms=1.45 cpu_in_500ms_after_abort=0.00 finished_after_abort=true` in an earlier independent run.
- `run-2/findings.json` (`auto-renewal-success-without-progress`, `execution.observed_result`) — `V2_C` shows `due_with_6h_old_auth_time=true` and `due_with_auth_time_equal_start=false`, i.e. the state also depends on the `auth_time`-based band.
- `tests/client.rs:371-382` (base) — `current_tgt_session` always queues a future `renew_till` and pins `start_time = auth_time`, so no existing test builds a due, nonrenewable, cache-only TGT.
- `tests/client/session_cache.rs:597` — `tokio_client_auto_renewal_handle_aborts` uses a fresh ticket and asserts nothing about pacing or progress.

## Proposed fix
1. In `spawn_auto_renewal_with_retry` (`src/client.rs:790`), snapshot the cached TGT before the refresh and compare `(ticket, session_key)` after; if the refresh errored *or* left the TGT unchanged, pace with `retry_delay` before iterating.
2. Keep the existing exits unchanged: the `credentials.is_none() && tgt.is_none()` early return (`:810-812`) and the error `retry_delay` (`:813-816`).
3. Leave `session_refresh_delay_at` semantics intact; the band is corrected by the separate `medium-renewal-window-auth-time.md` plan, but this pacing fix must hold independently of it.

```rust
// in spawn_auto_renewal_with_retry, replacing the refresh/retry tail:
let before = client
    .tgt
    .as_ref()
    .map(|tgt| (tgt.ticket.clone(), tgt.session_key.clone()));
let refreshed = client.refresh_tgt_if_needed().await.map(|_| ());
let after = client
    .tgt
    .as_ref()
    .map(|tgt| (tgt.ticket.clone(), tgt.session_key.clone()));
if refreshed.is_err() || after == before {
    // due but not refreshable (or a genuine error): pace instead of spinning
    drop(client);
    tokio::time::sleep(retry_delay).await;
}
```

## Regression tests
- `tests/client/session_cache.rs::tokio_client_auto_renewal_paces_cache_only_nonrenewable_tgt` (new, runs under `--test client`) — build a session with `start_time` inside the band and `renew_till = None` (parameterize `current_tgt_session` at `tests/client.rs:362`, which currently always sets `renew_till`), pass it to `from_tgt_session`/`from_ccache` (no credentials), `spawn_auto_renewal_with_retry` a `retry_delay` of e.g. 50 ms, and assert the task does not consume a core: compare process CPU ticks over a matched window against a not-due control, or assert measured CPU stays near zero.
- `tests/client/session_cache.rs::tokio_client_auto_renewal_handle_aborts` (`:597`) — keep as the liveness anchor; add an assertion that a due nonrenewable cache-only TGT still lets the task be aborted at the next yield.
- Fixture need: a cache-only due nonrenewable TGT; reuse `sample_tgt_session` and the ccache import path rather than the current always-renewable `current_tgt_session`.

## Verification
```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --test client
```

## Compatibility / notes
- No public API change; only the internal loop gains pace in a previously unpaced path. A caller-supplied `retry_delay` (default 60 s from `spawn_auto_renewal`) now also governs the no-progress case, so a due-but-nonrenewable cache-only TGT is retried at `retry_delay` cadence instead of per-iteration.
- Consider (optional) sleeping until `end_time` when the TGT is nonrenewable instead of `retry_delay`; the audit's strategy allows either bound, and `retry_delay` is the minimal change.
- The two in-flight HIGH fixes are in `src/service.rs` and do not touch this code. This plan shares `src/client.rs` with `medium-renewal-window-auth-time.md` (the band) and `low-renewal-eligibility-expired-tgt.md` (eligibility); coordinate a single client refresh change, since the `session_key` comparison must include the renewed key.

## Upstream route
- PR against `clelange/rskrb5` (base `6f4abc9`) is viable and self-contained; it is the smallest of the three `src/client.rs` refresh fixes and can ship alone even if the band/eligibility plans are deferred.

## Risks / open questions
- The comparison `(ticket, session_key)` treats a renewal that installs an identical session key + ticket as no progress; a KDC that returns byte-identical material would be paced rather than trusted, which is the desired behavior but is unproven against a real KDC.
- Must be verified that `refresh_tgt_if_needed` cannot legitimately install a fresh TGT whose `ticket` and `session_key` are both byte-identical while "making progress" (i.e. no false pacing of a genuine refresh); the audit's reproduction shows the no-progress case only.
- The state is reachable from a lower-trust local input (a placed ccache, chosen `KRB5CCNAME`, or a handed-over TGT), but no attacker action is required and there is no data disclosure; the only resource cost is one CPU of the embedding process for up to the refresh band.
