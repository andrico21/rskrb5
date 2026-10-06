# Refresh band computed from `auth_time`, so a renewed TGT is immediately due
- Severity: medium — likelihood medium, impact medium, confidence not scored in the record (verdict: confirmed, independently reproduced) — fingerprint `rskrb5/client/renewal-window-original-auth-time`
- Audit: run-2 `findings.json` record (verdict `confirmed`) + `agents/vfy-rskrb5-client-renewal-wind/artifacts/vfy-renewal-window-3` (promoted sandbox log)
- Status: planned; not implemented in the fork; no upstream PR yet

## Problem
`session_refresh_due_at` and `session_refresh_delay_at` derive the refresh band from
`end_time - auth_time` — the original authentication time — instead of the current ticket
life `end_time - start_time`. RFC 4120 leaves `auth_time` unmodified across renewals while
a renewal advances `start_time`, so the measured "lifetime" grows with the age of the
login. Once a client keeps the same renewable TGT for roughly five ticket lifetimes, the
band (`lifetime / 6`) exceeds the whole remaining validity and every just-renewed ticket is
already due; `spawn_auto_renewal_with_retry` then issues one authenticated TGS renewal per
transport round trip (measured 600 requests / 1.2 s on loopback) until `renew_till`,
holding the client mutex across every exchange.

## Root cause (verified against upstream 6f4abc9)
- `src/client.rs:3645` — `let Ok(lifetime) = session.end_time.duration_since(session.auth_time) else {` — the due predicate uses the original login time; `start_time` is never consulted (fork `src/client.rs:3809`).
- `src/client.rs:3655` — `remaining <= lifetime / SESSION_REFRESH_DIVISOR` — the band grows without bound as the login ages.
- `src/client.rs:3663` / `src/client.rs:3668` — the delay path repeats the same `auth_time` basis for `refresh_at` and returns `Duration::ZERO` whenever due (fork `src/client.rs:3827`/`3832`).
- `src/client.rs:54` — `const SESSION_REFRESH_DIVISOR: u32 = 6;` — the divisor that turns the inflated lifetime into a band larger than the remaining validity.
- `src/client.rs:2480-2483` — `process_tgs_rep_inner` already stores `auth_time` and `start_time` separately (`start_time` falls back to `auth_time` only when the reply omits it), so the correct basis is available on the session.
- `src/client.rs:202-216` — `AsRepSession` carries both `auth_time` (`:213-214`) and `start_time` (`:215-216`), so the wrong field is a pure selection bug.
- `src/client.rs:3562-3567` — `ccache_credential_session` imports both fields separately (`start_time` defaults to `auth_time` only when the ccache `starttime` is 0), so an imported renewed ccache reaches the same state without any local renewal.

Line drift: in the fork these live at `spawn_auto_renewal_with_retry` `829`, `affirm_login` `1130`, `ensure_tgt` `1382`, `process_tgs_rep_inner` `2586`, `ccache_credential_session` `3726`, `session_refresh_due_at` `3805`, `session_refresh_delay_at` `3823`, `session_renewable_at` `3840`; the function bodies are byte-identical to base (fork `src/client.rs` is +164 lines earlier in the file).

## Evidence (from the audit)
- `run-2/findings.json` (`renewal-window-original-auth-time`, `evidence[].description`) — `session_refresh_due_at` derives the band from `end_time - auth_time`; `start_time` is available but unused.
- `agents/vfy-rskrb5-client-renewal-wind/artifacts/vfy-renewal-window-3` (`execution.observed_result`) — `tgt_refresh_due()` true for a ticket renewed 60 s ago with 1 h left whose `auth_time` is 6 h old, false for the identical ticket with `auth_time = start_time`; against the loopback mock KDC 600 accepted TGS-REQs in 1.2 s, and the control rewriting `auth_time` did not storm.
- `tests/client.rs:371` (base) — `tgt.start_time = tgt.auth_time;` in `current_tgt_session`, i.e. every refresh fixture pins the two fields equal, so no existing test exercises a stale `auth_time` with a fresh `start_time`.

## Proposed fix
1. In `session_refresh_due_at` (`src/client.rs:3641`) and `session_refresh_delay_at` (`src/client.rs:3659`) replace `session.auth_time` with `session.start_time`, keeping the `now >= end_time` short-circuit, the zero-lifetime guard, and the existing `Duration::ZERO` returns.
2. Do not change the construction-time normalization: `process_tgs_rep_inner` (`:2481-2483`) and `ccache_credential_session` (`:3564-3568`) already fall back `start_time -> auth_time` when the wire/ccache start time is absent, which is the intended `auth_time`-only fallback.
3. Leave `session_renewable_at` unchanged; eligibility (renew `renew_till`) is a separate finding (`low-renewal-eligibility-expired-tgt.md`).

```rust
fn session_refresh_due_at(session: &AsRepSession, now: SystemTime) -> bool {
    if now >= session.end_time {
        return true;
    }
    let Ok(lifetime) = session.end_time.duration_since(session.start_time) else {
        return true;
    };
    if lifetime.is_zero() {
        return true;
    }
    let remaining = session
        .end_time
        .duration_since(now)
        .unwrap_or(Duration::ZERO);
    remaining <= lifetime / SESSION_REFRESH_DIVISOR
}

fn session_refresh_delay_at(session: &AsRepSession, now: SystemTime) -> Duration {
    if session_refresh_due_at(session, now) {
        return Duration::ZERO;
    }
    let Ok(lifetime) = session.end_time.duration_since(session.start_time) else {
        return Duration::ZERO;
    };
    let Some(refresh_at) = session
        .end_time
        .checked_sub(lifetime / SESSION_REFRESH_DIVISOR)
    else {
        return Duration::ZERO;
    };
    refresh_at.duration_since(now).unwrap_or(Duration::ZERO)
}
```

## Regression tests
- `tests/client/session_cache.rs::tokio_client_refresh_due_uses_current_ticket_life` (new, runs under `--test client`) — build a session with `auth_time = now - 60 h`, `start_time = now - 60 s`, `end_time = now + 10 h`; assert `TokioClient::tgt_refresh_due()` is `false`, and a copy with `remaining <= lifetime/6` asserts `true`. Fixture: parameterize `current_tgt_session` (`tests/client.rs:362`) to accept a `start_time` distinct from `auth_time` while the existing callers keep `start_time = auth_time`.
- `tests/client/session_cache.rs::tokio_client_auto_renewal_paces_after_renewal` — answer the loopback mock KDC (`tests/client.rs:1038-1089` helpers) with a renewal that preserves `auth_time` and advances `start_time`; assert the number of TGS-REQs in a fixed window stays near one per refresh band instead of per round trip.
- Keep `tests/client/session_cache.rs::tokio_client_reports_tgt_refresh_due_window` (`:559`) green as the non-regression anchor for the existing `start_time == auth_time` shape.

## Verification
```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --test client
```

## Compatibility / notes
- No public API change; only the two private `#[cfg(feature = "tokio")]` session helpers change basis. `tokio_client_reports_tgt_refresh_due_window` and `tokio_client_refresh_tgt_if_needed_reuses_fresh_cache_only_tgt` (`:583`) keep passing because their fixtures pin `start_time == auth_time`.
- Release-note implication: refresh cadence is now a fraction of the current ticket life; a just-renewed ticket is no longer due.
- The two in-flight HIGH fixes are both in `src/service.rs` (replay-key identity, authenticator realm binding) and do not touch this code. This plan overlaps the other two `src/client.rs` plans (`low-auto-renewal-busy-loop.md`, `low-renewal-eligibility-expired-tgt.md`) in the same functions; land them as one client refresh change or sequence them so `session_refresh_*` is edited once.

## Upstream route
- PR against `clelange/rskrb5` (base `6f4abc9`) is viable: self-contained, no fork-only dependency, and the base tree still ships the `auth_time` basis. Nothing blocks an upstream first PR; the fork can carry it meanwhile.

## Risks / open questions
- The bug requires a conforming KDC that preserves `auth_time` across renewals (RFC 4120 §2.3, §3.3.3). A non-conforming KDC that rewrites `auth_time` masks the symptom but the scheduling basis is still the wrong field, so the fix is correct either way.
- Changing the band changes observable timing for deployments that tuned around the inflated band; the intended behavior is strictly tighter pacing, but any hidden reliance on "due immediately" is unproven and untested.
- If `start_time` is occasionally later than `end_time` on malformed input, `duration_since` returns `Err` and due is reported `true` — the existing fail-open-to-due shape is retained deliberately.
