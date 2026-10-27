# client: fix the TGT refresh band, pace auto-renewal and recover from refused renewals

- Target: `clelange/rskrb5` `main` (`6f4abc9`), branch `fix/client-renewal-series`.
- Commits:
  - `29b6a51` client: measure the refresh band from the current ticket life
  - `0a2cf65` client: pace auto-renewal when a refresh makes no progress
  - `9db3c87` client: recover automatic logins when a cached TGT can no longer be renewed
  - `babea69` client: make the renewal tests parallel-safe and lint-clean
  - `20541ea` client: pace by due state and test with paused time
  - `fbf4320` client: cover renewal pacing after a renewal, the refused-renewal AS fallback and the service-ticket path

## Problem

Three defects in the `Tokio` TGT refresh logic. They share the same functions, so they ship together.

**1. The refresh band grew with the age of the login.** `session_refresh_due_at` and `session_refresh_delay_at` measured the ticket lifetime as `end_time - auth_time`. A renewal advances `start_time` but keeps `auth_time`, so the measured lifetime grew with every renewal. After roughly five ticket lifetimes, the band (`lifetime / 6`) was larger than the whole remaining validity. Every freshly renewed TGT was then due at once, and `spawn_auto_renewal_with_retry` sent one TGS renewal per transport round trip until `renew_till` (600 requests in 1.2 s on loopback), holding the client mutex the whole time.

**2. Auto-renewal spun when a refresh made no progress.** A cache-only client (`from_ccache`, `from_tgt_session`) whose TGT is due but not renewable gets the unchanged session back from `refresh_tgt_if_needed`. The loop counted that as success: the delay is zero while due, so it skipped the sleep, and `retry_delay` only applied after an `Err`. The task re-ran immediately and burned about a full core for the rest of the refresh band.

**3. An expired but renewable TGT blocked recovery.** `session_renewable_at` checks only `renew_till`. For a TGT whose `end_time` had passed while `renew_till` was still ahead, `affirm_login` and `ensure_tgt` sent a TGS RENEW and returned its error directly. A conforming KDC refuses that renewal (`KRB_AP_ERR_TKT_EXPIRED`), so every automatic path failed (`affirm_login`, `refresh_tgt_if_needed`, `get_service_ticket`, auto-renewal), even with a password or keytab configured. Only an explicit `login()` recovered.

RFC basis:

- RFC 4120 section 5.3 defines `authtime` as the time of initial authentication for the principal, so it doesn't move when a ticket is renewed. The renewed ticket gets a new `starttime`, so the current ticket life is `endtime - starttime`.
- RFC 4120 section 2.3: a renewable ticket can be renewed only while it's still valid. Once it has expired, the KDC refuses to renew it.

## Change

- **Band** (`29b6a51`): both helpers use `end_time - start_time`. The `end_time` short-circuit, the zero-lifetime guard and the `Duration::ZERO` returns stay. Construction already falls back from `start_time` to `auth_time` when the wire or ccache has no start time.
- **Pacing** (`0a2cf65`, reworked in `20541ea`): after each refresh, the loop checks whether the TGT is still due. If the refresh failed or the TGT is still due, it sleeps `retry_delay` before the next iteration. The check reads the due state, so no ticket or key bytes are compared or cloned. It also caps a renewal storm, even without the band fix.
- **Recovery** (`9db3c87`): in `affirm_login` and `ensure_tgt`:
  - a TGT that has expired, with a credential configured, goes straight to the AS exchange;
  - otherwise the renewal is still tried first, and if it fails and a credential is configured, the code falls through to the credential-backed `login()`;
  - cache-only clients keep returning the renewal error (no AS exchange is possible), so `session_renewable_at` still keeps a ticket inside the KDC's clock-skew grace period.
- **Tests** (`babea69`, `20541ea`, `fbf4320`): the dev-dependency on `tokio` gains the `test-util` feature for paused-clock tests. No new crates.

## Tests

New tests in `tests/client/session_cache.rs` (they run under `--test client`):

- `tokio_client_refresh_due_uses_current_ticket_life`: a ticket renewed 60 s ago with 10 h left and a 60 h old `auth_time` isn't due, and the same ticket near its end is.
- `tokio_client_auto_renewal_paces_cache_only_nonrenewable_tgt`: under a paused clock, a due, non-renewable, cache-only TGT lets a 600 s virtual sleep complete (the loop paces), where a spinning loop times out.
- `tokio_client_auto_renewal_paces_after_renewal`: the counting mock KDC answers each renewal with a TGT that keeps `auth_time = now - 60 h` and sets `start_time = now`, `end_time = now + 10 h`. Over 600 s of virtual time there's exactly 1 renewal request.
- `tokio_client_affirm_login_falls_back_to_as_for_expired_renewable_tgt` and `tokio_client_refresh_tgt_if_needed_falls_back_to_as_for_expired_renewable_tgt`: a loopback KDC answers TGS renewals with `KRB_AP_ERR_TKT_EXPIRED` and counts AS-REQs. Both paths recover through the AS exchange.
- `tokio_client_get_service_ticket_falls_back_to_as_for_expired_renewable_tgt`: an expired renewable cached TGT plus a password. `get_service_ticket` sends an AS-REQ, then a TGS-REQ, and returns `Ok`.
- `tokio_client_auto_renewal_uses_as_when_renewal_refused`: password credentials and a due TGT whose renewal the KDC refuses. At least one AS-REQ is seen within 600 s of virtual time.
- `tokio_client_cache_only_expired_renewable_tgt_keeps_renewal_error`: the cache-only control. The renewal error is still returned after exactly one TGS request.

Fail-before evidence:

- With `src/client.rs` restored to `6f4abc9`, every new test fails except the cache-only control: `tokio_client_refresh_due_uses_current_ticket_life`, `tokio_client_auto_renewal_paces_cache_only_nonrenewable_tgt`, `tokio_client_auto_renewal_paces_after_renewal`, `tokio_client_affirm_login_falls_back_to_as_for_expired_renewable_tgt`, `tokio_client_refresh_tgt_if_needed_falls_back_to_as_for_expired_renewable_tgt`, `tokio_client_get_service_ticket_falls_back_to_as_for_expired_renewable_tgt` and `tokio_client_auto_renewal_uses_as_when_renewal_refused`.
- How the last three of those fail: the pacing test hits its 10 s real-time timeout, the refused-renewal test sees no AS-REQ within 600 s, and `get_service_ticket` returns the KDC's error code 32.
- `tokio_client_cache_only_expired_renewable_tgt_keeps_renewal_error` passes there too, as it should: cache-only behaviour doesn't change.

## Verification

All runs used stable Rust 1.99.1 on the branch tip.

- `cargo test --all-features --test client session_cache`: ok.
- `cargo test --all-features --no-fail-fast`: 33 test targets ok, 0 failed.
- `cargo fmt --all -- --check`: clean.
- `cargo clippy --all-targets --all-features -- -D warnings -A clippy::chunks_exact_to_as_chunks`: the only diagnostics are the 3 `clippy::byte_char_slices` errors in `tests/kadmin.rs` that already fail on `main`. Clippy on the `client` test crate alone is clean. CI on `main` stays red on `clippy::chunks_exact_to_as_chunks` and `clippy::byte_char_slices` until PR #15 lands. This change adds no diagnostic.

## Compatibility

- No public API change. All the changed functions are private or keep their signatures.
- Behaviour:
  - refresh timing is now a fraction of the current ticket life, so a just-renewed ticket isn't due;
  - a refresh that makes no progress waits `retry_delay` (60 s by default from `spawn_auto_renewal`) instead of spinning;
  - with a credential configured, an expired renewable TGT is replaced through the AS exchange instead of failing on a refused renewal. This changes KDC traffic for that case from a doomed TGS RENEW to an AS-REQ.
- Dev-only: the `tokio` dev-dependency gains the `test-util` feature.

## Series and merge order

- `src/client.rs`: `fix/enctype-policy`, then this PR. They merge cleanly in either order (checked with `git merge-tree` on `6f4abc9`). The enctype PR goes first because these tests drive the exchange paths it changes.
- `tests/client/session_cache.rs` also gets new tests from `fix/host-case-spn` and `fix/domain-realm-normalization`. Those merge cleanly in any order.

## Notes

- A non-conforming KDC that rewrites `auth_time` on renewal hides defect 1, but `start_time` is the right basis either way.
- The pacing check treats "still due after a refresh" as no progress. A renewal that returns a ticket already inside its own refresh band is paced too, which is the intended outcome.
