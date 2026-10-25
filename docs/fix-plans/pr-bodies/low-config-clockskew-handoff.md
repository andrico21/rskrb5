# config: apply [libdefaults] clockskew on the Config-driven acceptors

- Target: `clelange/rskrb5` `main` (`6f4abc9`), branch `fix/config-clockskew-handoff`.
- Commit: `3e4c6c5` config: apply [libdefaults] clockskew on the Config-driven acceptors

## Problem

`Config` parses `[libdefaults] clockskew` into `LibDefaults.clockskew`, but nothing on the acceptor side reads it. The `Config`-driven constructors copy only `default_keytab_name` and leave `ServiceValidator::max_clock_skew` at the compile-time default of 300 s:

- `ServiceValidator::from_default_keytab_name` and `ServiceValidator::from_default_keytab`;
- `NegotiateLayer::from_default_keytab_name` and `NegotiateLayer::from_default_keytab` (and the `NegotiateService` constructors that delegate to them).

An operator who tightens `clockskew = 1s` still gets a validator that accepts authenticators 2 to 299 seconds stale, and tickets up to 300 s past `end_time`. A captured AP-REQ stays replayable for that whole window against any acceptor whose replay cache hasn't seen it (a second instance, a restart). The declared policy is silently not enforced. Deployments on the default value aren't affected, because the default equals the enforced 300 s.

RFC basis: RFC 4120 section 3.2.3 has the server reject an authenticator whose time isn't within the allowable clock skew, and MIT `krb5.conf(5)` defines `[libdefaults] clockskew` as that maximum allowable skew.

## Change

- The four constructors above pass the parsed value through the existing `with_max_clock_skew` builder.
- `ServiceValidator::new`, `from_keytab` and `from_keytab_cow` keep the gokrb5-compatible 300 s default. `DEFAULT_MAX_CLOCK_SKEW` and `ValidatorOptions` are unchanged.

## Tests

New tests:

- `tests/service.rs::config_clockskew_bounds_authenticator_freshness`: with `clockskew = 1s`, both `ServiceValidator::from_default_keytab_name` and `from_default_keytab` reject the fixture authenticator 2 s after its `ctime`, and accept it at its own `ctime`.
- `tests/http.rs::tower_layer_config_clockskew_rejects_stale_authenticator`: `NegotiateLayer::from_default_keytab_name` with `clockskew = 1s` answers `401 Unauthorized` 2 s after the authenticator's `ctime`.
- `tests/service.rs::service_validator_new_keeps_default_skew`: `ServiceValidator::new` still accepts at `ctime + 2s` and rejects at `ctime + 301s`. It pins the 300 s default.

Fail-before evidence: with `src/service.rs` and `src/http.rs` restored to `6f4abc9`, `config_clockskew_bounds_authenticator_freshness` and `tower_layer_config_clockskew_rejects_stale_authenticator` fail. `service_validator_new_keeps_default_skew` passes there too, as it should: it's the control for the unchanged default.

## Verification

All runs used stable Rust 1.99.1 on the branch tip.

- `cargo test --all-features --no-fail-fast`: 33 test targets ok, 0 failed.
- `cargo fmt --all -- --check`: clean.
- `cargo clippy --all-targets --all-features -- -D warnings -A clippy::chunks_exact_to_as_chunks`: the only diagnostics are the 3 `clippy::byte_char_slices` errors in `tests/kadmin.rs` that already fail on `main`. Clippy stops at that test crate, so a second run with `-A clippy::byte_char_slices` lints every target and is clean. CI on `main` stays red on `clippy::chunks_exact_to_as_chunks` and `clippy::byte_char_slices` until PR #15 lands. This change adds no diagnostic.

## Compatibility

- No signature or type change.
- Behaviour: services built through the `Config` constructors now enforce the configured `clockskew`. With the default (300 s) nothing changes. A configured value larger than 300 s now widens the window on those paths too, because the configured value is what gets applied.
- Services built with `ServiceValidator::new` or `from_keytab*` behave as before. The `clockskew` doc should say it applies on the `Config` paths only.

## Series and merge order

- `src/service.rs`, `tests/service.rs`: #20, then #21, then this PR. This PR edits only the constructors and merges cleanly on top of either (checked with `git merge-tree` on `6f4abc9`). It goes last because its tests run through `validate_ap_req`, which #20 and #21 change.
- `src/http.rs`, `tests/http.rs`: this PR, then `fix/mutual-auth-classification`. They merge cleanly in either order. Merging this one first keeps the constructor change separate from the send-wrapper rework.

## Notes

- The ticket-expiry tolerance in `validate_ticket_times` reads the same `max_clock_skew`, so it now follows the configured value too. The tests cover the authenticator window only: the fixture's authenticator ages out of any enforced window before its ticket does.
