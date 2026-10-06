# Operator-declared [libdefaults] clockskew never reaches the acceptor AP-REQ window

- Severity: low — likelihood low / impact low / confidence high — fingerprint `src/config.rs:LibDefaults:clockskew-not-consumed-by-acceptor-skew-check`
- Audit: run-2 `findings.json` record `src/config.rs:LibDefaults:clockskew-not-consumed-by-acceptor-skew-check` + primary evidence `run-2/agents/vfy-src-config-rs-libdefaults-/artifacts/vfy-clockskew-probe.log` (two-stage reproduction + candidate fix), corroborated by `run-2/agents/hunt4-acceptor-policy/artifacts/wave4-policy-probe.log`
- Status: planned; not implemented in the fork; no upstream PR yet

## Problem

`Config` parses `[libdefaults] clockskew` into `LibDefaults.clockskew`, but the only functional read is the config JSON view; every `Config`-driven acceptor constructor copies just `default_keytab_name` and leaves `ServiceValidator::max_clock_skew` at the compile-time `DEFAULT_MAX_CLOCK_SKEW` (300 s). An operator who tightens `clockskew = 1` therefore gets a validator that still accepts authenticators 2–299 s stale (and tickets up to 300 s past `end_time`). A captured AP-REQ (ticket + authenticator ciphertext, no key material) is replayable while its authenticator stays inside 300 s, so the declared acceptance policy is silently not enforced; default-config services behave as intended.

## Root cause (verified against upstream 6f4abc9)

- `src/config.rs:270` — `pub clockskew: Duration` (doc "Accepted clock skew"); default `Duration::from_secs(300)` at `src/config.rs:348`; parsed at `src/config.rs:399` — `"clockskew" => self.clockskew = parse_duration(value)?`.
- `src/config.rs:911` — `clockskew: duration_nanos(libdefaults.clockskew)` — the sole functional read; the value is reported (`duration_nanos` at `:1015`) and never enforced.
- `src/service.rs:306` — `max_clock_skew: DEFAULT_MAX_CLOCK_SKEW` hardcoded in `from_keytab_cow` (`DEFAULT_MAX_CLOCK_SKEW` = `Duration::from_secs(5 * 60)` at `src/service.rs:19`); the only override is the builder `with_max_clock_skew` at `src/service.rs:323`.
- `src/service.rs:557` — `from_default_keytab_name` copies only `config.libdefaults.default_keytab_name`; `src/service.rs:565` — `from_default_keytab` does the same. Neither calls the builder with the configured skew.
- `src/http.rs:756`/`:764` — `NegotiateLayer::from_default_keytab_name`/`from_default_keytab` repeat the drop; `NegotiateService` delegates at `src/http.rs:898`/`:906`; `ValidatorOptions::build` applies `max_clock_skew` only when `Some` (`src/http.rs:1008`) and no `Config` path sets it.
- Enforcement sinks: `src/service.rs:434` — `if abs_duration(now, authenticator_time) > self.max_clock_skew` (error at `:727`); `src/service.rs:487` (start tolerance) and `:496` (expiry twin) in `validate_ticket_times` (`:480`).

Fork delta: `src/service.rs` constructors are at fork `:581`/`:589` (base `:557`/`:565`); `src/http.rs` lines are identical in both trees. Other cited `src/service.rs` lines (`19`, `306`, `323`, `434`, `480`, `487`, `496`) match both trees.

## Evidence (from the audit)

- `run-2/agents/vfy-src-config-rs-libdefaults-/artifacts/vfy-clockskew-probe.log:174` — stage 1: `from_default_keytab_name(config declared=1s) now=ctime+2s -> ACCEPTED client=testuser1`.
- `.../vfy-clockskew-probe.log:175` — same config at `now=ctime+299s -> ACCEPTED`; `:176` — `from_default_keytab(config) now=ctime+2s -> ACCEPTED`.
- `.../vfy-clockskew-probe.log:177` — control: `with_max_clock_skew(1s) now=ctime+2s -> REJECTED 'authenticator clock skew exceeds 1s'` (the window is enforceable).
- `.../vfy-clockskew-probe.log:178`/`:179` — control: default validator rejects at `ctime+301s`, accepts at `ctime+299s` (the 300 s bound actually in force).
- `.../vfy-clockskew-probe.log:171`/`:172` — Tower: `NegotiateLayer::from_default_keytab_name(config)` at `+2s -> 200 OK` while `with_max_clock_skew(1s) -> 401 Unauthorized`.
- `.../vfy-clockskew-probe.log:192`–`:200` — stage 3 (candidate fix): config constructors now reject at `+2s`; `ServiceValidator::new` still accepts at `+2s`/rejects at `+301s`; Tower config layer returns `401` at `+2s`.
- `run-2/agents/hunt4-acceptor-policy/artifacts/wave4-policy-probe.log:140`–`:143` — prior hunter reproduction of the same divergence.

## Proposed fix

Wire the already-parsed field into every `Config`-driven constructor via the existing `with_max_clock_skew` builder; keep `ServiceValidator::new` at 300 s for gokrb5 compatibility. Four constructor bodies plus the two `NegotiateService` delegates (which already delegate to the layer).

1. `src/service.rs` `from_default_keytab_name` / `from_default_keytab` (base `:557`, `:565`): append `.with_max_clock_skew(config.libdefaults.clockskew)`.
2. `src/http.rs` `NegotiateLayer::from_default_keytab_name` / `from_default_keytab` (base `:756`, `:764`): same append.
3. Leave `ValidatorOptions`/`with_max_clock_skew` untouched; do not change `src/service.rs:306` or `DEFAULT_MAX_CLOCK_SKEW`.

```rust
// src/service.rs — ServiceValidator<'static>
pub fn from_default_keytab_name(config: &Config) -> Result<Self, Error> {
    Ok(Self::from_keytab_name(&config.libdefaults.default_keytab_name)?
        .with_max_clock_skew(config.libdefaults.clockskew))
}

pub fn from_default_keytab(config: &Config) -> Result<Self, Error> {
    Ok(Self::from_keytab_name(crate::keytab::default_keytab_name(
        &config.libdefaults.default_keytab_name,
    )?)
    .with_max_clock_skew(config.libdefaults.clockskew))
}

// src/http.rs — NegotiateLayer
pub fn from_default_keytab_name(config: &Config) -> Result<Self> {
    Ok(Self::from_keytab_name(&config.libdefaults.default_keytab_name)?
        .with_max_clock_skew(config.libdefaults.clockskew))
}

pub fn from_default_keytab(config: &Config) -> Result<Self> {
    Ok(Self::from_keytab_name(crate::keytab::default_keytab_name(
        &config.libdefaults.default_keytab_name,
    )?)
    .with_max_clock_skew(config.libdefaults.clockskew))
}
```

## Regression tests

- `tests/service.rs::config_clockskew_bounds_authenticator_freshness` — reuse the existing `HTTP_KEYTAB` and `VALID_AP_REQ` fixtures (authenticator ctime `1_893_553_447.123456`, `http_keytab()`/`timestamp()`/`decode_hex()` helpers). Build a config with `clockskew = 1` plus `default_keytab_name` pointing at the saved keytab (extend `config_with_default_keytab_name`, base `tests/service.rs:537`); assert `from_default_keytab_name(&config).with_now(ctime + 2s)` returns the `Error::ClockSkew` error and `.with_now(ctime)` validates; repeat for `from_default_keytab` with `KRB5_KTNAME` unset (`common::EnvVarGuard`).
- `tests/service.rs::service_validator_new_keeps_default_skew` — `ServiceValidator::new(&keytab)` still accepts at `ctime + 2s` and rejects at `ctime + 301s`, pinning the gokrb5-compatible 300 s default.
- `tests/http.rs::tower_layer_config_clockskew_rejects_stale_authenticator` (`#[cfg(feature = "tower")]`) — model on `tower_layer_loads_config_default_keytab_name` (base `tests/http.rs:670`); `NegotiateLayer::from_default_keytab_name(&config clockskew = 1)` at `now = ctime + 2s` must return `401 Unauthorized`, and `with_max_clock_skew(1s)` remains a working override.

## Verification

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --test service
cargo test --all-features --features tower --test http
```

## Compatibility / notes

- Parity: `ServiceValidator::new` and `from_keytab_cow` keep 300 s (gokrb5 default); only `Config`-driven constructors adopt the declared value. Document that `clockskew` is applied on `Config` paths only.
- Interaction with the two in-flight HIGH fixes: `src/service.rs:ReplayKey:unbound-ticket-service-identity` and `src/service.rs:validate_ap_req:unbound-authenticator-realm` both edit `ServiceValidator::validate_ap_req` (around `src/service.rs:434` and the replay-key construction) — the same function whose skew check this fix feeds. The clockskew hunk edits only the constructors (`:557`/`:565`), so a textual merge is unlikely, but the regression tests must run after those land because they exercise `validate_ap_req`.
- No API break: constructors keep their signatures and return types.

## Upstream route

- PR against `clelange/rskrb5` (base `6f4abc9`): the field, constructors, and builder are all upstream code; the fix is a strict policy handoff with no new API. Coordinate with the two in-flight HIGH `src/service.rs` PRs to sequence the edits/tests.

## Risks / open questions

- Unproven by the audit: the ticket-expiry twin (`src/service.rs:496`) — read directly from the same unfed field and stated as source-verified rather than end-to-end demonstrated, because the in-repo fixture's authenticator ages past any enforced window first. Cover it with a dedicated test if a suitable fixture/clock can be constructed.
- Condition: requires a non-default `clockskew` declaration; the default equals the enforced 300 s, so default deployments are unaffected.
- A replayed captured AP-REQ additionally needs a replay cache that has not seen the `(service, client, ctime, cusec)` tuple (second instance/restart/cleared cache); impact remains bounded to a 300 s tolerance.
- If the maintainers prefer the directive be refused rather than applied when a `Config` constructor is used, that alternative is noted in the remediation strategy but is a larger API decision.
