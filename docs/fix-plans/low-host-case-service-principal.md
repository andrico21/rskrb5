# Host-based service constructors preserve DNS host case

- Severity: low — likelihood medium / impact low / confidence high — fingerprint `rskrb5/client/host-based-principal-host-case`
- Audit: run-2 `findings.json` record `rskrb5/client/host-based-principal-host-case` + primary evidence `run-2/agents/vfy-rskrb5-client-host-based-p/artifacts/vfy-host-case3.log` (independent reproduction), corroborated by `run-2/agents/hunt2b-identity/artifacts/probe-identity-3.log`
- Status: planned; not implemented in the fork; no upstream PR yet

## Problem

`Principal::host_based_service` and `Principal::host_based_service_in_realm` copy the caller-supplied DNS host into the two-component `KRB_NT_SRV_INST` name exactly as written, so `HTTP/AUTH.CERN.CH` and `HTTP/auth.cern.ch` become two distinct principal identities for one DNS peer. Because every downstream consumer (the `[domain_realm]` lookup, the service-ticket cache key, and the TGS-REQ `sname`) reads that component verbatim, a mixed-case host text silently misses an exact `[domain_realm]` entry, occupies a second cache entry, and is requested from the KDC with non-canonical case. Against a case-sensitive KDC principal store (MIT krb5) the non-canonical SPN then fails to match the registered lower-case service principal. RFC 4120 §6.2.1 requires the host name to be lowercase where it is not case sensitive (Internet domain names); §1.3 folds user-entered names to lowercase for interoperability.

## Root cause (verified against upstream 6f4abc9)

- `src/client/principal.rs:129` — `[service.to_owned(), host.to_owned()]` — the shared helper `host_based_service_principal` (declared at `:109`) never applies the ASCII host fold, so both host-based constructors inherit the verbatim copy.
- `src/client/principal.rs:72` — `pub fn host_based_service(...)` and `src/client/principal.rs:80` — `pub fn host_based_service_in_realm(...)` — the two public entry points that enter the helper with caller host text.
- `src/client/principal.rs:55` — `pub fn parse_service(...)` — preserves each component's bytes; the constructor-scoped fix intentionally leaves this explicit parser unchanged (documented in the remediation).
- `src/client/negotiate.rs:110` — `authorization_header_for_host` / `:144` — `authorization_context_for_host` — the documented HTTP initiators call `Principal::host_based_service(service, host)` with the caller's host and leave the realm empty for `[domain_realm]` resolution, so any non-lowercase host reaches the helper unchanged and is then mapped with the same unfitted case.
- `src/config.rs:688` — `domain_realm.insert(domain.to_ascii_lowercase(), realm.to_owned())` — keys are lower-cased, while `src/config.rs:199`/`:204`–`:205` look the un-folded query up case-sensitively, so a mixed-case host misses an exact entry.
- `src/client.rs:3451` — `service_realm` submits `components.last()` to `resolve_realm`; `src/client.rs:3621` — `service_cache_key` NUL-joins realm and components, so case variants key different cache entries; `src/client.rs:1934` — TGS-REQ body `sname: Some(principal_to_rasn(&service)?)` copies the un-canonicalized name into the request.

Fork delta: the audit's citations `src/client.rs:3615/3785/2095` and `src/config.rs:866` are fork line numbers (fork refactors `build_tgs_req_for_realm_with_confounder` into `build_tgs_req_for_realm_inner`, fork `:2063`/`:2095`). The base-tree equivalents above are the PR-target lines.

## Evidence (from the audit)

- `run-2/agents/vfy-rskrb5-client-host-based-p/artifacts/vfy-host-case3.log:183` — probe: `lower=["HTTP", "auth.cern.ch"]` vs `upper=["HTTP", "AUTH.CERN.CH"]` vs `mixed=["HTTP", "Auth.Cern.Ch"]`; `assert_ne!(lower, upper)` held through the public constructors.
- `run-2/agents/vfy-rskrb5-client-host-based-p/artifacts/vfy-host-case3.log:185` — `[domain_realm]` mapping `auth.cern.ch`/.cern.ch`: `lower_exact=Some("PARTNER.REALM")` but `upper_exact=None upper_tail=Some("SUFFIX.REALM")`.
- `run-2/agents/vfy-rskrb5-client-host-based-p/artifacts/vfy-host-case3.log:181` — `cache count=2` after caching one fabricated `TgsRepSession` per spelling; `upper_service=Some("HTTP/AUTH.CERN.CH")`.
- `run-2/agents/hunt2b-identity/artifacts/probe-identity-3.log:187` — hunter observation `AUDIT_OBSERVED .../dns-host-case-preserved` matches the independent reproduction.

## Proposed fix

Fold only the DNS host component inside the shared helper; leave the service component, the realm, `Principal::new`, and `parse_service` untouched. This is a one-line change covering both host-based constructors.

1. Edit `host_based_service_principal` in `src/client/principal.rs` (base `:109`–`:131`): ASCII-lower-case the host at construction.
2. Confirm no call site relies on the previous pass-through case (grep `host_based_service` / `host_based_service_in_realm` in `src/`, `tests/`, `examples/`): `tests/client_principal.rs:68`–`:88` uses lower-case hosts only.
3. Note: finding `src/config.rs:resolve_realm/asymmetric-domain-case-normalization` proposes the identical `principal.rs` hunk plus a `resolve_realm` fold — if both land, deduplicate the `principal.rs` edit.

```rust
// src/client/principal.rs — host_based_service_principal
    Ok(Principal::new(
        realm,
        KRB_NT_SRV_INST,
        [service.to_owned(), host.to_ascii_lowercase()],
    ))
```

## Regression tests

- `tests/client_principal.rs::host_based_service_folds_dns_host_case` — assert `Principal::host_based_service("HTTP", "AUTH.CERN.CH")` has components `["HTTP", "auth.cern.ch"]` and empty realm; `host_based_service_in_realm("HTTP", "AUTH.CERN.CH", "CERN.CH")` has components `["HTTP", "auth.cern.ch"]` with realm `CERN.CH`; and `parse_service("HTTP/AUTH.CERN.CH@CERN.CH")` still preserves `AUTH.CERN.CH` (case-sensitive passthrough). No fixture needed.
- `tests/client_principal.rs::host_based_service_preserves_service_case` — assert the `service` component (`"HTTP"` vs `"http"`) and realm case are unchanged by the fix, guarding against over-folding.
- `tests/config.rs::resolve_realm_folds_dns_case` (shared with the case-normalization plan) — configure `[domain_realm] auth.cern.ch = PARTNER.REALM`; assert `resolve_realm("AUTH.CERN.CH")` and `resolve_realm("Auth.Cern.Ch")` equal `Some("PARTNER.REALM")`.
- `tests/client.rs::cached_service_ticket_identity_is_case_folded` — build a `TokioClient` with no network I/O (`from_ccache` over an empty ccache), cache one fabricated `TgsRepSession` for the lower-case SPN, and assert `cached_service_ticket_count() == 1` with a hit for the upper-case spelling supplied through `Principal::host_based_service` (guards the cache-key split that probe 3 observed).

## Verification

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --test client_principal
cargo test --all-features --test config
```

## Compatibility / notes

- Behavioural change: mixed-case hosts now canonicalize to lower case in host-based SPNs — an intentional RFC 4120 §6.2.1 conformance fix. `Principal::new`, `parse_service`, and generic name handling keep pass-through semantics.
- `Principal` equality is byte-exact over `components` (`Vec<String>`), so the fold changes `host_based_service("HTTP", "AUTH.CERN.CH") == host_based_service("HTTP", "auth.cern.ch")` from `false` to `true`; this is the intended single-identity behaviour and is covered by the regression test above.
- The two in-flight HIGH fixes (`src/service.rs:ReplayKey:unbound-ticket-service-identity`, `src/service.rs:validate_ap_req:unbound-authenticator-realm`) touch `src/service.rs`, not `src/client/principal.rs`; no textual or behavioural interaction.
- This is the same underlying defect as finding `src/config.rs:resolve_realm/asymmetric-domain-case-normalization`; the two plans overlap on the `principal.rs` helper line.
- Mixed-case realm values and service names are unaffected; only the host component of the two host-based constructors is folded, so realm matching (case-sensitive) keeps its current semantics.

## Upstream route

- PR against `clelange/rskrb5` (base `6f4abc9`): the helper and both constructors are upstream code. Coordinate with the case-normalization PR to avoid two edits to the same line; a single combined PR (host fold in the helper + `resolve_realm` input fold) is preferable.

## Risks / open questions

- Condition (from `conditions`): the host text supplied to a host-based constructor must carry at least one upper-case ASCII letter (the KDC principal store must be case-sensitive for the SPN to actually fail; AD's case-insensitive store masks the divergence). The identity split, realm-mapping miss, and cache split occur regardless.
- No credential disclosure, privilege gain, or cross-principal ticket reuse was demonstrated; impact stays low.
- Risk: applications that deliberately pass a case-preserving host expecting the old byte-exact SPN would change behaviour — treat as the intended canonicalization and note it in release notes.
- The fold uses `to_ascii_lowercase()` (ASCII only), matching DNS case-insensitivity and RFC 4120 §6.2.1's host-name rule; non-ASCII host text is passed through unchanged.
- Release note: host-based service principals built by `host_based_service(_in_realm)` now carry lower-case DNS hosts; embedders relying on the previous verbatim host text must adapt.
