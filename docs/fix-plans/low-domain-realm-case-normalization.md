# Mixed-case DNS host misses the lower-cased [domain_realm] mapping

- Severity: low — likelihood medium / impact low / confidence high — fingerprint `src/config.rs:resolve_realm/asymmetric-domain-case-normalization`
- Audit: run-2 `findings.json` record `src/config.rs:resolve_realm/asymmetric-domain-case-normalization` + primary evidence `run-2/agents/vfy-src-config-rs-resolve-re-be1675/artifacts/probe-case-verify2.log`, corroborated by `run-2/run-1/agents/smoke/artifacts/consolidated-probes.log`
- Status: planned; not implemented in the fork; no upstream PR yet

## Problem

`parse_domain_realm` stores every `[domain_realm]` key ASCII-lower-cased, but `Config::resolve_realm` folds only a trailing dot and then performs case-sensitive exact and dot-suffix lookups. A caller-supplied DNS host text with any upper-case letter (typically a URL host, a user-entered name, or an application-side name the application did not fold) therefore misses an exact mapping and can fall through to a less specific suffix or to the client-realm fallback, silently selecting a different realm — and a different cached principal identity — than the operator's mapping intends. The same missing fold in the host-based constructors additionally violates RFC 4120 §6.2.1's lowercase-host requirement. No key, ticket, or privilege is needed; the trigger is only non-lower-case host text.

## Root cause (verified against upstream 6f4abc9)

- `src/config.rs:42`–`:43` — doc: `[domain_realm]` mappings "keyed by lower-case domain names"; `src/config.rs:688` — `domain_realm.insert(domain.to_ascii_lowercase(), realm.to_owned())` fixes the relation as case-insensitive on the key side only.
- `src/config.rs:198` — `let domain_name = domain_name.trim_end_matches('.');` — only the trailing dot is stripped; `src/config.rs:199` — case-sensitive exact `self.domain_realm.get(domain_name)`.
- `src/config.rs:204` — `let suffix = format!(".{}", parts[start..].join("."))` and `:205` — case-sensitive `get(&suffix)` — the dot-suffix walk compares the un-folded query tail against lower-cased keys (`resolve_realm` spans `:197`–`:209`).
- `src/client/principal.rs:129` — `[service.to_owned(), host.to_owned()]` — the host component enters the SPN verbatim (`host_based_service` `:72`, `host_based_service_in_realm` `:80`).
- `src/client/negotiate.rs:110` — `authorization_header_for_host` / `:144` — `authorization_context_for_host` — documented initiators that hand the caller's host to `Principal::host_based_service` and leave the realm to be resolved from `[domain_realm]` or the client realm.
- `src/client.rs:3451` — `service_realm` submits the last SPN component to `resolve_realm`; `src/client.rs:1381` — `resolve_service_principal` falls back to `self.client.realm` when the lookup misses (`:1382`); `src/client.rs:3621` — `service_cache_key` keys the cache by resolved realm + byte-exact components; `src/client.rs:1934` — TGS-REQ `sname` carries the un-canonicalized name.
- `src/client/transport.rs:676` — `get_service_ticket_with_referral_trace_limit` repeats the empty-realm resolution for direct callers, setting `target_realm` at `:694`.

Fork delta: the audit's `src/config.rs:299/300/304-310/866`, `src/client.rs:3615/3785/1423/2095`, `src/client/transport.rs:708/710` and `src/client/principal.rs:129` are fork line numbers. Base equivalents are above; `src/client/principal.rs:129` is identical in both trees.

## Evidence (from the audit)

- `run-2/agents/vfy-src-config-rs-resolve-re-be1675/artifacts/probe-case-verify2.log:181` — public-API probe: `lower_exact=Some("PARTNER.REALM") lower_suffix=Some("PARTNER.REALM") upper_exact=None mixed_exact=None upper_suffix=None mixed_suffix=None`.
- `.../probe-case-verify2.log:182` — SPN components case-preserved: `upper={realm="" components=["HTTP","FOO.EXAMPLE.COM"]}`, `mixed={... "Foo.Example.com"}`.
- `.../probe-case-verify2.log:183` — cached-service-ticket realm divergence: `lower=Some("PARTNER.REALM") upper=Some("CLIENT.REALM") mixed=Some("CLIENT.REALM")`; `test result: ok. 1 passed; SANDBOX_EXIT=0`.
- `run-2/run-1/agents/smoke/artifacts/consolidated-probes.log:300` — run-1 corroboration: `resolve_realm` `uppercase=None mixed=SUFFIX lowercase=EXACT`.

## Proposed fix

Fold the DNS-name text to lower case once on both sides of the relation, leaving realm values and the service component case-sensitive. This is finding `.../asymmetric-domain-case-normalization`; it overlaps the host-case finding on the `principal.rs` line.

1. `src/config.rs` `resolve_realm` (base `:197`–`:209`): ASCII-fold the query (after stripping the trailing dot) before the exact and suffix lookups. Keep the write-side `to_ascii_lowercase()` at `:688` and the most-specific-first order.
2. `src/client/principal.rs` `host_based_service_principal` (base `:129`): ASCII-fold the host component (identical hunk to the host-case plan — deduplicate if both land).
3. Leave realm values, the `service` component, `parse_service`, and generic `Principal::new` unchanged (RFC 4120 §6.1: domain names are case-insensitive, realm names are case-sensitive).

```rust
// src/config.rs — Config::resolve_realm
pub fn resolve_realm(&self, domain_name: &str) -> Option<&str> {
    let folded = domain_name.trim_end_matches('.').to_ascii_lowercase();
    let domain_name = folded.as_str();
    if let Some(realm) = self.domain_realm.get(domain_name) {
        return Some(realm);
    }

    let parts: Vec<_> = domain_name.split('.').collect();
    for start in 1..parts.len() {
        let suffix = format!(".{}", parts[start..].join("."));
        if let Some(realm) = self.domain_realm.get(&suffix) {
            return Some(realm);
        }
    }
    None
}

// src/client/principal.rs — host_based_service_principal
    Ok(Principal::new(
        realm,
        KRB_NT_SRV_INST,
        [service.to_owned(), host.to_ascii_lowercase()],
    ))
```

## Regression tests

- `tests/config.rs::resolve_realm_folds_dns_case` — `Config::parse` a config with `[domain_realm] foo.example.com = PARTNER.REALM` and `.example.com = SUFFIX.REALM`; assert `resolve_realm` returns identical values for `"FOO.EXAMPLE.COM"`, `"Foo.Example.com"`, `"FOO.EXAMPLE.COM."` as for the lower-case spelling, and that realm values keep their case. (Base has no `Config::parse_without_env`; use `Config::parse` for the upstream-targeted test.)
- `tests/client_principal.rs::host_based_service_folds_dns_host_case` — shared with the host-case plan: upper/mixed hosts fold to `["HTTP","auth.cern.ch"]`; `parse_service` and the service/realm case stay unchanged.
- `tests/client_integration.rs::resolve_service_principal_uses_case_folded_domain_realm` (or a unit test over `TokioClient::from_ccache` + `cache_service_ticket`/`cached_service_ticket`) — given `[domain_realm]` mapping for a domain, a client with a different own realm must select the mapped realm (and cache key) for an upper-case host, not fall back to the client realm.

## Verification

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --test config
cargo test --all-features --test client_principal
```

## Compatibility / notes

- Behaviour change is confined to case-insensitive DNS-name comparison; realm values remain case-sensitive, so realm matching semantics are unchanged.
- Overlaps the host-case finding on `src/client/principal.rs:129`; if both PRs land, one hunk must be deduplicated (or merge into a single PR).
- The two in-flight HIGH fixes touch `src/service.rs`, not `src/config.rs` or `src/client/principal.rs`; no interaction.

## Upstream route

- PR against `clelange/rskrb5` (base `6f4abc9`): `resolve_realm` and the host helper are upstream code. Prefer a single combined PR with the host-case finding (same `principal.rs` hunk).

## Risks / open questions

- Condition: the config must carry a `[domain_realm]` mapping whose realm differs from the client realm; without a mapping the client-realm fallback is the ordinary path. Host text must contain an upper-case ASCII letter.
- The host text arrives from the embedding application (URL host/user entry), not from peer-supplied bytes — this is why the severity is below high; the audit explicitly corrected the hunter's "peer-supplied" framing.
- No credential disclosure, key recovery, or privilege gain follows: accepting any resulting ticket still requires the service's own key.
- Allocator note: the fold consumes one `String` per lookup; acceptable, but avoid folding if the query is already lower case if hot-path sensitivity is a concern.
