# Bare [domain_realm] tag is not applied to its subdomains

- Severity: low — likelihood medium / impact low / confidence high — fingerprint `src/config.rs:resolve_realm/bare-domain-tag-subdomain-miss`
- Audit: run-2 `findings.json` record `src/config.rs:resolve_realm/bare-domain-tag-subdomain-miss` + primary evidence `run-2/agents/vfy-src-config-rs-resolve-re-77c6c5/artifacts/target-repro.log` and MIT-reference calibration `run-2/agents/vfy-src-config-rs-resolve-re-77c6c5/artifacts/mit-semantics2.log`
- Status: planned; not implemented in the fork; no upstream PR yet

## Problem

MIT `krb5.conf(5)` defines a bare `[domain_realm]` tag as the mapping for that domain and all its subdomains, with a leading period restricting a tag to subdomains only. `Config::resolve_realm` implements only an exact key lookup plus a leading-dot suffix walk: the walk formats `.<suffix>` and looks up only that key, so a bare tag is reachable for subdomains through neither path. With `mit.edu = ATHENA.MIT.EDU` alone, `resolve_realm("mit.edu")` resolves (exact match) but `resolve_realm("crash.mit.edu")` returns `None`, so the host-based service principal is bound to the client's own realm instead of the declared realm; the service-ticket cache is keyed with that realm and the TGS-REQ is sent to the wrong realm's KDC.

## Root cause (verified against upstream 6f4abc9)

- `src/config.rs:194` — doc `/// This mirrors gokrb5's lookup order: exact hostname first, then the most specific dotted suffix mapping.` — the asymmetric tag handling is inherited design.
- `src/config.rs:199` — `self.domain_realm.get(domain_name)` — a bare tag matches only the literal host text (exact lookup).
- `src/config.rs:204` — `let suffix = format!(".{}", parts[start..].join("."))` — suffix keys are built with a leading dot only; `src/config.rs:205` — only the dot-form key is queried, so bare keys are structurally unreachable for subdomains.
- `src/config.rs:688` — `parse_domain_realm` stores the operator's spelling lower-cased and records no domain relation for a bare tag.
- `src/client.rs:3451` — `service_realm` hands the last SPN component (DNS host) to `resolve_realm`; `None` means "no operator relation found".
- `src/client.rs:1381`/`:1382` — `resolve_service_principal` fills an empty service realm from `service_realm` and otherwise from `self.client.realm`, so the miss becomes the client's own realm; `src/client.rs:3621` — `service_cache_key` then selects/stores a different principal identity.
- `src/client/transport.rs:676` / `:694` — `get_service_ticket_with_referral_trace_limit` resolves the empty realm the same way and sets `target_realm` to the current TGT realm, so the loop requests the service directly instead of obtaining a referral TGT.

Fork delta: the audit's `src/config.rs:296/299-311/866`, `src/client.rs:3619/1422/1423/3785/1024-1026/2094-2095` and `src/client/transport.rs:707/708/710/714-715` are fork line numbers. Base equivalents are above; `tests/config.rs:32`–`:36` fixtures match both trees.

## Evidence (from the audit)

- `run-2/agents/vfy-src-config-rs-resolve-re-77c6c5/artifacts/target-repro.log` — public-API probe (2 tests passed): bare `mit.edu = ATHENA.MIT.EDU` gives `resolve_realm("mit.edu")=Some(...)` but `resolve_realm("crash.mit.edu")=None`, `resolve_realm("a.b.mit.edu")=None`, `resolve_realm("notmit.edu")=None`; dot tag `.mit.edu` gives `resolve_realm("mit.edu")=None`, `resolve_realm("crash.mit.edu")=Some(...)`; the MIT three-tag example gives `crash.mit.edu=Some(TEST.ATHENA.MIT.EDU)`, `sub.crash.mit.edu=None`. Service identity for `HTTP/crash.mit.edu` under a bare tag selects `CLIENT.REALM`, bypassing the seeded `ATHENA.MIT.EDU` ticket.
- `run-2/agents/vfy-src-config-rs-resolve-re-77c6c5/artifacts/mit-semantics2.log` — MIT krb5 1.22.1 reference (`krb5_get_host_realm`, `dns_lookup_realm=false`, network-isolated): with only `mit.edu = ATHENA.MIT.EDU`, `mit.edu`/`crash.mit.edu`/`a.b.mit.edu` all resolve; with only `.mit.edu`, the domain itself resolves to nothing and `crash.mit.edu` resolves. Establishes the intended rule.
- `tests/config.rs:32`–`:36` — the repository's own fixtures pair both spellings (`.test.gokrb5` with `test.gokrb5`, `.resdom.gokrb5` with `resdom.gokrb5`), so no unit test exercises a bare-only tag and the suite stays green.

## Proposed fix

Make the suffix walk honour MIT tag semantics: at each strict suffix level consult both the leading-dot key (subdomains-only) and the bare key (domain-and-subdomains), keeping the most-specific-first order and the exact-host check at `src/config.rs:199` untouched (so a host exactly equal to a tag still resolves there and a leading-dot tag still does not match the domain itself). Realms and the write-side lower-casing stay as-is.

1. Edit `Config::resolve_realm` in `src/config.rs` (base `:197`–`:209`) as below.
2. Compose with the case-normalization finding `src/config.rs:resolve_realm/asymmetric-domain-case-normalization`: both edit the same function. Apply the ASCII fold to the query first, then run this bare/dot walk (the attached `resolve_realm` shows the bare-tag variant without the fold; merge the two hunks into one).
3. Add the regression test (see below) and update any existing `resolve_realm` expectations.

```rust
// src/config.rs — Config::resolve_realm (bare-tag aware; merge with the case fold)
pub fn resolve_realm(&self, domain_name: &str) -> Option<&str> {
    let domain_name = domain_name.trim_end_matches('.');
    if let Some(realm) = self.domain_realm.get(domain_name) {
        return Some(realm);
    }

    let parts: Vec<_> = domain_name.split('.').collect();
    for start in 1..parts.len() {
        let bare = parts[start..].join(".");
        let dot = format!(".{bare}");
        if let Some(realm) = self.domain_realm.get(&dot) {
            return Some(realm);
        }
        if let Some(realm) = self.domain_realm.get(&bare) {
            return Some(realm);
        }
    }
    None
}
```

## Regression tests

- `tests/config.rs::resolve_realm_applies_bare_domain_tags_to_subdomains` — parse the MIT three-tag config (`crash.mit.edu = TEST.ATHENA.MIT.EDU`, `.dev.mit.edu = TEST.ATHENA.MIT.EDU`, `mit.edu = ATHENA.MIT.EDU`, `default_realm = CLIENT.REALM`); assert `resolve_realm("crash.mit.edu") == Some("TEST.ATHENA.MIT.EDU")`, `resolve_realm("x.dev.mit.edu") == Some("TEST.ATHENA.MIT.EDU")`, `resolve_realm("dev.mit.edu") == Some("ATHENA.MIT.EDU")` (bare `mit.edu` applies; `.dev.mit.edu` does not), `resolve_realm("sub.crash.mit.edu") == Some("ATHENA.MIT.EDU")`.
- `tests/config.rs::resolve_realm_dot_tag_does_not_match_domain` — with only `.mit.edu = ATHENA.MIT.EDU`, assert `resolve_realm("mit.edu") == None` and `resolve_realm("crash.mit.edu") == Some("ATHENA.MIT.EDU")` (leading-dot semantics preserved). Use `Config::parse` (base has no `Config::parse_without_env`).
- `tests/config.rs::resolve_realm_rejects_bare_prefix_extension` — assert `resolve_realm("notmit.edu") == None` (suffix matching must be dot-anchored, not string-suffix).

## Verification

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --test config
```

## Compatibility / notes

- Behaviour change is limited to hosts that are strict subdomains of a bare-declared domain; hosts exactly equal to a bare tag, leading-dot deployments, and the "both spellings" fixtures are unaffected. The suggested bare lookup preserves most-specific-first and dot-before-bare ordering within a level.
- Overlaps the case-normalization finding on the same `resolve_realm` function — these two hunks must be merged (one PR) or sequenced to avoid a conflict.
- The two in-flight HIGH fixes touch `src/service.rs`, not `src/config.rs` or the client realm path; no interaction.

## Upstream route

- PR against `clelange/rskrb5` (base `6f4abc9`): `resolve_realm`, `parse_domain_realm`, and the client realm-mapping path are upstream code. Combine with the case-normalization finding into a single `resolve_realm` PR.

## Risks / open questions

- Prevalence of the bare-only spelling is the likelihood input (the repo's fixtures write both, masking the defect); correctness is established against the MIT reference for every divergent row probed.
- Precedence when both `.dev.mit.edu` and `dev.mit.edu` are declared was probed as a control; the chosen dot-before-bare ordering within a level must be checked against MIT for that row before merge (the audit verified the divergent rows but the two-spelling precedence is a control, not a demonstrated requirement).
- No credential disclosure, privilege gain, or memory-safety effect was observed; the reach of a ticket issued by the wrong realm depends on the deployment's cross-realm trust layout, which is outside this run.
