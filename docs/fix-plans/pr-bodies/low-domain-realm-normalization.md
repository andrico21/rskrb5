# config: fold DNS case and honour bare [domain_realm] tags

- Target: `clelange/rskrb5` `main` (`6f4abc9`), branch `fix/domain-realm-normalization`.
- Commits:
  - `9ede05a` config: fold DNS case and honour bare [domain_realm] tags
  - `20e48ab` config: test dot-anchored suffixes and the client realm path

## Problem

`Config::resolve_realm` had two gaps.

1. **Case.** `parse_domain_realm` stores every `[domain_realm]` key lower-cased, but `resolve_realm` stripped only a trailing dot and then compared the caller's text case-sensitively. A host like `Foo.Example.COM` missed an exact mapping and fell through to a less specific suffix, or to the client's own realm.
2. **Bare tags.** The suffix walk built `.<suffix>` keys only. A bare tag (`mit.edu = ATHENA.MIT.EDU`) matched the literal domain and never its subdomains, so `crash.mit.edu` resolved to `None`.

In both cases the client binds the host-based service principal to the wrong realm. The service-ticket cache keys on that realm, and the TGS-REQ goes to the wrong realm's KDC instead of following the operator's mapping.

Basis:

- MIT `krb5.conf(5)` `[domain_realm]`: a tag with a leading period applies to subdomains only. A tag without one applies to that domain and all its subdomains. MIT krb5 1.22.1 (`krb5_get_host_realm` with `dns_lookup_realm = false`) resolves `crash.mit.edu` and `a.b.mit.edu` from a bare `mit.edu` tag.
- DNS names compare case-insensitively (RFC 4343), and RFC 4120 section 6.2.1 lower-cases host names in service principals. Realm names stay case-sensitive.

## Change

- `resolve_realm` lower-cases the query (ASCII) after stripping the trailing dot.
- At each suffix level, most specific first, it checks the leading-dot key, then the bare key. The exact-host lookup comes first and is unchanged, so a leading-dot tag still doesn't match the domain itself, and a bare tag still matches it exactly.
- Realm values and the write-side lower-casing are unchanged.

## Tests

New tests in `tests/config.rs`:

- `resolve_realm_folds_dns_case`: upper-case, mixed-case and trailing-dot spellings resolve to the same realm as the lower-case one, and realm values keep their case.
- `resolve_realm_applies_bare_domain_tags_to_subdomains`: MIT's own three-tag example (`crash.mit.edu`, `.dev.mit.edu`, `mit.edu`). The expected rows match the MIT 1.22.1 reference, for example `sub.crash.mit.edu` resolves to `TEST.ATHENA.MIT.EDU` and `dev.mit.edu` to `ATHENA.MIT.EDU`.
- `resolve_realm_dot_tag_does_not_match_the_domain_itself`: with only `.mit.edu`, `mit.edu` stays unresolved and `crash.mit.edu` resolves.
- `resolve_realm_prefers_dot_tag_over_bare_at_the_same_level`: with both `.dev.mit.edu` and `dev.mit.edu`, the domain resolves from the bare tag and its subdomains from the dot tag.
- `resolve_realm_rejects_bare_prefix_extension`: matching is dot-anchored, so `notmit.edu` and `sub.notmit.edu` don't match `mit.edu`, while `mit.edu` and `sub.mit.edu` do.

New test in `tests/client/session_cache.rs`:

- `service_realm_resolution_folds_dns_case`: the client path. With `default_realm = CLIENT.REALM` and `.example.com = PARTNER.REALM`, a service ticket cached for `HTTP/Host.Example.COM@PARTNER.REALM` is found by a realm-less lookup for `HTTP/Host.Example.COM`. Both principals are built with `Principal::new`, so the test doesn't depend on the host-case fold in `fix/host-case-spn`.

Fail-before evidence:

- With `src/config.rs` restored to `6f4abc9`, four tests fail: `resolve_realm_folds_dns_case`, `resolve_realm_applies_bare_domain_tags_to_subdomains`, `resolve_realm_rejects_bare_prefix_extension` (its `sub.mit.edu` row) and `service_realm_resolution_folds_dns_case`.
- The dot-tag and precedence tests pass on the old code too. They're controls that pin the behaviour the fix keeps.
- The `notmit.edu` rows are a control as well. With the dot-anchored walk replaced by a plain `ends_with` string-suffix match, `resolve_realm_rejects_bare_prefix_extension` fails: `notmit.edu` resolves to `ATHENA.MIT.EDU`.

## Verification

All runs used stable Rust 1.99.1 on the branch tip.

- `cargo test --all-features --no-fail-fast`: 33 test targets ok, 0 failed.
- `cargo fmt --all -- --check`: clean.
- `cargo clippy --all-targets --all-features -- -D warnings -A clippy::chunks_exact_to_as_chunks`: the only diagnostics are the 3 `clippy::byte_char_slices` errors in `tests/kadmin.rs` that already fail on `main`. CI on `main` stays red on `clippy::chunks_exact_to_as_chunks` and `clippy::byte_char_slices` until PR #15 lands. This change adds no diagnostic.

## Compatibility

- No signature change.
- Behaviour:
  - hosts with upper-case letters now find their lower-cased mapping;
  - strict subdomains of a bare-tagged domain now resolve to that tag's realm instead of a less specific match or the client realm.
- Configurations that write both spellings (like the existing test fixtures) and leading-dot-only deployments resolve as before.

## Series and merge order

- `src/config.rs`, `tests/config.rs`: `fix/enctype-policy` first, then this PR.
  - `src/config.rs` merges cleanly, but both PRs append tests at the end of `tests/config.rs`, so they conflict textually (checked with `git merge-tree` on `6f4abc9`). I'll rebase this PR once `fix/enctype-policy` lands.
- `tests/client/session_cache.rs` also gets new tests from `fix/host-case-spn` and `fix/client-renewal-series`. Those merge cleanly in any order.
- Related: `fix/host-case-spn` folds the same DNS case when the service principal is built. Each PR stands on its own.

## Notes

- One `String` is allocated per lookup for the fold. That's negligible next to a KDC round trip.
