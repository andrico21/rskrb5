# client: fold the DNS host component in host-based service principals

- Target: `clelange/rskrb5` `main` (`6f4abc9`), branch `fix/host-case-spn`.
- Commits:
  - `50e5284` client: fold the DNS host component in host-based service principals
  - `5dd96f2` client: test that host-case variants share one cached service ticket

## Problem

`Principal::host_based_service` and `Principal::host_based_service_in_realm` copied the caller's host text verbatim into the two-component `KRB_NT_SRV_INST` name. So `HTTP/AUTH.CERN.CH` and `HTTP/auth.cern.ch` were two different principals for one DNS host. Every downstream consumer reads that component byte for byte:

- the `[domain_realm]` lookup missed an exact mapping (keys are stored lower-cased);
- the service-ticket cache stored a second entry per spelling;
- the TGS-REQ asked the KDC for a non-canonical SPN, which a case-sensitive principal store (MIT krb5) doesn't match against the registered lower-case service.

The documented HTTP initiators (`authorization_header_for_host`, `authorization_context_for_host`) pass the caller's host straight in, so a URL host with an upper-case letter was enough to trigger this.

RFC basis: RFC 4120 section 6.2.1 requires the host name in a host-based service name to be lower-case when it isn't case sensitive, as with Internet domain names. DNS names compare case-insensitively (RFC 4343).

## Change

- The shared helper `host_based_service_principal` lower-cases the host component with `to_ascii_lowercase()`. Both public constructors go through it.
- The service component, the realm, `Principal::new` and the explicit parser `Principal::parse_service` keep their byte-exact behaviour. Non-ASCII host text passes through unchanged.

## Tests

New tests:

- `tests/client_principal.rs::host_based_service_folds_dns_host_case`: upper- and mixed-case hosts become `["HTTP", "auth.cern.ch"]` through both constructors, and `parse_service("HTTP/AUTH.CERN.CH@CERN.CH")` still preserves the case.
- `tests/client_principal.rs::host_based_service_preserves_service_and_realm_case`: the service component and the realm keep their case.
- `tests/client/session_cache.rs::cached_service_ticket_identity_is_case_folded`: a `Tokio` with no network I/O caches a service ticket for `HTTP/auth.cern.ch@CERN.CH`. The lookup through `host_based_service_in_realm("HTTP", "AUTH.CERN.CH", "CERN.CH")` hits it, and caching a second session built from `"Auth.Cern.CH"` keeps `cached_service_ticket_count()` at 1.

Fail-before evidence: with `src/client/principal.rs` restored to `6f4abc9`, all three tests fail. In the cache test, the upper-case lookup returns `None`.

## Verification

All runs used stable Rust 1.99.1 on the branch tip.

- `cargo test --all-features --no-fail-fast`: 33 test targets ok, 0 failed.
- `cargo fmt --all -- --check`: clean.
- `cargo clippy --all-targets --all-features -- -D warnings -A clippy::chunks_exact_to_as_chunks`: the only diagnostics are the 3 `clippy::byte_char_slices` errors in `tests/kadmin.rs` that already fail on `main`. CI on `main` stays red on `clippy::chunks_exact_to_as_chunks` and `clippy::byte_char_slices` until PR #15 lands. This change adds no diagnostic.

## Compatibility

- No signature change.
- Behaviour: host-based SPNs now carry a lower-case DNS host. `host_based_service("HTTP", "AUTH.CERN.CH") == host_based_service("HTTP", "auth.cern.ch")` changes from `false` to `true`, which is the point of the fix. Code that relied on the exact host text in the SPN has to adapt; `Principal::new` and `parse_service` remain available for that.

## Series and merge order

- `src/client/principal.rs`: no other open PR touches it.
- `tests/client/session_cache.rs` also gets new tests from `fix/domain-realm-normalization` and `fix/client-renewal-series`. All three merge cleanly with each other in any order (checked with `git merge-tree` on `6f4abc9`).
- Related: `fix/domain-realm-normalization` folds the same DNS case on the lookup side (`Config::resolve_realm`). Each PR stands on its own.

## Notes

- AD's principal store compares case-insensitively and hides the KDC-side symptom, but the cache split and the `[domain_realm]` miss happen there too.
