# PR: service — bind the accepted client identity to the ticket realm

- Target: `clelange/rskrb5`, branch `fix/service-authenticator-realm` (based on `6f4abc9`)
- Commit: `service: bind the accepted client identity to the ticket realm`
- Distinct from PR #19 (TCP transport) and from PR #15 (clippy drift); no other open PR touches `src/service.rs`.

## Summary

`ServiceValidator::validate_ap_req` compared only the ordered name components of
the ticket's client against the authenticator's, and `ValidatedApReq.client`
carried the authenticator-derived principal. RFC 4120 section 3.2.3 requires the
client **name and realm** of the KDC-encrypted ticket to match the
authenticator's same fields (KRB_AP_ERR_BADMATCH otherwise), so an accepted
AP-REQ could present an actor-chosen realm as the authenticated client identity
wherever an application consumes `client.realm` (realm-based authorization,
cross-realm trust mapping, audit identity).

## Evidence

- Source: `src/service.rs:418-424` decodes both principals and compared
  `components` only; `:449` returned the authenticator-derived principal;
  `ClientPrincipalMismatch` carried component names only.
- Reproduction (independent sandbox, twice, same revision): a fixture AP-REQ
  whose authenticator `crealm` is changed to `EVIL.VERIFIER.REALM` while the
  ticket stays `TEST.GOKRB5` validates with `accepted=true`,
  `ticket_unchanged=true`, components preserved; changing the components is
  rejected, and ciphertext tampering is rejected. The same observation was made
  in run-1 with `OTHER.DUMMY.REALM`.
- RFC 4120 section 3.2.3 (cached text): "The name and realm of the client from
  the ticket are compared against the same fields in the authenticator. If they
  don't match, the KRB_AP_ERR_BADMATCH error is returned".

## Change

- Compare `authenticator_client.realm != ticket_client.realm` in addition to the
  ordered components (byte-exact; realms are case-sensitive).
- Report both principals as `name@realm` in `ClientPrincipalMismatch` and update
  the field docs.
- Return the ticket-derived principal in `ValidatedApReq.client` (and document
  it), so no authenticator-supplied value reaches callers.

## Tests

- `tests/service.rs::rejects_authenticator_client_realm_mismatch` — realm-only
  mismatch rejected, error carries both `name@realm`s. Fails before the change.
- `tests/service.rs::returns_the_ticket_client_identity` — an authenticator with
  an advisory name-type difference is accepted, and the returned identity
  (including `name_type`) is the ticket's, cross-checked by decrypting the
  ticket. Fails before the change.
- Existing 19 service tests unchanged and green.

## Verification

- `cargo test --all-features --test service` → 21 passed.
- `cargo test --all-features --no-fail-fast` → all targets green.
- `cargo fmt --all -- --check` → clean. Clippy on the current `main` reports 7
  pre-existing `chunks_exact_to_as_chunks` errors (`src/crypto.rs`, `src/pac.rs`,
  Rust 1.99 drift fixed by PR #15); this change adds none.

## Compatibility

- Intentionally divergent from gokrb5 v8.4.4, whose `APReq.Verify` compares
  components only (`types.PrincipalName.Equal`) and whose service layer returns
  authenticator-derived credentials; recorded under "Intentional divergences"
  in `docs/gokrb5-parity.md`.
- Wire-compatible; only the accept/reject decision for realm-mismatched AP-REQs
  and the identity reported to callers change.

## Notes

- Companion fix (separate PR): canonicalize the AP-REQ replay identity over the
  advisory name-type (`src/service.rs` replay key). Both touch
  `validate_ap_req`; they are independent and can land in either order.
