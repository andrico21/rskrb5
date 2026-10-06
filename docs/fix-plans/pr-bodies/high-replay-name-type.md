# PR: service — canonicalize the AP-REQ replay identity over the advisory name-type

- Target: `clelange/rskrb5`, branch `fix/service-replay-name-type` (based on `6f4abc9`)
- Commit: `service: canonicalize the AP-REQ replay identity over the advisory name-type`
- Distinct from PR #19 (TCP transport) and PR #15 (clippy drift); no other open PR touches `src/service.rs`.

## Summary

The AP-REQ replay key was built from whole `Principal` values, whose derived
`Eq`/`Hash` includes `name_type` (`src/service.rs:23, 749-755`). The ticket's
outer `sname` - including that advisory field - is cleartext and is not covered
by the ticket ciphertext (`decrypt_ticket_enc_part` decrypts only
`enc_part.cipher`), while the keytab lookup ignores `name_type`
(`src/keytab.rs:314-333`) and selects the same service key. A captured AP-REQ
with a one-byte name-type edit therefore counted as a new presentation and its
authenticator could be replayed within the clock-skew window.

RFC 4120 section 3.2.3 keys the replay cache on the server name, the client
name, the time and the microseconds; section 6.2 states the name-type "SHOULD
be treated only as a hint ... It is not significant when checking for
equivalence. Principal names that differ only in the name-type identify the
same principal."

## Evidence

- Two independent reproductions on the same revision (run-1 and run-2 audits,
  sandboxed): `identical_replay=rejected name_type_only_replay=accepted
  ciphertexts_unchanged=true accepted_presentations=3 cache_len=3`, plus the
  override variant (`override_alias_replay=accepted
  alias_without_override=rejected`).
- RFC 4120 section 3.2.3 (cached): replay cache stores "at least the server
  name, along with the client name, time, and microsecond fields"; section 6.2
  (cached): the quoted equivalence rule above.

## Change

- Build both replay-key components without `name_type`.
- Bind the service component to the key identity that accepted the ticket: the
  configured `keytab_principal` override when one is set, otherwise the
  ticket's own components - aliases for the same service key are the same
  server principal for replay purposes.

## Tests

- `tests/service.rs::replay_identity_ignores_the_ticket_name_type` — a
  name-type-only mutation of the fixture AP-REQ is now `Error::Replay` (fails
  before the change).
- `tests/service.rs::replay_identity_follows_the_accepted_key_identity` — an
  alias sname accepted through `with_keytab_principal` shares its replay
  identity with the ticket sname (fails before the change).
- Existing replay tests unchanged and green; full suite green.

## Verification

- `cargo test --all-features --test service` → 21 passed; `cargo test
  --all-features --no-fail-fast` → all targets green.
- `cargo fmt --all -- --check` → clean. Clippy on the current `main` reports 7
  pre-existing `chunks_exact_to_as_chunks` errors (`src/crypto.rs`,
  `src/pac.rs`, Rust 1.99 drift fixed by PR #15); this change adds none.

## Compatibility

- Wire-compatible. Only replay classification changes for presentations that
  differ solely in the advisory name-type; the field itself remains exposed on
  `ValidatedApReq.service`/`.client` (a separate companion PR binds the client
  realm to the ticket).

## Notes

- Companion fix (separate PR): bind the authenticator client realm to the
  ticket realm. Both touch `validate_ap_req`; independent, either order.
