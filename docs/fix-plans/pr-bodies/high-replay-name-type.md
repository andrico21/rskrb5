# service: canonicalize the AP-REQ replay identity over the advisory name-type

- Target: `clelange/rskrb5` `main` (`6f4abc9`), branch `fix/service-replay-name-type`.
- Commits:
  - `5148851` service: canonicalize the AP-REQ replay identity over the advisory name-type
  - `b7fb459` service: reject an authenticator re-presented under a rewritten ticket sname
- Distinct from PR #19 (TCP transport) and PR #15 (clippy drift). PR #21 also edits `src/service.rs`; see "Series and merge order".

## Problem

The AP-REQ replay key was built from whole `Principal` values, and their derived `Eq`/`Hash` include `name_type`. The ticket's outer `sname`, that advisory field included, is cleartext. The ticket ciphertext doesn't cover it (`decrypt_ticket_enc_part` decrypts only `enc_part.cipher`), and the keytab lookup ignores `name_type`, so it still selects the same service key. A captured AP-REQ with a one-byte name-type edit therefore counted as a new presentation, and its authenticator could be replayed inside the clock-skew window.

The same gap exists for the service name itself. When a keytab holds several SPN aliases that share one key (common in AD-style multi-SPN keytabs) and no `with_keytab_principal` override is set, the replay identity follows the ticket's cleartext `sname` components. Rewriting the `sname` to another alias gives the same authenticator a fresh replay identity, and the ticket still decrypts.

RFC basis:

- RFC 4120 section 3.2.3: the replay cache stores "at least the server name, along with the client name, time, and microsecond fields".
- RFC 4120 section 6.2: the name-type "SHOULD be treated only as a hint ... It is not significant when checking for equivalence. Principal names that differ only in the name-type identify the same principal."

## Change

- Build both replay-key components without `name_type` (`5148851`).
- Bind the service component to the key identity that accepted the ticket: the configured `keytab_principal` override when one is set, otherwise the ticket's own components (`5148851`).
- Keep that RFC 4120 key, and add a second index on the authenticator itself (`b7fb459`):
  - `validate_ap_req` computes SHA-256 over the authenticator ciphertext as received (`ap_req.authenticator.cipher`) and nothing else. The unauthenticated `etype`/`kvno` fields stay out of the digest, so rewriting them can't produce a fresh one.
  - `ReplayCache` keeps the digests next to its entries. A presentation is a replay when either its RFC key or its authenticator digest was already seen. The shared replay cache forwards the digest the same way.
  - Both indexes are written in `record_replay`, which still runs last, so a request that fails validation records nothing.
  - `clear()` and `clear_older_than_at` prune both indexes with the same age rule. `len()` and `is_empty()` keep counting the RFC entries only, and their docs say so.

The authenticator is encrypted under the ticket session key, so re-presenting the same authenticator ciphertext under any rewritten cleartext ticket field is now a replay.

## Tests

New tests in `tests/service.rs`:

- `replay_identity_ignores_the_ticket_name_type`: a name-type-only mutation of the fixture AP-REQ is `Error::Replay`.
- `replay_identity_follows_the_accepted_key_identity`: an alias `sname` accepted through `with_keytab_principal` shares its replay identity with the ticket `sname`.
- `replay_identity_survives_a_shared_key_sname_alias`: the keytab holds `HTTP/...` plus an `HTTP/alias.test.gokrb5` entry with the same key, there's no override, and the alias-`sname` re-presentation of an accepted AP-REQ is `Error::Replay`.
- `shared_replay_cache_rejects_a_shared_key_sname_alias`: the same flow through the shared replay cache.
- `clearing_old_entries_also_forgets_authenticator_digests`: after `clear_older_than_at`, the alias presentation is accepted again, so the digest index ages out with the entries.

Fail-before evidence:

- With `src/service.rs` restored to `6f4abc9`, these four fail: `replay_identity_ignores_the_ticket_name_type`, `replay_identity_follows_the_accepted_key_identity`, `replay_identity_survives_a_shared_key_sname_alias` and `shared_replay_cache_rejects_a_shared_key_sname_alias`.
- With `src/service.rs` restored to `5148851` (the first commit only), both shared-key alias tests fail: the alias presentation returns `Ok(ValidatedApReq { service: HTTP/alias.test.gokrb5, .. })` instead of `Error::Replay`.
- `clearing_old_entries_also_forgets_authenticator_digests` passes on the old code too. It's the expiry control for the new index, not a regression test.

The existing `detects_ap_req_replay` and `clears_old_replay_cache_entries` stay unchanged and green.

## Verification

All runs used stable Rust 1.99.1 on the branch tip.

- `cargo test --all-features --test service`: 24 passed.
- `cargo test --all-features --no-fail-fast`: 33 test targets ok, 0 failed.
- `cargo fmt --all -- --check`: clean.
- `cargo clippy --all-targets --all-features -- -D warnings -A clippy::chunks_exact_to_as_chunks`: the only diagnostics are the 3 `clippy::byte_char_slices` errors in `tests/kadmin.rs` that already fail on `main`. CI on `main` stays red on `clippy::chunks_exact_to_as_chunks` and `clippy::byte_char_slices` until PR #15 lands. This change adds no diagnostic.

## Compatibility

- Wire-compatible, no public API change. `ReplayKey`'s fields and every public signature are unchanged. The new `insert` parameter is on private methods.
- Replay classification changes in two cases: presentations that differ only in the advisory name-type, and an authenticator re-presented under a rewritten cleartext ticket field (for example a shared-key `sname` alias). Both are now rejected.
- Memory: the replay cache keeps one extra 32-byte digest and timestamp per accepted AP-REQ, pruned together with the entries.
- `ValidatedApReq.service`/`.client` still expose the name type. A separate companion PR (#21) binds the client realm to the ticket.

## Series and merge order

- `src/service.rs`, `tests/service.rs`: this PR (#20), then #21, then `fix/config-clockskew-handoff`.
  - #20 and #21 both edit `validate_ap_req` and append tests to `tests/service.rs`, so they conflict textually. Whichever merges second needs a rebase, and I'll do it.
  - `fix/config-clockskew-handoff` touches only the `Config` constructors and merges cleanly on top of either. It goes last because its tests run through `validate_ap_req`.
- No other open PR touches these files.

## Notes

- The digest index is an addition to the RFC 4120 section 3.2.3 key, not a replacement. RFC 4120 lists the minimum fields a replay cache must store, and the extra index only rejects presentations the RFC key could miss.
