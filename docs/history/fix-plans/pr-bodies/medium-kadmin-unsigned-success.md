# kadmin: reject kpasswd success without authenticated provenance

- Target: `clelange/rskrb5` `main` (`6f4abc9`), branch `fix/kadmin-unsigned-success`.
- Commit: `a089831` kadmin: reject kpasswd success without authenticated provenance

## Problem

A network peer that can answer an outstanding kpasswd exchange could make the client report a successful password change without holding any key. For a password-backed client, that also replaced the stored password credential.

The path:

1. `Reply::parse` routes a zero `ap_rep_length` into the KRB-ERROR branch and parses `e_data` into a `ChangePasswordResult`. It doesn't exclude result code 0 (`KPASSWD_SUCCESS`).
2. `verify_kpasswd_ap_rep` returns `Ok(None)` for KRB-ERROR replies, so the AP-REP check, the session-key decryption and the authenticator `ctime`/`cusec` echo check are all skipped.
3. `Reply::decrypt_result` returned that pre-parsed result before it looked at the supplied key.
4. `ensure_success` accepted code 0, and `change_password_for_with_options` then overwrote the stored credential when `update_password_credential` was set.

Success was therefore decided by bytes nobody authenticated.

RFC basis: RFC 3244 section 2 returns the result of a processed request inside a KRB-PRIV that's protected with the key from the AP-REP exchange. A KRB-ERROR reply carries its result code in `e-data`, and nothing in it is bound to the client's keys. A success code is only meaningful when it arrives through the authenticated KRB-PRIV path.

## Change

- `Reply::decrypt_result` rejects a success result that came from the KRB-ERROR `e-data` branch (the only source of a pre-parsed result) with the new `rskrb5_ng::error::Kadmin::UnauthenticatedSuccess`. This single check covers the high-level client and the library-level `exchange_kpasswd_result*` helpers.
- `change_password_for_with_options` treats a success as authoritative only after a verified AP-REP. Otherwise it returns the existing `rskrb5_ng::error::Client::MissingKpasswdApRep`, before `ensure_success` and before any credential replacement.
- Non-zero result codes from a KRB-ERROR keep their `PasswordChangeFailed` behaviour, so the server's failure text still reaches the caller.

## Tests

New tests:

- `tests/kadmin.rs::kpasswd_reply_rejects_unsigned_krb_error_success_result`: a framed code-0 KRB-ERROR `Reply` makes `decrypt_result` fail, even with an unrelated key.
- `tests/client_transport.rs::tokio_transport_rejects_unauthenticated_kpasswd_success_result`: the transport-level exchange rejects the same reply.
- `tests/client/password_change.rs::tokio_client_rejects_unsigned_kpasswd_success`: a client password change against an unsigned code-0 reply fails and doesn't rotate the stored credential. Two consecutive attempts still authenticate under the old password.

The existing password-change mocks now answer with AP-REP-authenticated successes, built by a new `kpasswd_authenticated_success_reply` helper in `tests/client.rs`. Before, they used the unsigned code-0 KRB-ERROR as their success fixture. The old "unsigned success rotates credentials" coverage is replaced by the rejection test.

Fail-before evidence: with both new guards removed (the `UnauthenticatedSuccess` check in `Reply::decrypt_result` and the `verified.is_none()` check in `change_password_for_with_options`), all three new tests fail.

## Verification

All runs used stable Rust 1.99.1 on the branch tip.

- `cargo test --all-features --no-fail-fast`: 33 test targets ok, 0 failed.
- `cargo fmt --all -- --check`: clean.
- `cargo clippy --all-targets --all-features -- -D warnings -A clippy::chunks_exact_to_as_chunks`: the only diagnostics are the 3 `clippy::byte_char_slices` errors in `tests/kadmin.rs` that already fail on `main`. Clippy stops at that test crate, so a second run with `-A clippy::byte_char_slices` lints every target and is clean. CI on `main` stays red on `clippy::chunks_exact_to_as_chunks` and `clippy::byte_char_slices` until PR #15 lands. This change adds no diagnostic.

## Compatibility

- Breaking: `rskrb5_ng::error::Kadmin` gains the variant `UnauthenticatedSuccess`. The enum isn't `#[non_exhaustive]`, so exhaustive matches need a new arm.
- Behaviour: a bare KRB-ERROR that claims code 0 is now an error instead of a success. Callers that relied on it must authenticate the reply (AP-REP plus KRB-PRIV), which conforming kpasswd servers already do. AP-REP-authenticated successes and non-zero error results behave as before.
- Wire format unchanged.

## Series and merge order

- `src/kadmin.rs`: PR #18 ("Keep kpasswd result bytes as received"), then this PR. The two merge cleanly in either order (checked with `git merge-tree` on `6f4abc9`). Merging #18 first keeps this check on top of the final result representation.
- `tests/client_transport.rs` is also touched by #18 and #19. Both merge cleanly with this PR.

## Notes

- `verify_kpasswd_ap_rep` still returns `Ok(None)` for KRB-ERROR replies on purpose: their failure text must stay usable. That's why the checks live in `decrypt_result` and in the success path, not in `verify_kpasswd_ap_rep`.
- Exploiting the old behaviour needs a network position that can answer or replace the kpasswd reply (on-path, spoofed UDP, or a rogue endpoint from config or DNS SRV). No key material is needed.
