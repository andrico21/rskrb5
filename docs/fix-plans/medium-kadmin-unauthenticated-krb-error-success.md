# Kadmin: reject kpasswd success from an unauthenticated KRB-ERROR

- Severity: medium (likelihood medium / impact medium / confidence high) — fingerprint `rskrb5/kadmin/Reply::decrypt_result/unauthenticated-krb-error-success`
- Audit: run-2 findings.json record (`verdict: confirmed`) + `agents/vfy-rskrb5-kadmin-reply-decryp/artifacts/vfy-kadmin-probe2.log:188-193`
- Status: planned; not implemented in the fork; no upstream PR yet

## Problem

A network peer able to supply the kpasswd reply for an outstanding password
change can make the high-level client report success and, for its own
password-backed principal, replace its stored password credential without
possessing any key. `Reply::parse` routes a zero payload length into the
KRB-ERROR branch and parses `e_data` into a `ChangePasswordResult` without
excluding result code 0; `verify_kpasswd_ap_rep` returns `Ok(None)` for
KRB-ERROR replies, so AP-REP authentication is skipped; `Reply::decrypt_result`
returns that pre-parsed result before the supplied key is consulted; and
`ensure_success` accepts code 0. Success is therefore decided without
authenticated provenance.

## Root cause (verified against upstream 6f4abc9)

- `src/kadmin.rs:394` — `pub fn parse(bytes: &[u8]) -> Result<Self, Error>` — `if frame.payload_length == 0` (`:400`) selects the KRB-ERROR branch.
- `src/kadmin.rs:406` — `.map(|data| ChangePasswordResult::parse(data.as_ref()))` — `e_data` becomes `Reply.result` with no exclusion of `KPASSWD_SUCCESS` and no keyed check; `krb_error` is set and `result` is stored.
- `src/client/kpasswd.rs:202` — `if reply.is_krb_error() { return Ok(None); }` — AP-REP validation, session-key decryption, and the authenticator timestamp/cusec echo check (`:206-231`) are all skipped for error replies.
- `src/kadmin.rs:448` — `pub fn decrypt_result(&self, key: &EncryptionKey)` — `if let Some(result) = &self.result { return Ok(result.clone()); }` (`:449-450`) returns the unauthenticated value before `key` or `krb_priv` is read (`:456`).
- `src/kadmin.rs:546,551` — `is_success` compares `code == KPASSWD_SUCCESS`; `ensure_success` returns `Ok(())` for it.
- `src/client/kpasswd.rs:279` — `change_password_for_with_options` calls `result.ensure_success()` (`:343`) and then overwrites the stored credential when `update_password_credential` is set (`:292-293`, `:345-348`).

## Evidence (from the audit)

- `agents/vfy-rskrb5-kadmin-reply-decryp/artifacts/vfy-kadmin-probe2.log:191` — `kadmin_reply_krb_error code_zero_accepted_without_reply_key=true ap_rep_provenance=false`; the framed unsigned KRB-ERROR code-zero result is accepted with an unrelated AES-256 key.
- `.../vfy-kadmin-probe2.log:188-189` — the loopback exchange returned `Ok(code 0)` with `server_supplied_ap_rep=false server_supplied_krb_priv=false`, and the second exchange succeeded only against a mock KDC demanding the new-password-derived key (`local_credential_replaced=true`).
- `.../vfy-kadmin-probe2.log:192-193` — controls: result code 3 stays a failure (`nonzero_error_code_control rejected=true code=3`) and a wrong-key AP-REP reply is rejected.
- `.../vfy-kadmin-probe2.log:203` — the target's unmodified `tokio_client_changes_password_updates_password_credentials` passes while answering both kpasswd exchanges with an unsigned KRB-ERROR carrying `KPASSWD_SUCCESS`.
- `tests/client/password_change.rs:981` — inside `tokio_client_changes_password_updates_password_credentials` (`:904`) the mock reply is literally `kpasswd_reply_frame(0, &kpasswd_result_krb_error(KPASSWD_SUCCESS, "password changed"))`, a source-visible unsigned-success fixture.
- Payload: framed reply `[u16 length][00 01 version][00 00 ap_rep_length][DER KRB-ERROR]` whose `e_data` is `00 00` plus text — the same frame produced by `kpasswd_reply_frame` (`tests/client.rs:1140`) and `kpasswd_result_krb_error` (`tests/client.rs:1153`).

## Proposed fix

1. In `Reply::decrypt_result` (`src/kadmin.rs:448`), reject a `KPASSWD_SUCCESS`
   result whose provenance is the unauthenticated KRB-ERROR branch. This single
   site covers the high-level flow and the library-level
   `exchange_kpasswd_result` / `exchange_kpasswd_result_with_config`
   (`src/client/transport.rs:398,417`). Add an `Error::UnauthenticatedSuccess`
   variant to `kadmin::Error`.
2. Defense in depth in `change_password_for_with_options`: treat the change as
   successful only when `verify_kpasswd_ap_rep` returned `Some(..)`; require
   `verified.is_some()` before `ensure_success`/credential replacement.
3. Keep non-zero result codes (server failure text) returning their
   `PasswordChangeFailed` error unchanged.

```rust
    /// Return the password-change result, decrypting KRB-PRIV when needed.
    pub fn decrypt_result(&self, key: &EncryptionKey) -> Result<ChangePasswordResult, Error> {
        if let Some(result) = &self.result {
            // `result` is populated only from the unauthenticated KRB-ERROR e-data
            // branch: a SUCCESS code there is not proof that the change happened.
            if result.is_success() {
                return Err(Error::UnauthenticatedSuccess); // new variant to add
            }
            return Ok(result.clone());
        }
        if self.krb_error.is_some() {
            return Err(Error::MissingReplyResult);
        }
        let krb_priv = self.krb_priv.as_ref().ok_or(Error::MissingKrbPriv)?;
        let enc_part = decrypt_krb_priv_enc_part(krb_priv, key)?;
        ChangePasswordResult::parse(enc_part.user_data.as_ref())
    }
```

```rust
        let verified = verify_kpasswd_ap_rep(&reply, &request)?;
        let result_key = verified
            .as_ref()
            .and_then(|metadata| metadata.subkey.as_ref())
            .unwrap_or(&request.reply_key);
        let result = reply.decrypt_result(result_key)?;
        if result.is_success() && verified.is_none() {
            // SUCCESS without an authenticated AP-REP has no keyed provenance.
            return Err(Error::MissingKpasswdApRep);
        }
        result.ensure_success()?;
```

## Regression tests

- `tests/kadmin.rs::rejects_unsigned_krb_error_success_result` — a framed code-0 KRB-ERROR `Reply` must make `decrypt_result` return `Error::UnauthenticatedSuccess` even with an unrelated key (fails before the change).
- `tests/kadmin.rs::keeps_nonzero_krb_error_result` — adjust `kpasswd_reply_decrypt_result_returns_krb_error_result` (`tests/kadmin.rs:685`) so a code-3 error still parses and returns its failure result.
- `tests/client/password_change.rs::tokio_client_rejects_unsigned_kpasswd_success` — the mock kpasswd returning the unsigned code-0 frame must make `change_password_with_options` fail and must not rotate `self.credentials`; an AP-REP-authenticated success (existing `kpasswd_reply_with_ap_rep`, `tests/client.rs:456`) still succeeds.
- Update `tokio_client_changes_password_updates_password_credentials` (`tests/client/password_change.rs:904`) to answer with an authenticated AP-REP reply, since the unsigned-success fixture it currently uses becomes an error.

## Verification

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --test kadmin
cargo test --all-features --test client
```

## Compatibility / notes

- Behavioural break for callers that relied on a bare KRB-ERROR code-0 being
  reported as success; this is the security-relevant fix and should be called
  out in the release note. Non-zero error results and AP-REP successes are
  unchanged.
- Fork delta: the fork's `ChangePasswordResult` carries an extra
  `text_raw: Vec<u8>` field and `Error::PasswordChangeFailed` gained `text_raw`
  (fork `src/kadmin.rs:535,555` vs upstream `:533,551`). The fix sketch above is
  fork-accurate; the guard only reads `is_success()`/`code`, so the extra field
  is unaffected.
- Neither in-flight HIGH fix touches `src/kadmin.rs` or `src/client/kpasswd.rs`
  (both are in `src/service.rs`).

## Upstream route

- Fork-only first, then a PR against `clelange/rskrb5`. Independent of the other
  medium plans; the `Error::UnauthenticatedSuccess` variant is new and does not
  collide with any proposed error name elsewhere.

## Risks / open questions

- Requires an active network position able to answer/replace the kpasswd reply
  (on-path, spoofed UDP, or a rogue endpoint from configuration/DNS SRV); no key
  material is needed. The condition is stated, not modelled against a live KDC.
- `verify_kpasswd_ap_rep` still returns `Ok(None)` for KRB-ERROR replies by
  design (their error text must remain usable), so the guard must live in
  `decrypt_result` and in the success check, not in
  `verify_kpasswd_ap_rep` itself.
- Confirm no in-tree caller depends on `decrypt_result` returning a code-0
  result from a KRB-ERROR (grep shows the only success consumer is
  `change_password_for_with_options`; the `exchange_kpasswd_result*` helpers
  return the result directly and are covered by the same guard).