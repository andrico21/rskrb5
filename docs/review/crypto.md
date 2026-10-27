# Cryptography review dispositions

This lane is in progress. Only the completed rows below have a disposition;
the remaining items are not claimed fixed or dismissed.
Full commands and red runs are in `task-31-rskrb5-ng-own-way.log`.
Commit subjects identify their item without self-referential hashes.

| ID | Status | Tests and commit | Behaviour change for CHANGELOG | Dismissal evidence |
|---|---|---|---|---|
| RSK-11BF294C | fixed | `rc4_checksum_matches_independent_high_usage_oracle`, `rc4_rejects_ciphertext_under_previously_colliding_usage`; commit subject suffix `(RSK-11BF294C)` | RC4-HMAC checksums and message keys encode the compatibility-mapped usage as four-byte little-endian (RFC 4757 §3). High usages no longer alias through truncated varints. Low-usage remapping is preserved. | N/A |
| RSK-FA2BF25E | fixed | `sha256_prf_accepts_empty_context`, `sha384_prf_accepts_empty_context`, `sha2_prf_matches_published_nonempty_vectors`; commit subject suffix `(RSK-FA2BF25E)` | AES-SHA2 PRF (`derive_random`) accepts empty application contexts per RFC 8009 §§3/5. Empty outputs match independent HMAC framing; Appendix A nonempty outputs are unchanged. Signatures and RFC 3961 constant checks are unchanged. | N/A |
| RSK-F240C18F / lead `s2kparams_to_iterations:unauthenticated-pbkdf2-work` | fixed | `s2kparams_rejects_excessive_iterations`, `s2kparams_accepts_iteration_policy_boundaries`, `aes_password_derivation_rejects_excessive_iterations`; commit subject suffix `(RSK-F240C18F)` | AES string-to-key and client password reply-key derivation reject iteration hints above the inclusive 2^24 local ceiling with `Crypto::IterationCountTooHigh { maximum, actual }` before PBKDF2. Counts are never clamped. Trusted low-level PBKDF2 is unchanged. | N/A |
| RSK-B51C2C85 / lead `nfold:lcm-usize-overflow` | fixed (prior repair `0fdca8f`) | `des3_large_salt_preserves_password_dependence`; coverage `e54e845`, disposition commit subject suffix `(RSK-B51C2C85)` | None in this lane: prior code already avoids the overflowing LCM product by dividing byte lengths before checked capacity multiplication. The i686 CI job now also runs `crypto_des3`. | Native i686 evidence obtained locally in one disposable Debian 12 Podman container with gcc-multilib and Rust 1.99.1: restoring only historical multiply-before-divide arithmetic panics on overflow (exit 101); restored current code passes all six DES3 tests, including the reported 3,195,661-byte fold oracle and password-dependence probe (exit 0). Default test-profile overflow checks enabled. Converge still verifies the CI i686 job runs the new test green. |
| RSK-CE4ACA12 | fixed | `crypto::tests::sha2_rejects_bad_tag_before_any_decryption`, `crypto::tests::sha2_valid_tag_reaches_decryption`; commit subject suffix `(RSK-CE4ACA12)` | AES-SHA2 message decryption verifies the ciphertext HMAC before deriving Ke or entering AES decryption (RFC 8009 §5). Invalid tags produce no unauthenticated plaintext scratch. SHA1/DES3 ordering and valid ciphertext outputs are unchanged. | N/A |
| RSK-8F3B02EE | fixed | `aes_rfc3961_rejects_oversized_constants`, `des3_rfc3961_rejects_oversized_constants`, `rfc3961_constant_boundaries_preserve_other_primitives`; commit subject suffix `(RSK-8F3B02EE)` | AES-SHA1 and DES3 DR/DK reject constants longer than 16 and 8 bytes respectively, with `Crypto::DerivationConstantTooLong { maximum, actual }` before n-folding. Exact-block constants remain valid; empty constants retain `EmptyUsage`. Generic n-fold and SHA2 PRF contexts/labels are unchanged. | N/A |
| RSK-911A31CB | dismissed | `crypto::tests::aes_cipher_setup_is_once_per_raw_operation`, `crypto::tests::des3_cipher_setup_is_once_per_raw_operation`; commit subject suffix `(RSK-911A31CB)` | None: no production optimization in this lane. | Prior repair `0fdca8f` moved cipher construction outside block loops. Test-only thread-local instrumentation of the real `keyed_cipher` boundary measures exactly one setup for each raw AES128/AES256 encrypt/decrypt at 16/32/33/4096/4097 bytes and each DES3 encrypt/decrypt at 8/16/4096 bytes. CTS-tail paths share the same schedule. Existing AES/DES3 vectors pass unchanged. This measures constructor work, not elapsed-time throughput; no speedup claim is made. |
| RSK-DEF6C438 / upstream issue #6 | fixed | `crypto::tests::password_derivation_erases_scratch`, `crypto::tests::integrity_failure_erases_scratch`; commit subject suffix `(RSK-DEF6C438)` | Internal password encodings, PBKDF2/DR intermediates, derived message keys, decrypted message buffers, CBC block arrays, CTS temporary plaintext, n-fold replication/replacement buffers and HMAC padded-key/digest copies now have value-attached erasure or explicit live-byte erasure. Public return types and crypto outputs are unchanged. | N/A |

## Secret ownership boundary

`SecretScratch` owns a `Zeroizing<Vec<u8>>` in both production and tests. Its
drop erases the live slice; `Zeroizing` subsequently erases the Vec's allocation,
including spare capacity. Test-only thread-local observation checks the live
slice before release; it never inspects freed storage or intercepts an allocator.
The red proof runs committed production code with only the new tests attached in
a scratch copy: both derivation and integrity-failure cleanup assertions fail.

The audit includes all four families' string-to-key and message-decryption paths,
DR feedback blocks and discarded IV owners, raw AES/DES3 plaintext/block scratch,
n-fold replication and previous accumulator owners, and explicit erasure of HMAC
key blocks and digest copies. Truncated KDF/MAC and CTS plaintext tails are erased
before truncation. Caller-owned returns retain their existing `Vec<u8>` API and
transfer cleanup responsibility to the caller; `SecretScratch::into_vec` moves
the allocation rather than leaving an extra secret copy behind.

Residuals are explicit: borrowed inputs, caller-owned returned values,
compiler/register/spill and scalar/by-value copies, allocator reallocation history,
and dependency-owned state are not claimed erased. AES 0.9.3 has optional zeroize
support; DES3 0.9.0, RC4 0.2.0, HMAC 0.13.0 and the hash crates also expose
optional zeroize features. The manifest does not enable them explicitly; this
change neither alters dependencies nor claims erasure of their schedules/hash
states or PBKDF2's internal dependency buffers. Closing that residual requires
an independently reviewed dependency-feature/state audit. Abort skips destructors.

## Remaining work

Final acceptance only: full STRICT, WIN-CLIPPY, FULL-TEST, DOCTEST, DOCS,
NIGHTLY-FMT, GATES and exact review-ID coverage. Full STRICT has not yet run.

Full acceptance remains outstanding. Scratch reversal proofs for the RC4 usage
and empty SHA2 PRF context fixes are recorded in the evidence log: each regression
fails when only its production fix is reverted, and the fix is then restored.
