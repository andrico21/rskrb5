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

## Remaining work
- RSK-CE4ACA12: authenticate AES-SHA2 ciphertext before decrypting.
- RSK-8F3B02EE: reject oversized RFC 3961 derivation constants.
- RSK-911A31CB: measure/probe the already hoisted CBC cipher setup.
- RSK-DEF6C438 / upstream issue #6: zeroizing secret scratch owners.

Full acceptance remains outstanding. Scratch reversal proofs for the RC4 usage
and empty SHA2 PRF context fixes are recorded in the evidence log: each regression
fails when only its production fix is reverted, and the fix is then restored.
