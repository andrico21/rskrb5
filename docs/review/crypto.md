# Cryptography review dispositions

This lane is in progress. Only the completed row below has a disposition;
the remaining items are not claimed fixed or dismissed.
Full commands and red runs are in `task-31-rskrb5-ng-own-way.log`.
Commit subjects identify their item without self-referential hashes.

| ID | Status | Tests and commit | Behaviour change for CHANGELOG | Dismissal evidence |
|---|---|---|---|---|
| RSK-11BF294C | fixed | `rc4_checksum_matches_independent_high_usage_oracle`, `rc4_rejects_ciphertext_under_previously_colliding_usage`; commit subject suffix `(RSK-11BF294C)` | RC4-HMAC checksums and message keys encode the compatibility-mapped usage as four-byte little-endian (RFC 4757 §3). High usages no longer alias through truncated varints. Low-usage remapping is preserved. | N/A |

## Remaining work

- RSK-F240C18F: password work-factor cap, including common client derivation.
- RSK-B51C2C85: verify existing n-fold arithmetic repair on i686; add CI coverage.
- RSK-CE4ACA12: authenticate AES-SHA2 ciphertext before decrypting.
- RSK-8F3B02EE: reject oversized RFC 3961 derivation constants.
- RSK-FA2BF25E: allow empty RFC 8009 PRF context.
- RSK-911A31CB: measure/probe the already hoisted CBC cipher setup.
- RSK-DEF6C438 / upstream issue #6: zeroizing secret scratch owners.

Full acceptance and scratch failure QA remain outstanding.
