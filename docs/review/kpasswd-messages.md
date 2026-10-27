# Kpasswd and message review dispositions

This lane is incomplete. Only the row below is claimed fixed; the remaining
todo 34 items have not yet been fixed or dismissed. Commit subjects identify
their atomic item without self-referential hashes. Full commands, red output
and exit codes are in `task-34-rskrb5-ng-own-way.log` in the execution evidence.

| ID | Status | Tests and commit | Behaviour change for CHANGELOG | Dismissal evidence |
| --- | --- | --- | --- | --- |
| RSK-A5F7D975 | fixed | `checksum_matches_whole_message_oracle`, `verifies_independent_whole_message_checksum`; commit subject suffix `(RSK-A5F7D975)` | Generate and verify usage-15 checksums over the entire DER KRB-SAFE with checksum type zero and an empty checksum value, per RFC 4120 §5.6.1, instead of body-only DER. | N/A |

## Checksum contract

The public body-based checksum function constructs a version-5, message-type-20
envelope. Verification uses the supplied envelope's version and message type,
so these fields participate in the MAC rather than being silently normalized.
The placeholder encoding is shared by generation and verification; the tests
independently construct and encode the normative peer envelope without calling
the builder. Existing round-trip, tampering and key/type mismatch tests remain.
No public signature or error variant changes. Only owned message clones are
used to replace the checksum; no caller message is mutated.

## Remaining work

- Bare RFC 3244 errors and explicit responder encoding profile.
- Contextual KRB-PRIV freshness, sequence and address validation.
- Complete-message trailing-byte rejection.
- Shared Microseconds and whole-second KerberosTime constraints.
- Password plaintext ownership, erasure and redaction.
- Cancellation and unknown-outcome contracts for mutation and wrappers.

Full final acceptance (fresh-target STRICT, WIN-CLIPPY, FULL-TEST, DOCTEST,
stable/nightly DOCS, NIGHTLY-FMT, GATES and exact review-ID coverage) is deferred
until all items are complete. No full-todo acceptance is claimed here.
