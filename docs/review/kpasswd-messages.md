# Kpasswd and message review dispositions

This lane is incomplete. Only the row below is claimed fixed; the remaining
todo 34 items have not yet been fixed or dismissed. Commit subjects identify
their atomic item without self-referential hashes. Full commands, red output
and exit codes are in `task-34-rskrb5-ng-own-way.log` in the execution evidence.

| ID | Status | Tests and commit | Behaviour change for CHANGELOG | Dismissal evidence |
| --- | --- | --- | --- | --- |
| RSK-A5F7D975 | fixed | `checksum_matches_whole_message_oracle`, `verifies_independent_whole_message_checksum`; commit subject suffix `(RSK-A5F7D975)` | Generate and verify usage-15 checksums over the entire DER KRB-SAFE with checksum type zero and an empty checksum value, per RFC 4120 §5.6.1, instead of body-only DER. | N/A |
| RSK-3B6BA222 | fixed | `kpasswd_bare_error_roundtrips`, `kpasswd_bare_error_cannot_assert_success`; commit subject suffix `(RSK-3B6BA222)` | Accept standalone RFC 3244 application-30 errors before frame interpretation; preserve bare encoding using version 0xff80, while version-1 legacy errors remain framed. Both forms reject unauthenticated success when consuming the result. | N/A |
| RSK-789A6FBB | fixed | `kpasswd_rejects_invalid_protected_controls`, existing password mutation tests; commit subject suffix `(RSK-789A6FBB)` | High-level result consumption validates the verified AP-REP's server sequence, requires a complete timestamp/usec pair or negotiated sequence, rejects invalid microseconds/fractions and timestamps outside 300 seconds of the explicit request time. Sender addresses must be well-formed IPv4/IPv6; an explicit request recipient pins the peer, and any response recipient must match the request sender. | N/A |
| RSK-0C0007B7 | fixed | `kpasswd_rejects_complete_frame_suffix`, `whole_message_rejects_trailing_value`, `authenticator_rejects_nonzero_authenticated_suffix`, `raw_codec_retains_prefix_contract`; commit subject suffix `(RSK-0C0007B7)` | Complete AP/KDC/ticket/KRB message codecs require an empty DER remainder, including decrypted parts after intentional zero-padding handling. Kpasswd frames require exact declared length. Generic `messages::decode_der` remains a raw prefix codec. | N/A |
| RSK-6A673A85 | fixed | `protocol_time_rejects_out_of_domain_microseconds`, `protocol_time_rejects_fractional_kerberos_time`, `protocol_time_accepts_microsecond_boundaries`, `protocol_time_kpasswd_builder_rejects_invalid_scalars`; commit suffix `(RSK-6A673A85)` | Shared checked Microseconds/whole-second conversions reject invalid KRB-ERROR diagnostics, explicit kpasswd request scalars and kpasswd AP-REP time fields. Raw ASN.1 codecs remain raw; service validation retains its earlier stricter checks. | N/A |

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

- Password plaintext ownership, erasure and redaction.
- Cancellation and unknown-outcome contracts for mutation and wrappers.

Full final acceptance (fresh-target STRICT, WIN-CLIPPY, FULL-TEST, DOCTEST,
stable/nightly DOCS, NIGHTLY-FMT, GATES and exact review-ID coverage) is deferred
until all items are complete. No full-todo acceptance is claimed here.
