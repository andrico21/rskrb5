# SPNEGO and GSS review disposition

Each row's commit is the commit with the ID in its subject; this avoids self-referential hashes.
Full red runs and acceptance output: `task-29-rskrb5-ng-own-way.log` in the execution evidence.

| ID | Status | Tests and commit | Behaviour change for CHANGELOG | Dismissal evidence |
| --- | --- | --- | --- | --- |
| RSK-622F4664 | fixed | `initiator_rejects_delegation_without_credentials`, `initiator_wrappers_reject_delegation`, `initiator_preserves_nondelegating_flag_masks`, `authenticator_checksum_delegation_prefix_is_mask_independent`; commit `(RSK-622F4664)` | Checked initiation rejects DELEG in split or combined masks with `DelegationRequiresCredential`; the raw checksum helper returns a consistent 24-byte prefix without fabricated delegation fields. | N/A |
| RSK-2A906A3A | fixed | `sealed_des3_wrap_roundtrips_all_payload_residues`, `sealed_des3_wrap_completes_manual_filler`, `sealed_des3_wrap_rejects_filler_overflow`; commit `(RSK-2A906A3A)` | Sealed DES3 Wrap derives sufficient pre-header filler and EC, preserves sufficient explicit filler and application trailing zeroes, and rejects EC overflow. Generic DES3 decryption remains padding-preserving. | N/A |
| RSK-84FA90AE | fixed | `unsealed_wrap_applies_rrc_on_decode_and_encode`; commit `(RSK-84FA90AE)` | Unsealed Wrap tokens apply RRC modulo body length on encoding and decoding. | N/A |
| RSK-C4BE57A0 | fixed | `acceptor_rejects_nonfirst_kerberos`, `acceptor_rejects_unverified_mech_list_mic`, `acceptor_rejects_stateless_continuation`, `acceptor_preserves_selected_kerberos_oid`, `acceptor_rejects_unsupported_mechanisms`, `acceptor_rejects_optimistic_oid_mismatch`, `acceptor_accepts_raw_ms_kerberos`, `acceptor_rejection_preserves_replay_cache`; commit `(RSK-C4BE57A0)` | Acceptor scope: accept only first-choice Kerberos OIDs; preserve selection in replies; fail closed on mechanism switches, supplied MICs and stateless continuations. | N/A |
| RSK-FAF64A85 / run-2 `src/spnego.rs:accept_sec_context_header:mandatory-gss-authenticator-fields` | fixed | `gss_authenticator_requires_checksum`, `gss_authenticator_requires_sequence`, `gss_authenticator_rejects_wrong_checksum_type`, `gss_authenticator_rejects_short_checksum`, `gss_authenticator_rejects_invalid_binding_length`, `gss_authenticator_rejects_malformed_delegation`, `gss_authenticator_rejection_preserves_generic_validation`, `gss_authenticator_deterministic_builder_requires_sequence`; commit `(RSK-FAF64A85)` | GSS acceptance checks RFC 4121 checksum type/framing and requires a sequence before replay insertion; deterministic initiation rejects an omitted sequence. Generic Kerberos validation is unchanged. | N/A |

## RSK-FAF64A85: GSS boundary validation

RFC 4121 section 4.1.1 requires checksum type `0x8003`, a sixteen-byte Bnd
with little-endian length, context flags and an authenticator sequence number.
Delegation framing requires option 1, the declared credential bytes and a
decodable KRB-CRED envelope. Credential import/decryption is not implemented by
this acceptor; fixing the delegation **builder** remains the separate
RSK-622F4664 item.

The service validator invokes an internal GSS check after decryption, identity
and clock checks, but before replay insertion. Ordinary AP-REQ validation does
not run that check. No second decryption or public result-field change is needed.
The API supplies no channel bindings, so it ignores Bnd content as permitted by
section 4.1.1.2; it also ignores unknown flags and trailing extensions. Positive
controls cover these cases, zero and maximum sequence numbers, and a framed
delegation envelope. Additional tests cover raw Kerberos headers and corrupted
authenticator ciphertext. No principal-forgery or channel-binding enforcement
claim is made.

## RSK-C4BE57A0: one-shot acceptor limitation

RFC 4178 sections 4-5 bind the optimistic token to the first offered mechanism.
Only `1.2.840.113554.1.2.2` and `1.2.840.48018.1.2.2` are accepted. Unsupported
trailing offers are not selected and do not prevent first-choice Kerberos use.
The token OID must match the first offer exactly; replies retain that OID.

The current API has no retained original mechanism-list transcript, negotiation
phase or established GSS sequence state for a MIC exchange and its final reply.
It therefore returns `error::Spnego::NegotiationRequiresState` for non-first
Kerberos or any continuation, and `MechListMicRequiresState` for any supplied
MIC (including empty or apparently valid MICs). It does not claim to verify
MICs. These errors occur before AP-REQ validation and replay-cache insertion.
Unsupported mechanisms return `UnsupportedMechanism`; mismatched optimistic
token OIDs return `OptimisticMechanismMismatch`.

This session addresses the acceptor only, as requested. The original review's
initiator/HTTP response-classifier observations remain outside this change;
this row is not a claim that those client-side paths have been repaired.
