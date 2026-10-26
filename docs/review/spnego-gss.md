# SPNEGO and GSS review disposition

Each row's commit is the commit with the ID in its subject; this avoids self-referential hashes.
Full red runs and acceptance output: `task-29-rskrb5-ng-own-way.log` in the execution evidence.

| ID | Status | Tests and commit | Behaviour change for CHANGELOG | Dismissal evidence |
| --- | --- | --- | --- | --- |
| RSK-84FA90AE | fixed | `unsealed_wrap_applies_rrc_on_decode_and_encode`; commit `(RSK-84FA90AE)` | Unsealed Wrap tokens apply RRC modulo body length on encoding and decoding. | N/A |
| RSK-C4BE57A0 | fixed | `acceptor_rejects_nonfirst_kerberos`, `acceptor_rejects_unverified_mech_list_mic`, `acceptor_rejects_stateless_continuation`, `acceptor_preserves_selected_kerberos_oid`, `acceptor_rejects_unsupported_mechanisms`, `acceptor_rejects_optimistic_oid_mismatch`, `acceptor_accepts_raw_ms_kerberos`, `acceptor_rejection_preserves_replay_cache`; commit `(RSK-C4BE57A0)` | Acceptor scope: accept only first-choice Kerberos OIDs; preserve selection in replies; fail closed on mechanism switches, supplied MICs and stateless continuations. | N/A |

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
