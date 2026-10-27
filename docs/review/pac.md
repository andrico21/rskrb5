# PAC and NDR review dispositions

All ten items are fixed. Full commands, initial red runs and scratch failure QA
are recorded in `task-32-rskrb5-ng-own-way.log`. Final acceptance is recorded
there separately; a disposition is not itself a claim that acceptance passed.

| ID | Status | Tests and commit | Behaviour change for CHANGELOG | Dismissal evidence |
|---|---|---|---|---|
| RSK-6DF06BE8 | fixed | `rejects_authorization_data_depth_above_eight`, `rejects_authorization_data_aggregate_bytes`, `rejects_authorization_data_bytes_before_decode`; `5362fb8` | Public PAC lookup enforces eight wrappers and 1 MiB cumulative visited payloads before decoding/processing, including across siblings. | N/A |
| RSK-B5912AE2 | fixed | `claims_rejects_excessive_declared_output`, `claims_rejects_excessive_uncompressed_output`, `claims_accepts_output_limit`; `9fd5f1b` | Claims output has an independent 1 MiB ceiling; at most two processed claims buffers bound aggregate decoded output to 2 MiB. Existing exact-size checks remain. | N/A |
| RSK-A9B8B032 | fixed | `credentials_rejects_count_without_descriptor_extent`, `credentials_accepts_empty_count`; `a5fe98f` | Credential counts and checked 16-byte descriptor extent are admitted before fallible reservation. Count ceiling is 1,000,000. | N/A |
| RSK-DB101DC5 | fixed | `credentials_accepts_conformant_single_entry`, `credentials_rejects_mismatched_conformant_count`; `9145554` | NDR32 conformant maximum count is consumed and correlated before CredentialCount; direct/encrypted fixtures include both words and serialization padding (MS-PAC 2.6.2). | N/A |
| RSK-8BA3D269 | fixed | `ntlm_uses_low_bit_validity_masks`, `ntlm_rejects_flags_without_valid_hash`; `d4dfda1` | NTLM validity uses numeric masks 1/2, ignores reserved bits and rejects records with neither validity bit (MS-PAC 2.6.4). | N/A |
| RSK-59B45280 | fixed | `ntlm_reads_nt_from_its_fixed_slot`, `ntlm_rejects_truncated_fixed_slots`; `a444917` | Both fixed NTLM slots are consumed regardless of validity flags; all valid combinations require the complete structure. | N/A |
| RSK-8E17F182 | fixed | `boolean_claims_decode_aligned_u64_values`, `boolean_claims_reject_non_binary_u64`; `61993e7` | Boolean claims consume aligned ULONG64 values and reject values other than 0/1 (MS-ADTS CLAIM_ENTRY/CLAIM_TYPE). | N/A |
| RSK-5E15962F | fixed | `ntlm_debug_redacts_hash_material`; `87219bc` | Decrypted scratch and package bytes have Zeroizing owners; NTLM hash slots have Drop erasure and redacted diagnostics. Container Debug delegates to redacted package entries. | N/A |
| RSK-6A286805 | fixed | `ndr_rejects_underdeclared_object_length`; `35aaa1a` | Serialized NDR object length must equal the supplied object extent and include eight-byte padding. Common-header field names now match type serialization version 1. | N/A |
| RSK-D33671B2 | fixed | `sid_summary_deduplicates_initial_user_groups`, `sid_summary_deduplicates_initial_device_groups`; `86097ca` | Membership sets replace quadratic output scans; every SID source follows first-seen deduplication while output order stays stable. | N/A |

## Trust and ownership boundaries

The traversal limits match the existing service authorization validator. This
closes the independently callable helper, not a demonstrated unauthenticated
service exploit. First-PAC lookup does not replace whole-tree authorization
validation. Ticket authorization data still requires service-key decryption.

Credential erasure covers owned decrypted scratch, package allocations and NTLM
hash fields. Caller-created copies, borrowed inputs, dependency-internal state,
compiler/register copies and allocator history are not claimed erased. Abort
does not run destructors. Public field/API changes are in the migration guide.
