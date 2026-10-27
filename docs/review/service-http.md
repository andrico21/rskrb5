# Service acceptor and HTTP review dispositions

This backlog is partially complete. Commit subjects identify their own atomic
item without self-referential hashes. Full commands, red output and exit codes
are in `task-30-rskrb5-ng-own-way.log` in the execution evidence.

| ID | Status | Tests and commit | Behaviour change for CHANGELOG | Dismissal evidence |
| --- | --- | --- | --- | --- |
| RSK-B161A328 | fixed | `fractional_time_rejects_all_ticket_fields`, `fractional_time_rejects_authenticator`, `fractional_time_rejects_reply_construction`, `fractional_time_rejects_reply_verification`; commit suffix `(RSK-B161A328)` | Reject nonzero fractions in all ticket times, authenticator ctime, service AP-REP verification and mutable reply construction input with `Service::FractionalKerberosTime` (RFC 4120 §5.2.3). No truncation or merging into cusec. | N/A |
| RSK-985742B6 | fixed | `microseconds_rejects_out_of_domain_authenticator`, `microseconds_rejects_invalid_reply_construction`, `microseconds_rejects_invalid_reply_verification`, `microseconds_reply_boundaries_roundtrip`; commit suffix `(RSK-985742B6)` | Enforce RFC 4120 Microseconds 0..=999999 before authenticator timestamp/replay processing and service AP-REP construction/verification. Reject rather than normalize; existing `IntegerOutOfRange` variant identifies the field. | N/A |
| RSK-7D80FA41 / lead `ReplayCache:indefinite-entry-retention` | fixed | `replay_lifecycle_automatically_expires_old_records`, `replay_lifecycle_rejects_clock_rollback`, `replay_lifecycle_capacity_preserves_live_records`, `replay_lifecycle_rejects_wider_shared_skew`, `replay_lifecycle_preserves_future_authenticators`; commit suffix `(RSK-7D80FA41)` | Option A: cache-owned immutable skew/capacity (default 300 seconds / 65,536 records), automatic conservative two-skew expiry, named wider-skew rejection, rollback high-water guard, fail-closed capacity admission. | N/A |
| RSK-D1D6BDC3 / lead `mandatory-authorization-data-discarded` | fixed | `authdata_rejects_ticket_critical_elements`, `authdata_rejects_authenticator_critical_elements`, `authdata_rejects_critical_sibling_after_verified_pac`, `authdata_accepts_optional_unknown_elements`, `authdata_rejects_mandatory_inside_optional_wrapper`, `authdata_rejects_unsupported_and_or_inside_optional_wrapper`, `authdata_enforces_depth_and_byte_limits`; commit suffix `(RSK-D1D6BDC3)` | Validate all ticket/authenticator authorization restrictions before success, independently of first-PAC extraction. Reject unknown critical elements and unsupported AD-KDCIssued/AD-AND-OR; interpret AD-IF-RELEVANT and AD-MANDATORY-FOR-KDC nesting with eight-wrapper/1 MiB decoded-payload limits (RFC 4120 §5.2.6). | N/A |
| RSK-3E3C2278 / lead `unchecked-cross-realm-transit` | fixed | `transit_rejects_unchecked_cross_realm_paths`, `transit_preserves_same_realm_and_kdc_checked_paths`, `transit_policy_explicitly_accepts_only_matching_paths`, `transit_policy_rejects_mismatching_paths`; commit suffix `(RSK-3E3C2278)` | Reject unchecked cross-realm paths unless an explicit caller `TransitValidator` approves endpoint realms and raw transit encoding, including direct paths and unknown encodings (RFC 4120 §§2.7, 3.3.3.2). | N/A |
| RSK-39F18D3B | fixed | `service_rejects_nested_ticket_version`, `service_rejects_nested_authenticator_version`, `authenticator_decoder_rejects_nested_version`, `ticket_decryptor_rejects_nested_version`; commit subject suffix `(RSK-39F18D3B)` | Shared ticket decryption rejects `tkt-vno != 5`; shared authenticator decoding rejects `authenticator-vno != 5` with existing typed `InvalidMessage` errors (RFC 4120 §§5.3, 5.5.1). Service rejection occurs before replay admission. | N/A |

## Remaining work

| Item | Progress | Next action or decision |
| --- | --- | --- |
| HTTP `replay-scope-unbound-http-request` | remaining | Probe existing clone sharing, document no method/URI/body/channel binding, and require explicit cache sharing between independently constructed layers for one principal. Never use per-request replay caches. |
| HTTP overlay deviation 8 | remaining | Make rejection bodies opaque; apply OWASP response headers and remove fingerprinting headers in the example. |

The transit item adds the documented policy trait/builders and a named service
error; nested-version signatures and errors remain unchanged. Existing
v5 fixture acceptance is the positive control. No external service, KDC or
upstream issue was modified or contacted.
