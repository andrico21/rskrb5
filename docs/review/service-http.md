# Service acceptor and HTTP review dispositions

All eight items have a disposition. Commit subjects identify their own atomic
item without self-referential hashes. Full commands, red output and exit codes
are in `task-30-rskrb5-ng-own-way.log` in the execution evidence.

| ID | Status | Tests and commit | Behaviour change for CHANGELOG | Dismissal evidence |
| --- | --- | --- | --- | --- |
| overlay deviation 8 (`http-services.md`) | fixed | `hardening_covers_all_response_statuses` (example), `rejection_helpers_have_opaque_bodies` (HTTP); commit suffix `(http-overlay-8)` | Example outer response middleware overrides all twelve overlay security headers and removes Server/X-Powered-By/ASP.NET fingerprint headers on every status. Existing empty challenge/reject bodies are pinned by a passing probe; no internal error rendering is introduced. | N/A |
| run-2 lead `src/http.rs:NegotiateLayer:replay-scope-unbound-http-request` | dismissed | `tower_layer_rejects_replay_across_services`, `replay_scope_independent_layers_share_explicit_cache`, `replay_scope_independent_caches_do_not_coordinate`; commit suffix `(replay-scope-unbound-http-request)` | Document mandatory per-principal cache sharing between independent same-process acceptors and request/channel-binding limits; no runtime behaviour change. | Existing default layer clones share the same cache and reject replays. Explicit `with_shared_replay_cache` coordinates independent layers, demonstrated by GET /account then POST /transfer rejection. Independent caches each accepting once is a documented deployment limitation, not repaired by request-local caches or an implicit process-global registry. No method/URI/body/TLS binding or cross-process replay-state claim is made. |
| RSK-B161A328 | fixed | `fractional_time_rejects_all_ticket_fields`, `fractional_time_rejects_authenticator`, `fractional_time_rejects_reply_construction`, `fractional_time_rejects_reply_verification`; commit suffix `(RSK-B161A328)` | Reject nonzero fractions in all ticket times, authenticator ctime, service AP-REP verification and mutable reply construction input with `Service::FractionalKerberosTime` (RFC 4120 §5.2.3). No truncation or merging into cusec. | N/A |
| RSK-985742B6 | fixed | `microseconds_rejects_out_of_domain_authenticator`, `microseconds_rejects_invalid_reply_construction`, `microseconds_rejects_invalid_reply_verification`, `microseconds_reply_boundaries_roundtrip`; commit suffix `(RSK-985742B6)` | Enforce RFC 4120 Microseconds 0..=999999 before authenticator timestamp/replay processing and service AP-REP construction/verification. Reject rather than normalize; existing `IntegerOutOfRange` variant identifies the field. | N/A |
| RSK-7D80FA41 / lead `ReplayCache:indefinite-entry-retention` | fixed | `replay_lifecycle_automatically_expires_old_records`, `replay_lifecycle_rejects_clock_rollback`, `replay_lifecycle_capacity_preserves_live_records`, `replay_lifecycle_rejects_wider_shared_skew`, `replay_lifecycle_preserves_future_authenticators`; commit suffix `(RSK-7D80FA41)` | Option A: cache-owned immutable skew/capacity (default 300 seconds / 65,536 records), automatic conservative two-skew expiry, named wider-skew rejection, rollback high-water guard, fail-closed capacity admission. | N/A |
| RSK-D1D6BDC3 / lead `mandatory-authorization-data-discarded` | fixed | `authdata_rejects_ticket_critical_elements`, `authdata_rejects_authenticator_critical_elements`, `authdata_rejects_critical_sibling_after_verified_pac`, `authdata_accepts_optional_unknown_elements`, `authdata_rejects_mandatory_inside_optional_wrapper`, `authdata_rejects_unsupported_and_or_inside_optional_wrapper`, `authdata_enforces_depth_and_byte_limits`; commit suffix `(RSK-D1D6BDC3)` | Validate all ticket/authenticator authorization restrictions before success, independently of first-PAC extraction. Reject unknown critical elements and unsupported AD-KDCIssued/AD-AND-OR; interpret AD-IF-RELEVANT and AD-MANDATORY-FOR-KDC nesting with eight-wrapper/1 MiB decoded-payload limits (RFC 4120 §5.2.6). | N/A |
| RSK-3E3C2278 / lead `unchecked-cross-realm-transit` | fixed | `transit_rejects_unchecked_cross_realm_paths`, `transit_preserves_same_realm_and_kdc_checked_paths`, `transit_policy_explicitly_accepts_only_matching_paths`, `transit_policy_rejects_mismatching_paths`; commit suffix `(RSK-3E3C2278)` | Reject unchecked cross-realm paths unless an explicit caller `TransitValidator` approves endpoint realms and raw transit encoding, including direct paths and unknown encodings (RFC 4120 §§2.7, 3.3.3.2). | N/A |
| RSK-39F18D3B | fixed | `service_rejects_nested_ticket_version`, `service_rejects_nested_authenticator_version`, `authenticator_decoder_rejects_nested_version`, `ticket_decryptor_rejects_nested_version`; commit subject suffix `(RSK-39F18D3B)` | Shared ticket decryption rejects `tkt-vno != 5`; shared authenticator decoding rejects `authenticator-vno != 5` with existing typed `InvalidMessage` errors (RFC 4120 §§5.3, 5.5.1). Service rejection occurs before replay admission. | N/A |

## HTTP response policy

The example's security middleware is outermost, outside authentication, so
challenge/reject and fallback responses pass through it as well as successful
handlers. The loopback HTTP listener is a development example: deployment must
provide HTTPS at a trusted boundary. Emitting HSTS does not add TLS to HTTP.
Only the four named fingerprint headers are removed; the example emits no
custom build, hostname or tracing fingerprint headers. Reverse proxies must
apply an equivalent policy to responses they generate or modify themselves.

The transit item adds the documented policy trait/builders and a named service
error; nested-version signatures and errors remain unchanged. Existing
v5 fixture acceptance is the positive control. No external service, KDC or
upstream issue was modified or contacted.
