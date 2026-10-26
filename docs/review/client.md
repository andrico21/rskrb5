# Client review dispositions

Each commit named below contains its fix and regression. Full commands, red
runs, acceptance output and failure QA are in the task-33 evidence log.

| ID | Status | Tests / commit | Behaviour change for CHANGELOG | Dismissal evidence |
|---|---|---|---|---|
| RSK-AFE184E0 | fixed | `tgs_authenticator_uses_client_realm_when_issuer_differs`; `client: Use client realm in TGS authenticators (RSK-AFE184E0)` | Cross-realm TGS authenticators identify the client realm rather than ticket issuer (RFC 4120 §5.5.1). | — |
| RSK-34601373 | fixed | `password_retry_echoes_latest_cookie`, `keytab_retry_echoes_latest_cookie`; commit with this ID | Password/keytab preauth retries replace stale cookies with exact challenge cookies (RFC 6113 §5.2); unrelated METHOD-DATA is not echoed. | — |
| RSK-072A268D | fixed | `initial_password_reply_uses_info2_salt_and_parameters`; commit with this ID | Initial password AS replies honor matching ETYPE-INFO2, then ETYPE-INFO, then PW-SALT hints (RFC 4120 §3.1.3). | — |
| RSK-2099CE19 | fixed | `process_as_rep_accepts_checksum_without_fast_marker`, existing corrupt-checksum test; commit with this ID | RFC 6806 §11 request-integrity checks no longer require optional FAST advertisement. | — |
| RSK-BC016031 | fixed | `tgs_reply_rejects_missing_negotiated_checksum`, `tgs_reply_accepts_valid_negotiated_checksum`; commit with this ID | AS and TGS replies share negotiated request-checksum validation using the actual reply key and original DER (RFC 6806 §11). | — |
| RSK-F526D18D | fixed | `explicit_login_commits_new_shorter_tgt`; commit with this ID | Successful explicit login replaces the primary TGT even when the old ticket lasts longer; dependent service tickets are cleared. | — |
| RSK-E48DA39B | fixed | `cached_service_rejects_invalid_flag`; commit with this ID | INVALID tickets are neither usable nor renewed as a substitute for validation; flags are never locally cleared (RFC 4120 §2.2). | — |
| RSK-1922A31B | fixed | `service_cache_preserves_component_boundaries`; commit with this ID | Service cache keys preserve realm/component boundaries; name type stays advisory (RFC 4120 §6.2). | — |
| RSK-45397760 | fixed | `as_request_does_not_advertise_unprotected_canonicalization`, `as_req_options_from_libdefaults_suppresses_canonicalize_flag`; commit with this ID | Unarmored AS builders suppress canonicalize rather than advertise unsupported identity changes. Strict reply identities remain enforced: a usage-56 checksum authenticates the request, not cleartext reply names; FAST advertisement is not armor (RFC 6806 §§3,6). TGS referral behavior is unchanged. | — |
