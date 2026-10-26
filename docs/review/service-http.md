# Service acceptor and HTTP review dispositions

This backlog is partially complete. Commit subjects identify their own atomic
item without self-referential hashes. Full commands, red output and exit codes
are in `task-30-rskrb5-ng-own-way.log` in the execution evidence.

| ID | Status | Tests and commit | Behaviour change for CHANGELOG | Dismissal evidence |
| --- | --- | --- | --- | --- |
| RSK-3E3C2278 / lead `unchecked-cross-realm-transit` | fixed | `transit_rejects_unchecked_cross_realm_paths`, `transit_preserves_same_realm_and_kdc_checked_paths`, `transit_policy_explicitly_accepts_only_matching_paths`, `transit_policy_rejects_mismatching_paths`; commit suffix `(RSK-3E3C2278)` | Reject unchecked cross-realm paths unless an explicit caller `TransitValidator` approves endpoint realms and raw transit encoding, including direct paths and unknown encodings (RFC 4120 §§2.7, 3.3.3.2). | N/A |
| RSK-39F18D3B | fixed | `service_rejects_nested_ticket_version`, `service_rejects_nested_authenticator_version`, `authenticator_decoder_rejects_nested_version`, `ticket_decryptor_rejects_nested_version`; commit subject suffix `(RSK-39F18D3B)` | Shared ticket decryption rejects `tkt-vno != 5`; shared authenticator decoding rejects `authenticator-vno != 5` with existing typed `InvalidMessage` errors (RFC 4120 §§5.3, 5.5.1). Service rejection occurs before replay admission. | N/A |

## Remaining work

| Item | Progress | Next action or decision |
| --- | --- | --- |
| Mandatory authorization data / `mandatory-authorization-data-discarded` | remaining | Validate ticket and authenticator restrictions independently of first-PAC extraction; test critical siblings and unsupported containers. |
| Replay retention / `ReplayCache:indefinite-entry-retention` | remaining | Owner chose option A: cache-owned fixed maximum skew, named rejection of wider validators, fail-closed clock rollback, and capacity admission. Document the contract in this ledger and migration guide. |
| Authenticator microseconds domain | remaining | Enforce 0..=999999 before timestamp/replay processing and AP-REP construction/verification. |
| Fractional KerberosTime | remaining | Reject fractions at ticket, authenticator and AP-REP semantic boundaries and construction inputs. |
| HTTP `replay-scope-unbound-http-request` | remaining | Probe existing clone sharing, document no method/URI/body/channel binding, and require explicit cache sharing between independently constructed layers for one principal. Never use per-request replay caches. |
| HTTP overlay deviation 8 | remaining | Make rejection bodies opaque; apply OWASP response headers and remove fingerprinting headers in the example. |

The transit item adds the documented policy trait/builders and a named service
error; nested-version signatures and errors remain unchanged. Existing
v5 fixture acceptance is the positive control. No external service, KDC or
upstream issue was modified or contacted.
