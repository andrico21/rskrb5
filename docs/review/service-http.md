# Service acceptor and HTTP review dispositions

This backlog is partially complete. Commit subjects identify their own atomic
item without self-referential hashes. Full commands, red output and exit codes
are in `task-30-rskrb5-ng-own-way.log` in the execution evidence.

| ID | Status | Tests and commit | Behaviour change for CHANGELOG | Dismissal evidence |
| --- | --- | --- | --- | --- |
| RSK-39F18D3B | fixed | `service_rejects_nested_ticket_version`, `service_rejects_nested_authenticator_version`, `authenticator_decoder_rejects_nested_version`, `ticket_decryptor_rejects_nested_version`; commit subject suffix `(RSK-39F18D3B)` | Shared ticket decryption rejects `tkt-vno != 5`; shared authenticator decoding rejects `authenticator-vno != 5` with existing typed `InvalidMessage` errors (RFC 4120 §§5.3, 5.5.1). Service rejection occurs before replay admission. | N/A |

## Remaining work

| Item | Progress | Next action or decision |
| --- | --- | --- |
| Cross-realm transit / `unchecked-cross-realm-transit` | remaining | Add a caller-configured transit validator and fail closed for unchecked cross-realm tickets, including empty paths and unknown encodings; preserve same-realm behaviour. |
| Mandatory authorization data / `mandatory-authorization-data-discarded` | remaining | Validate ticket and authenticator restrictions independently of first-PAC extraction; test critical siblings and unsupported containers. |
| Replay retention / `ReplayCache:indefinite-entry-retention` | blocked | Choose a cache-owned fixed maximum skew, reject wider validators, and fail closed on clock rollback with capacity admission; alternatively register all policies before use and prohibit widening. Arbitrary future skew changes and rollback are incompatible with safe expiry under the present contract. |
| Authenticator microseconds domain | remaining | Enforce 0..=999999 before timestamp/replay processing and AP-REP construction/verification. |
| Fractional KerberosTime | remaining | Reject fractions at ticket, authenticator and AP-REP semantic boundaries and construction inputs. |
| HTTP `replay-scope-unbound-http-request` | remaining | Probe existing clone sharing, document no method/URI/body/channel binding, and require explicit cache sharing between independently constructed layers for one principal. Never use per-request replay caches. |
| HTTP overlay deviation 8 | remaining | Make rejection bodies opaque; apply OWASP response headers and remove fingerprinting headers in the example. |

Public signatures and error enums are unchanged by the completed item. Existing
v5 fixture acceptance is the positive control. No external service, KDC or
upstream issue was modified or contacted.
