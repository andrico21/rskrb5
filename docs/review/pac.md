# PAC and NDR review dispositions

This lane is in progress. Unlisted items remain pending, not dismissed.
Full commands, red runs and scratch failure QA are recorded in
`task-32-rskrb5-ng-own-way.log`. Commit subjects identify the associated item.

| ID | Status | Tests and commit | Behaviour change for CHANGELOG | Dismissal evidence |
|---|---|---|---|---|
| RSK-6DF06BE8 / lead `pac.authorization-data.unbounded-if-relevant-recursion` | fixed | `rejects_authorization_data_depth_above_eight`, `rejects_authorization_data_aggregate_bytes`, `rejects_authorization_data_bytes_before_decode`; boundary controls `extracts_pac_at_authorization_data_depth_eight`, `accepts_authorization_data_at_byte_budget`; commit subject suffix `(RSK-6DF06BE8)` | Public first-PAC lookup rejects a ninth AD-IF-RELEVANT wrapper or more than 1 MiB of cumulative visited payloads before decoding/processing, with named PAC errors. | N/A |

| RSK-B5912AE2 / lead `pac.claims-decompression.peer-controlled-cap` | fixed | `claims_rejects_excessive_declared_output`, `claims_rejects_excessive_uncompressed_output`, `claims_accepts_output_limit`; commit suffix `(RSK-B5912AE2)` | Claims decode rejects declared output or raw input over 1 MiB before framing, decompressing or copying, using `Pac::ClaimsOutputLimit`. At most two processed claims buffers bound aggregate decoded output to 2 MiB. Existing compression output cap and exact-size checks remain. | N/A |

## Traversal policy and trust boundary

The inclusive limits match the existing service authorization validator: eight
wrappers and 1 MiB of visited entry payloads. Every visited payload is charged,
including ignored entries and PAC bytes; nested content is charged at each level
and siblings share one budget. These local resource limits are not RFC limits.
The first PAC still terminates lookup, so this helper is not a replacement for
the service's mandatory-authorization-data validation of the whole tree.

The service already validates these budgets before PAC lookup. This repair closes
the independently callable public helper; it does not claim a newly demonstrated
unauthenticated service exploit. Ticket authorization data still requires service
key decryption, as recorded by the audit lead. No service call-site edit is needed.

## Remaining work

Eight other todo-32 items remain pending. Final full STRICT, WIN-CLIPPY,
FULL-TEST, DOCTEST, DOCS, NIGHTLY-FMT, GATES and exact doc-ID acceptance are
deferred until all items are complete, as required by the lane instructions.
