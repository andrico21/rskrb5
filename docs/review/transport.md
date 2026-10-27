# Transport review dispositions

This lane is in progress. Each completed row identifies the atomic commit by
its subject suffix. Full red/green output and exit codes are recorded in the
task-35 execution evidence; final acceptance is deferred until all items finish.

| ID | Status | Tests / commit | Behaviour change for CHANGELOG | Dismissal evidence |
|---|---|---|---|---|
| RSK-03EDCC7E | fixed | `configured_endpoint_preserves_bare_ipv6`; commit suffix `(RSK-03EDCC7E)` | Complete bare IP literals retain their complete host and service default port; explicit IPv6 ports require brackets. | — |
