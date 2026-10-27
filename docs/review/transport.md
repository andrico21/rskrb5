# Transport review dispositions

This lane is in progress. Each completed row identifies the atomic commit by
its subject suffix. Full red/green output and exit codes are recorded in the
task-35 execution evidence; final acceptance is deferred until all items finish.

| ID | Status | Tests / commit | Behaviour change for CHANGELOG | Dismissal evidence |
|---|---|---|---|---|
| RSK-03EDCC7E | fixed | `configured_endpoint_preserves_bare_ipv6`; commit suffix `(RSK-03EDCC7E)` | Complete bare IP literals retain their complete host and service default port; explicit IPv6 ports require brackets. | — |
| RSK-3F13B5FE | fixed | `kpasswd_admin_fallback_preserves_ipv6`; commit suffix `(RSK-3F13B5FE)` | Configured administration fallback retains complete IPv6 hosts and replaces administration ports with 464, including bare and bracketed literals. | — |
| RSK-0D8D7D97 | fixed | `udp_transport_reaches_ipv6_loopback`; commit suffix `(RSK-0D8D7D97)` | Resolve UDP candidates before binding a matching IPv4/IPv6 wildcard socket; try alternative candidates on bind/connect failure within the existing timeout. No post-send retry is introduced. | — |
