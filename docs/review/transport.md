# Transport review dispositions

This lane is in progress. Each completed row identifies the atomic commit by
its subject suffix. Full red/green output and exit codes are recorded in the
task-35 execution evidence; final acceptance is deferred until all items finish.

| ID | Status | Tests / commit | Behaviour change for CHANGELOG | Dismissal evidence |
|---|---|---|---|---|
| RSK-03EDCC7E | fixed | `configured_endpoint_preserves_bare_ipv6`; commit suffix `(RSK-03EDCC7E)` | Complete bare IP literals retain their complete host and service default port; explicit IPv6 ports require brackets. | — |
| RSK-3F13B5FE | fixed | `kpasswd_admin_fallback_preserves_ipv6`; commit suffix `(RSK-3F13B5FE)` | Configured administration fallback retains complete IPv6 hosts and replaces administration ports with 464, including bare and bracketed literals. | — |
| RSK-0D8D7D97 | fixed | `udp_transport_reaches_ipv6_loopback`; commit suffix `(RSK-0D8D7D97)` | Resolve UDP candidates before binding a matching IPv4/IPv6 wildcard socket; try alternative candidates on bind/connect failure within the existing timeout. No post-send retry is introduced. | — |
| RSK-484961E9 | fixed | `udp_transport_rejects_truncated_datagram`; commit suffix `(RSK-484961E9)` | UDP response limits reject oversized datagrams with `Client::UdpResponseTooLarge`, never return a truncated prefix. | — |
| Ambient input `RSKRB5_DNS_SERVER` | fixed | `transport_dns_has_no_ambient_environment_reads`; commit suffix `(ambient-DNS)` | Transport no longer reads environment DNS overrides; applications explicitly call `Tokio::with_dns_server`. The gated integration test reads the variable itself. | — |
| RSK-4AD555A5 | fixed | `kpasswd_dns_admin_fallback_uses_port_464`; commit suffix `(RSK-4AD555A5)` | DNS administration fallback retains discovered hosts but uses kpasswd port 464; actual `_kpasswd` service ports remain authoritative. | — |
