# Credential file review dispositions

Todo 37 is in progress. Only rows with recorded dispositions below are
complete. Full commands, red runs and exit codes are recorded in
`task-37-rskrb5-ng-own-way.log`; final acceptance is separate.

| ID | Status | Tests and commit | Behaviour change for CHANGELOG | Dismissal evidence |
| --- | --- | --- | --- | --- |
| RSK-7F30E854 | fixed | `upsert_replaces_principal_identity_despite_name_type`, `upsert_preserves_distinct_principal_identities`; commit suffix `(RSK-7F30E854)` | Ccache upsert replaces records with the same client/server realms and components despite differing name-type hints (RFC 4120 §6.2); new hints are preserved. Structural principal equality and component-only lookup remain unchanged. | N/A |
| RSK-01B7A90E | fixed | `serde_rejects_unsupported_ccache_versions`, `serde_supported_ccache_versions_roundtrip`; commit suffix `(RSK-01B7A90E)` | Serde decoding rejects ccache versions outside 1–4 using the binary parser's version admission rule; serialization also validates before emitting output. The serde field shape remains unchanged. | N/A |

## Remaining work

Private file creation, final-component symlink rejection, process identity
tokens, keytab serialization bounds and
secret scratch ownership remain under review.
