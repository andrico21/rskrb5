# Credential file review dispositions

Todo 37 is in progress. Only rows with recorded dispositions below are
complete. Full commands, red runs and exit codes are recorded in
`task-37-rskrb5-ng-own-way.log`; final acceptance is separate.

| ID | Status | Tests and commit | Behaviour change for CHANGELOG | Dismissal evidence |
| --- | --- | --- | --- | --- |
| RSK-7F30E854 | fixed | `upsert_replaces_principal_identity_despite_name_type`, `upsert_preserves_distinct_principal_identities`; commit suffix `(RSK-7F30E854)` | Ccache upsert replaces records with the same client/server realms and components despite differing name-type hints (RFC 4120 §6.2); new hints are preserved. Structural principal equality and component-only lookup remain unchanged. | N/A |
| RSK-01B7A90E | fixed | `serde_rejects_unsupported_ccache_versions`, `serde_supported_ccache_versions_roundtrip`; commit suffix `(RSK-01B7A90E)` | Serde decoding rejects ccache versions outside 1–4 using the binary parser's version admission rule; serialization also validates before emitting output. The serde field shape remains unchanged. | N/A |
| RSK-98FEE876 | fixed | `serializer_rejects_unparseable_field_boundaries`, `serializer_accepts_largest_parseable_fields`, `serialized_keytab_roundtrips`; commit suffix `(RSK-98FEE876)` | Keytab serialization rejects component counts, strings, keys and encryption types above the parser's signed 16-bit range instead of emitting unparseable or sign-changed records. A version-one realm-inclusive component count uses the same checked bound. | N/A |
| RSK-DC80DC52 / lead `file-name/uid-token-environment-substitution` | fixed | `resolves_process_identity_tokens_without_uid_environment`, `resolves_keytab_process_identity_tokens`, non-Linux `identity_tokens_require_linux_procfs` and `keytab_identity_tokens_require_linux_procfs`; commit suffix `(RSK-DC80DC52)` | Linux UID tokens use the real/effective Uid fields in `/proc/self/status`, never environment text. On macOS, Windows and other non-Linux platforms, these tokens now fail with `IdentityUnavailable`; literal paths remain supported. Unavailable/malformed Linux procfs also fails closed. | N/A |
| RSK-DF3180A2 / lead `credential-file/save/inherited-permissions` | fixed | `saves_cache_with_private_permissions`, `saves_keytab_with_private_permissions`; commit suffix `(RSK-DF3180A2)` | Credential saves stage with exclusive creation and Unix mode 0600 before writing secrets, then rename in the same directory; existing owner permissions are only narrowed, never widened. Windows requires a caller-provided owner-only directory ACL. | N/A |

## Remaining work

Final-component symlink rejection and
secret scratch ownership remain under review.
