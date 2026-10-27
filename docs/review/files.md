# Credential file review dispositions

All seven items and their three associated leads have implementation dispositions.
Full commands, red runs and exit codes are recorded in
`task-37-rskrb5-ng-own-way.log`; final acceptance is separate.

## Acceptance checkpoint

Every fixed item has an initial red run and a scratch reversal proof.
Native all-features/no-default clippy, credential-format tests and the prose
gate passed during iteration. The resumed final acceptance is recorded under
`TODO 37 RESUMED FINAL ACCEPTANCE` in the evidence log, with individual
`FINISH EXIT` records for STRICT, Windows clippy, FULL-TEST, DOCTEST,
stable/nightly docs, both nightly format checks and every gate. STRICT uses
a fresh exclusive target without the earlier capability-drop wrapper.
The final ID check compares all ten first-column keys with the plan, including
the three leads, and rejects missing or duplicated leads in negative self-tests.

| ID | Status | Tests and commit | Behaviour change for CHANGELOG | Dismissal evidence |
| --- | --- | --- | --- | --- |
| RSK-7F30E854 | fixed | `upsert_replaces_principal_identity_despite_name_type`, `upsert_preserves_distinct_principal_identities`; commit `9751ceb` | Ccache upsert replaces records with the same client/server realms and components despite differing name-type hints (RFC 4120 §6.2); new hints are preserved. Structural principal equality and component-only lookup remain unchanged. | N/A |
| RSK-01B7A90E | fixed | `serde_rejects_unsupported_ccache_versions`, `serde_supported_ccache_versions_roundtrip`; commit `0d7a313` | Serde decoding rejects ccache versions outside 1–4 using the binary parser's version admission rule; serialization also validates before emitting output. The serde field shape remains unchanged. | N/A |
| RSK-98FEE876 | fixed | `serializer_rejects_unparseable_field_boundaries`, `serializer_accepts_largest_parseable_fields`, `serialized_keytab_roundtrips`; commit `093d7e0` | Keytab serialization rejects component counts, strings, keys and encryption types above the parser's signed 16-bit range instead of emitting unparseable or sign-changed records. A version-one realm-inclusive component count uses the same checked bound. | N/A |
| RSK-DC80DC52 / lead `file-name/uid-token-environment-substitution` | fixed | `resolves_process_identity_tokens_without_uid_environment`, `resolves_keytab_process_identity_tokens`, non-Linux `identity_tokens_require_linux_procfs` and `keytab_identity_tokens_require_linux_procfs`; commit `39cade9` | Linux UID tokens use the real/effective Uid fields in `/proc/self/status`, never environment text. On macOS, Windows and other non-Linux platforms, these tokens now fail with `IdentityUnavailable`; literal paths remain supported. Unavailable/malformed Linux procfs also fails closed. | N/A |
| RSK-DF3180A2 / lead `credential-file/save/inherited-permissions` | fixed | `saves_cache_with_private_permissions`, `saves_keytab_with_private_permissions`; commit `58a0f9f` | Credential saves stage with exclusive creation and Unix mode 0600 before writing secrets, then rename in the same directory; existing owner permissions are only narrowed, never widened. Windows requires a caller-provided owner-only directory ACL. | N/A |
| RSK-58A6D5DD / lead `credential-file/path-write/followed-symlink` | fixed | `rejects_symlinked_cache_destinations_and_primary`, `rejects_symlinked_keytab_destination`, `saves_cache_through_symlinked_parent`; commit `b6a01c5` | Saves reject a symlinked final destination; exclusive same-directory staging and rename never write through a swapped final link. DIR primary resolution rejects final symlinks and initializes only with create-new, including for dangling links. Parent-directory symlinks remain supported. | N/A |
| RSK-361F35CC | fixed | `file_name::tests::credential_file_buffers_are_erased`, `file_name::tests::partial_serialization_is_erased`; commit `30fbcf3` | Owned file reads, save buffers, keytab entry staging and partial serializer output have value-attached erasure. Keytab parse adopts keys before later fallible fields; timestamp admission precedes password derivation. Public raw-byte exports remain caller-owned. | N/A |

## Ownership and filesystem limits

Erasure is observed on live storage before deallocation, not by inspecting freed
memory. Borrowed parser input, successfully exported raw bytes (including serde
serializer outputs), compiler/register copies, allocator reallocation history and
dependency-owned state are outside the guarantee. Abort does not run Drop.
No memory-recovery or cross-UID exploit is claimed.

Filesystem safety assumes callers choose trusted parent directories. Parent
symlinks are deliberately permitted; std-only path operations do not pin ancestor
directory identities against concurrent renames. Atomic replacement does not
follow a raced final link, but cannot promise that a link swapped in after the
last metadata check is itself rejected. Windows ACL construction remains the
caller's responsibility. DIR reads retain the existing read API; this review
hardens write and initialization sinks, not general no-follow credential reads.
