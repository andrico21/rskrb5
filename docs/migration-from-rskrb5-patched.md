# Migrating from rskrb5-patched

The package is now `rskrb5-ng`; Rust imports use `rskrb5_ng`.
The version remains 0.3.0. Wire formats and field semantics are unchanged.

## Non-exhaustive types and constructors

Public structs and enums are non-exhaustive. Construct values through their
constructors or builders instead of struct literals. External enum matches
must handle every known variant explicitly and include a final fallback for
future variants. Matches within the library remain exhaustive.

External construction by struct literal is rejected, including struct update
syntax:

```compile_fail,E0639
use rskrb5_ng::config::LibDefaults;

let defaults = LibDefaults {
    default_realm: "EXAMPLE.COM".to_owned(),
    ..LibDefaults::default()
};
```

Use the builder path instead:

```rust
use rskrb5_ng::config::LibDefaults;

let defaults = LibDefaults::default().with_default_realm("EXAMPLE.COM".to_owned());
assert_eq!(defaults.default_realm, "EXAMPLE.COM");
```

### Construction map

All constructor arguments retain the corresponding public field's meaning.
Builders consume and return the value; existing public fields remain readable
and writable. `Option` builders accept the complete `Option<T>`, including
`None`, unless an existing method explicitly accepts the payload directly.

| Type | Construction path |
| --- | --- |
| `ccache::EncryptionKey`, `keytab::EncryptionKey` | `new(etype, value)` |
| `ccache::Principal`, `keytab::Principal`, `client::Principal` | Existing `new(realm, name_type, components)` |
| `service::Principal` | `new(realm, name_type, components)` |
| `ccache::AuthorizationDataEntry` | `new(ad_type, data)` |
| `ccache::Credential` | `new(client, server, key, times, ticket_flags, ticket)`; `with_is_skey`, `with_addresses`, `with_auth_data`, `with_second_ticket` |
| `keytab::Entry` | `new(principal, timestamp, kvno8, key, kvno)` |
| `client::BuiltAsReq` | `new(message, der, client, service, nonce)` |
| `client::BuiltTgsReq` | `new(message, der, client, service, kdc_realm, nonce)` |
| `client::AsRepSession` and alias `TgsRepSession` | `new(client, service, session_key, ticket, ticket_flags, auth_time, end_time)`; `with_start_time`, `with_renew_till`, `with_key_expiration`. The initial start time equals `auth_time`. |
| `client::PreauthKeyInfo` | `new(etype)`; `with_salt`, `with_s2kparams` |
| `client::KdcError` | `new(stime, susec, error_code, service)`; `with_ctime`, `with_cusec`, `with_text`, `with_client`, `with_e_data`, `with_method_data`, `with_preauth_key_info` |
| `client::PrunedSessions` | Existing `Default`; `with_primary_tgt`, `with_tgt_sessions`, `with_service_tickets` |
| `config::LibDefaults` | Existing `Default`, `new`, or `new_without_env`; `with_<field>` for every public field. Environment-reading behavior is unchanged. |
| `config::Config`, `config::Realm` | Existing constructors or config parsing; modify public fields after construction |
| `service::ApRepOptions` | Existing `Default`; `with_subkey`, `with_sequence_number`, `with_kvno` |
| `messages::EncryptedData` | `new(etype, cipher)`; `with_kvno` |
| `messages::PaReqEncPaRep` | `new(checksum_type, checksum)` |
| `pac::ClaimsInfo` | `new(metadata, claims_set)` |
| `pac::GroupMembership` | `new(relative_id, attributes)` |
| `spnego::MicToken` | Existing `new(flags, snd_seq_num)` or `Default`; `with_flags`, `with_snd_seq_num`, existing `with_payload`, `with_checksum` |
| `spnego::WrapToken` | Existing `new(flags, snd_seq_num)` or `Default`; `with_flags`, `with_ec`, `with_rrc`, `with_snd_seq_num`, existing `with_payload`, `with_checksum`, `with_encrypted_body` |
| `crypto::Rc4HmacEtype`, `crypto::Des3CbcSha1KdEtype` | `new()` or `Default` instead of bare unit-struct values |
| `kadmin::ChangePasswordResult` | Existing `parse(bytes)`; results are decoded, not synthesized |
| Other decoded message, PAC, metadata, and context views | Existing decode/parse/build operations; no literal construction |

Existing request-option and context-option constructors/builders remain the
construction paths for `AsReqOptions`, `TgsReqOptions`, `ApReqOptions`,
`KpasswdRequestOptions`, `EncKrbPrivPartOptions`, `ChangePasswdMessageOptions`,
and `InitiatorContextOptions`. Existing token constructors remain available for
`NegTokenInit`, `NegTokenResp`, and `Krb5MechToken`.

## Earlier source-compatible signature changes

`TokioClient::{change_password, change_password_for, change_password_with_options,
change_password_for_with_options}` accept a named generic `P: AsRef<[u8]>`
instead of an `impl AsRef<[u8]>` argument. Ordinary calls are unchanged.
