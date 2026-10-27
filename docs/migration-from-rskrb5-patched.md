# Migrating from rskrb5-patched

The package is now `rskrb5-ng`; Rust imports use `rskrb5_ng`.
The version remains 0.3.0. Wire formats and field semantics are unchanged.

## Review backlog behaviour changes

### Decrypted PAC credential ownership

`SecpkgSupplementalCredential::credentials` is now `Zeroizing<Vec<u8>>`.
Borrow it as a slice for intentional access; avoid extracting a nonzeroizing copy.
Decryption scratch is zeroizing even on parse errors. NTLM credentials erase
their owned optional hashes on Drop and redact Debug, as do package entries.
Their array field types are unchanged, but moving fields out of a Drop type is
restricted; borrow them instead. Copies deliberately made by callers, borrowed
parser inputs, dependency-internal state and compiler/register copies are outside
this guarantee. Abort does not run Drop.

### Boolean claim values

Boolean claim arrays are decoded as aligned ULONG64 values, not bytes.
Values other than zero or one return `error::Pac::InvalidBooleanClaim`.

### NTLM supplemental validity masks

`NTLM_SUPPLEMENTAL_CRED_LMOWF` and `NTLM_SUPPLEMENTAL_CRED_NTOWF` now hold
numeric masks 1 and 2, not the erroneous indices 31 and 30. Test these masks
directly against the decoded flags. Reserved bits are ignored when receiving
credentials; records with neither validity bit return
`error::Pac::MissingNtlmValidityFlag` as required by MS-PAC 2.6.4.

### Bounded supplemental credential allocation

Credential data rejects counts above 1,000,000 or whose 16-byte fixed
descriptors cannot fit the remaining input, before reserving either vector.
Allocation failures after admission return `error::Pac::CredentialAllocation`.
Zero credentials remain valid; no public signatures change.

### Bounded claims output

`ClaimsSetMetadata::decoded_claims_set_bytes` rejects declared output lengths
or stored payloads above 1 MiB with `error::Pac::ClaimsOutputLimit` before
framing, decompression or copying. The cap applies to mutable metadata and to
uncompressed claims too. At most one client and one device claims buffer are
processed, bounding total decoded claims output to 2 MiB per PAC. Existing
decompressed-size correlation remains unchanged; no output is clamped.

### Bounded public PAC lookup

`pac::find_pac_in_authorization_data` now rejects more than eight nested
AD-IF-RELEVANT wrappers with `Pac::AuthorizationDataDepthLimit` and more than
1 MiB of cumulative visited entry payloads with `Pac::AuthorizationDataByteLimit`
(both in `error::Pac`). The inclusive byte budget is shared across siblings and
counts nested payloads again at each decoded level, before decoding or PAC
processing. Its signature and first-PAC behavior are unchanged. Service acceptance
already imposed these limits independently while validating all restrictions.

### HTTP replay-cache scope and binding limits

Layer clones already share replay state. Independently constructed
`NegotiateLayer`/`NegotiateService` instances for the same service principal
must be wired to the same `SharedReplayCache`; never construct a fresh cache
per request. This is in-process only: replicas, restarts and separate hosts
require external coordination or a single accepting boundary. There is no
automatic global cache keyed by principal.

The adapter authenticates an AP-REQ, not HTTP method, URI, headers or body.
No TLS channel-binding input is available. Use TLS, but do not claim that TLS
alone makes this adapter's tokens request/channel-bound. A captured token's
first-use race is not prevented by replay detection. No API signatures change.

### Whole-second KerberosTime (RSK-B161A328)

Service acceptance rejects fractional ticket `authtime`, `starttime`, `endtime`
and `renew-till`, plus fractional authenticator `ctime`, with the new
`Service::FractionalKerberosTime` variant. Service AP-REP verification and
construction enforce the same rule, including mutable public construction
inputs. Fractions are neither truncated nor added to `cusec`; the separate
microseconds field remains valid. Generic DER codecs are unchanged.

### Strict Microseconds domain (RSK-985742B6)

Service AP-REQ acceptance and `ValidatedApReq` AP-REP construction/verification
now reject microseconds outside 0..=999999 using the existing
`Service::IntegerOutOfRange` error (`authenticator.cusec` or `ap-rep.cusec`).
Values at or above one million are not normalized into additional seconds.
Construction rechecks the mutable public `authenticator_cusec` field. Zero and
999999 remain valid. Public signatures and error variants are unchanged.

### Bounded replay-cache lifecycle (RSK-7D80FA41)

`ReplayCache::new`/`default` now own an immutable 300-second skew ceiling and
65,536-record capacity. Use `ReplayCache::with_limits(max_clock_skew, capacity)`
and `SharedReplayCache::from_cache` for an explicitly different policy. A validator
whose skew exceeds the cache ceiling fails admission with
`Service::ReplayCacheSkewExceeded`; `with_max_clock_skew` does not widen a cache.
This also applies to the shared cache created by a Tower layer.

Each insert prunes records presented more than twice the cache skew ago, then
checks replay and capacity atomically under the shared lock. Twice-skew retention
covers authenticators first accepted up to one skew window in the future. Equality
at the expiry boundary stays live. Backward validation time returns
`ReplayCacheClockRollback` until time catches up to the high-water mark; even
explicit `clear` does not reset that mark. Full capacity returns
`ReplayCacheCapacityExceeded`, never evicting live replay evidence.

Explicit `clear`/`clear_older_than*` remain administrative overrides that can erase
live replay protection. Do not schedule aggressive pruning; automatic admission
now maintains expiry. Replace caches only with service downtime lasting at least
the replay window; creating a fresh cache or restarting still loses in-memory
evidence. Capacity bounds records, not principal-string bytes or allocator RSS.

### Mandatory authorization-data policy (RSK-D1D6BDC3)

Service acceptance now scans all ticket and authenticator authorization data,
independently of first-PAC extraction, before replay admission. Unknown critical
elements return `error::Service::UnsupportedAuthorizationData { kind }`.
AD-IF-RELEVANT permits unknown direct children; AD-MANDATORY-FOR-KDC contents
are interpreted with criticality restored. Unsupported AD-KDCIssued and
AD-AND-OR containers fail closed, including inside optional wrappers. Ticket
PACs retain their existing server-checksum verification; authenticator PACs
are not treated as KDC-authenticated authorization evidence.

Policy traversal is limited to eight wrappers and 1,048,576 cumulative payload
bytes (including decoded nested payloads), returning `AuthorizationDataLimit`.
Malformed known wrappers return the existing `Service::Decode` classification.
These service-only bounds do not change the standalone PAC extraction API.

### Explicit unchecked cross-realm transit policy (RSK-3E3C2278)

The service validator now rejects cross-realm tickets lacking
TRANSITED-POLICY-CHECKED with `error::Service::TransitPolicyRejected`, unless
an explicitly configured `service::TransitValidator` approves the complete path.
Use `Validator::with_transit_validator(Arc<dyn TransitValidator>)` or the matching
`http::NegotiateLayer` builder. Implementations receive client realm, service
realm and the raw `TransitedEncoding`; validate all three. Empty contents still
represent cross-realm transit. Reject unknown encodings unless your implementation
understands them. The library does not decode or implicitly trust transit paths.
Same-realm tickets and KDC-checked cross-realm tickets are unaffected.

### RFC3961 derivation constant bounds (RSK-8F3B02EE)

AES-SHA1 `derive_random` and `derive_key` now reject constants longer than
16 bytes; DES3 rejects constants longer than 8 bytes. Handle the new
`error::Crypto::DerivationConstantTooLong { maximum, actual }` variant.
The limits are inclusive cipher-block bounds from RFC3961 section 5.1;
constants are not silently reduced. Empty constants still return `EmptyUsage`.
Signatures, generic `nfold`, and SHA2 PRF contexts/derivation labels are unchanged.

### Bounded AES password derivation (RSK-F240C18F)

`crypto::s2kparams_to_iterations` and both AES families' `string_to_key` now
reject counts above 16,777,216 (2^24) with
`error::Crypto::IterationCountTooHigh { maximum, actual }`. The limit is
inclusive, fixed locally, and not a Kerberos protocol maximum. Excessive counts
are rejected, never clamped. Zero retains `UnsupportedIterationCountZero`.
The common client password-reply-key path propagates the new error before
PBKDF2, including for unauthenticated ETYPE-INFO2 hints. Deployments with larger
work factors must adjust their KDC policy to use this bounded path.
Public signatures are unchanged; direct `string_to_pbkdf2` remains a trusted,
caller-controlled primitive and must not receive unchecked peer work factors.

### Bounded HTTP Negotiate headers (upstream issue #9)

`spnego::parse_negotiate_header` now rejects header values longer than 65,536
bytes with `error::Spnego::NegotiateHeaderTooLong { maximum, actual }` before
scanning or base64 decoding. The limit includes the scheme and whitespace;
exactly 65,536 bytes remain eligible for normal parsing. It applies to both
SPNEGO and raw Kerberos tokens, including acceptor and AP-REP verification
callers. Smaller malformed headers retain their existing error classifications.
Public signatures and token encoders are unchanged. This is a local resource
limit, not a Kerberos protocol maximum; callers needing larger headers must
account for this compatibility restriction.

### Unsupported initiator delegation (RSK-622F4664)

Checked SPNEGO initiation now returns `error::Spnego::DelegationRequiresCredential`
when any context flag mask contains `CONTEXT_FLAG_DELEG`, whether supplied alone,
split across entries or combined with other flags. These builders have no delegated
credential input; they no longer emit malformed delegation checksums. Remove the
request if delegation is not needed; credential forwarding is not implemented.
Public signatures are unchanged. Nondelegating callers are unaffected.

The low-level `authenticator_checksum` helper returns a 24-byte prefix for every
flag representation, not a complete delegation checksum. It no longer appends four
zero bytes for a standalone delegation flag. A caller building delegation manually
must append DlgOpt=1, a little-endian length and the encrypted KRB-CRED specified by
RFC 4121 section 4.1.1. Acceptor framing validation is unchanged and does not import
delegated credentials.

### Mandatory GSS authenticator fields (RSK-FAF64A85)

`spnego::accept_sec_context_header` (and the HTTP acceptor using it) now checks
the RFC 4121 section 4.1.1 authenticator checksum type, framing and sequence
presence before recording a replay. Handle the new `error::Spnego` variants
`MissingAuthenticatorChecksum`, `InvalidAuthenticatorChecksum` and
`MissingAuthenticatorSequence`. Generic `service::Validator::validate_ap_req`
still permits authenticators without these GSS-specific fields.

`init_sec_context_with_confounder` now requires
`InitiatorContextOptions::with_sequence_number(Some(sequence))`; zero is valid.
The random `init_sec_context` builder still supplies a sequence when omitted.
No signatures change. The acceptor still has no channel-binding input, ignores
unknown flags and extensions, and does not import delegated credentials.

### SPNEGO acceptor negotiation (RSK-C4BE57A0)

`AcceptedContext::selected_mechanism` records the first offered Kerberos OID;
AP-REP headers preserve it. Both the standard and Microsoft legacy Kerberos
OIDs are supported, including raw Kerberos headers.

`NegTokenInit::krb5_ap_req`, `Token::krb5_ap_req` and
`accept_sec_context_header` now fail closed for negotiation shapes the one-shot
API cannot complete. Handle the new `error::Spnego` variants
`NegotiationRequiresState`, `MechListMicRequiresState` and
`OptimisticMechanismMismatch`. Supplied MICs are rejected, not verified;
mechanism switches and continuations require a future stateful API retaining
the original offer, GSS context state and final MIC exchange. Unsupported OIDs
continue to use `UnsupportedMechanism`. Token codecs still permit inspection
of these messages; successful decoding does not mean successful negotiation.

### S4U frontend keys (delegated-client-unbound-to-ticket-payload)

S4U exchanges now require frontend long-term keys to validate delegated ticket
identity. Set `TgsReq::with_delegation_keytab(keytab)` for runtime-neutral or
transport APIs. High-level keytab-backed clients provide their keys automatically.
Without keys, reply processing returns `error::Client::DelegationKeyRequired`;
protected ticket/evidence identity mismatches return `DelegationPrincipalMismatch`.
`TgsReq` and `BuiltTgsReq` carry optional local-only `delegation_keytab` metadata.

### Unknown password-mutation outcome (RSK-14E2755A, RSK-8BBFC1EE)

High-level password mutation exchange and reply-validation failures now return
`Client::KpasswdOutcomeUnknown(Box<Client>)`, preserving the underlying cause.
The classification is conservative and may include failure before delivery.
It does not mean rejection or rollback: reconcile with a fresh login before
retrying. Dropping a mutation future returns no error at all; the caller must
record unknown externally. Confirmed server rejection remains a normal result
failure. Async Negotiate wrappers preserve this error and the same cancellation
contract. Transport retry/deadline staging is a separate review item.

### Password plaintext ownership (RSK-471362A3)

Password-specific `ChangePasswdData` Debug now redacts `new_passwd`. High-level
password copies and owned DER staging buffers use zeroizing owners; immutable
rasn `OctetString` fields remain dependency-owned residuals (see the review).

### RFC 3244 bare error responses (RSK-3B6BA222)

`kadmin::Reply::parse` also accepts standalone KRB-ERROR responses. For these
responses `version` is `CHANGE_PASSWORD_REQUEST_VERSION` (0xff80),
`message_length` is the DER wire length and `ap_rep_length` is zero. `encode`
preserves this bare profile. Legacy version-1 error replies remain framed;
callers constructing responders can select the profile through `version`.
Neither error form authenticates a success result.

### Validated kpasswd response controls (RSK-789A6FBB)

High-level password changes now reject invalid KRB-PRIV response controls with
`error::Client::KpasswdReplyControl`. If AP-REP negotiates a server sequence,
the result must carry that sequence (not the client's starting sequence).
Otherwise a timestamp/usec pair is required. Supplied times must be whole-second
KerberosTime plus 0..=999999 microseconds and within 300 seconds of the request
metadata. `RequestOptions::recipient_address`, when present, pins the response
sender; absent that option, the sender must have valid IPv4/IPv6 encoding but
is not bound to the transport endpoint. A supplied response recipient must
match `RequestOptions::sender_address`. Raw `Reply::decrypt_result` remains a
decryption-only API with no contextual freshness/address claim.

## Non-exhaustive types and constructors

Public structs and enums are non-exhaustive. Construct values through their
constructors or builders instead of struct literals. External enum matches
must handle every known variant explicitly and include a final fallback for
future variants. Matches within the library remain exhaustive.

External construction by struct literal is rejected, including struct update
syntax:

Stable rustdoc accepts any compilation error in a `compile_fail` block; it does
not check the annotated error code. Use
`cargo +nightly-2026-10-03 test --doc --all-features` to check that this example
fails specifically with E0639, rather than an unrelated compilation error.

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
| `ccache::Principal`, `keytab::Principal`, `client::principal::Principal` | Existing `new(realm, name_type, components)` |
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
construction paths for `AsReq`, `TgsReq`, `ApReq`,
`RequestOptions`, `EncKrbPrivPartOptions`, `ChangePasswdMessageOptions`,
and `InitiatorContextOptions`. Existing token constructors remain available for
`NegTokenInit`, `NegTokenResp`, and `Krb5MechToken`.

## Earlier source-compatible signature changes

`Tokio::{change_password, change_password_for, change_password_with_options,
change_password_for_with_options}` accept a named generic `P: AsRef<[u8]>`
instead of an `impl AsRef<[u8]>` argument. Ordinary calls are unchanged.

## Signature changes

### Earlier compliance passes

The lifetime parameter on `service::Validator`, `http::NegotiateLayer`,
and `http::NegotiateService` is named `'keytab` instead of `'a`; the Tower
`Service` implementation uses an anonymous lifetime. Lifetime semantics are
unchanged. `http::{challenge_response, reject_response}` retain their generic
`B: Default` bound, now written in a where-clause.

The earlier pass added `#[must_use]` to these public APIs:

- `http::NegotiateLayer::{new, require_client_address, with_ap_rep,
  with_ap_rep_options, with_client_address, with_keytab_principal,
  with_max_clock_skew, with_now, with_reject_invalid, with_shared_replay_cache,
  without_shared_replay_cache}`;
- `http::NegotiateService::{require_client_address, with_ap_rep,
  with_ap_rep_options, with_client_address, with_keytab_principal,
  with_max_clock_skew, with_now, with_reject_invalid, with_shared_replay_cache,
  without_shared_replay_cache}`;
- `service::Validator::{new, require_client_address, shared_replay_cache,
  with_client_address, with_keytab_principal, with_max_clock_skew, with_now,
  with_shared_replay_cache, without_shared_replay_cache}`;
- `evaluation::render_markdown`.

The earlier pass also made these public APIs `const fn`:

- `service::Validator::{with_now, with_max_clock_skew,
  require_client_address, shared_replay_cache, replay_cache_mut}`;
- `http::NegotiateLayer::{with_now, with_max_clock_skew, require_client_address,
  with_ap_rep, with_reject_invalid}`;
- `http::NegotiateService::{inner, inner_mut, with_ap_rep, with_reject_invalid}`.

The four password-change methods listed above already use a named generic `P`
with a where-clause. Each former argument-position `impl Trait` in this pass
likewise becomes an independent named generic with the same bounds; ordinary
calls keep type inference, and callers may now explicitly name these type
arguments using turbofish syntax.

### API pass B call-site migration

- `config::LibDefaults`' thirteen boolean option fields and their `with_*`
  parameters now use `config::Toggle::{Disabled, Enabled}`. Read an option with
  `is_enabled()`, or convert a boolean with `Toggle::from_bool` / `From<bool>`.
  Both direct serde and gokrb5 JSON snapshots retain boolean representations;
  missing `permitted_enctypes_explicit` still means disabled.
- `config::Realm::realm` is now `name`. Serialized field names remain unchanged.
- `client::{kpasswd::build_kpasswd_request, kpasswd::build_kpasswd_request_with_confounders}` borrow
  their `RequestOptions`; `service::ValidatedApReq::build_ap_rep_with_confounder`
  and the corresponding SPNEGO response-header helpers borrow `ApRepOptions`.
- `client::build_tgs_req_for_realm_with_confounder_and_subkey` now takes
  `(tgt, kdc_realm, service, parts)`. Build `parts` with
  `TgsRequestParts::new(options, confounder, subkey).with_timestamp(timestamp, cusec)`.
  The constructor defaults to `options.now` and zero microseconds; pass the same
  explicit timestamp and microseconds as before to reproduce an existing request.
- `kadmin::build_change_password_message_with_confounders` groups its final three
  encryption inputs into `PasswordEncryption::new(reply_key, ap_req_confounder,
  krb_priv_confounder)`; their order and meaning are unchanged.
- Unused receivers became associated functions with the original public names.
  Use `Type::function(args)` instead of `value.function(args)` for the functions
  listed below. Runtime-dispatched `KerberosEtype` methods keep their receivers.
- Newly `#[must_use]` functions require callers to handle their results. Newly
  `const fn` functions work at runtime as before and may also be used in constant
  expressions. No runtime behavior or error text is changed.

### Complete public function inventory for API pass B

The following inventory includes all public signature and must-use changes in
this pass, including const eligibility exposed by the other signature changes.
Generic parameter names are explicit; each where-clause retains the former
argument's independent bound. Module-level re-export paths continue to work.

#### New must-use contracts

- `ap_req::ap_options_from_bits`.
- `ap_req::ap_options_to_bits`.
- `ccache::CacheName::file_path`.
- `ccache::CacheName::into_file_path`.
- `ccache::CCache::new`.
- `ccache::CCache::version`.
- `ccache::CCache::header`.
- `ccache::CCache::default_principal`.
- `ccache::CCache::client_realm`.
- `ccache::CCache::client_name`.
- `ccache::CCache::credentials`.
- `ccache::CCache::entries`.
- `ccache::CCache::config_entry_value`.
- `ccache::CCache::contains_server`.
- `ccache::CCache::get_entry`.
- `ccache::Principal::name_string`.
- `ccache::Principal::principal_string`.
- `ccache::Principal::matches_components`.
- `client::kpasswd::RequestOptions::with_recipient_address`.
- `client::negotiate::Client::from_tokio_client`.
- `client::negotiate::Client::with_keytab`.
- `client::negotiate::Client::inner`.
- `client::negotiate::Client::into_inner`.
- `client::options::AsReq::new`.
- `client::options::AsReq::from_libdefaults`.
- `client::options::AsReq::with_ticket_lifetime`.
- `client::options::AsReq::with_renew_lifetime`.
- `client::options::AsReq::with_etypes`.
- `client::options::AsReq::with_kdc_option_bits`.
- `client::options::AsReq::with_padata`.
- `client::options::AsReq::with_assume_preauthentication`.
- `client::options::AsReq::with_fast_negotiation`.
- `client::options::TgsReq::new`.
- `client::options::TgsReq::from_libdefaults`.
- `client::options::TgsReq::with_ticket_lifetime`.
- `client::options::TgsReq::with_renew_lifetime`.
- `client::options::TgsReq::with_etypes`.
- `client::options::TgsReq::with_kdc_option_bits`.
- `client::options::TgsReq::with_padata`.
- `client::options::TgsReq::with_additional_tickets`.
- `client::options::TgsReq::with_renewal`.
- `client::options::ApReq::new`.
- `client::options::ApReq::with_ap_option_bits`.
- `client::options::ApReq::with_checksum`.
- `client::options::ApReq::with_subkey`.
- `client::options::ApReq::with_sequence_number`.
- `client::principal::Principal::name`.
- `client::transport::KdcEndpoint::authority`.
- `client::transport::Tokio::new`.
- `client::transport::Tokio::with_timeout`.
- `client::transport::Tokio::with_udp_response_limit`.
- `client::transport::Tokio::with_tcp_response_limit`.
- `client::TokioClientDiagnostics::is_ok`.
- `client::PrunedSessions::is_empty`.
- `client::TokioClientAutoRenewal::is_finished`.
- `client::Tokio::with_keytab`.
- `client::Tokio::with_password_credential`.
- `client::Tokio::with_keytab_credential`.
- `client::Tokio::from_ccache`.
- `client::Tokio::from_tgt_session`.
- `client::Tokio::with_transport`.
- `client::Tokio::with_assume_preauthentication`.
- `client::Tokio::with_fast_negotiation`.
- `client::Tokio::config`.
- `client::Tokio::protocol`.
- `client::Tokio::client_principal`.
- `client::Tokio::is_configured`.
- `client::Tokio::assume_preauthentication`.
- `client::Tokio::fast_negotiation`.
- `client::Tokio::tgt_session`.
- `client::Tokio::tgt_refresh_due`.
- `client::Tokio::tgt_session_count`.
- `client::Tokio::tgt_session_for_realm`.
- `client::Tokio::cached_service_ticket_count`.
- `client::Tokio::cached_service_ticket`.
- `client::<'request>TgsRequestParts<'request>::new`.
- `client::<'request>TgsRequestParts<'request>::with_timestamp`.
- `client::default_password_salt`.
- `config::Config::new`.
- `config::Config::realm`.
- `config::Toggle::from_bool`.
- `config::Toggle::is_enabled`.
- `config::LibDefaults::new`.
- `config::parse_supported_enctype_ids`.
- `crypto::AesSha1Etype::from_etype_id`.
- `crypto::AesSha1Etype::etype_id`.
- `crypto::AesSha1Etype::checksum_type_id`.
- `crypto::AesSha1Etype::key_len`.
- `crypto::AesSha1Etype::confounder_len`.
- `crypto::AesSha1Etype::hmac_len`.
- `crypto::AesSha1Etype::default_s2kparams`.
- `crypto::AesSha1Etype::string_to_pbkdf2`.
- `crypto::AesSha1Etype::verify_checksum`.
- `crypto::AesSha2Etype::from_etype_id`.
- `crypto::AesSha2Etype::etype_id`.
- `crypto::AesSha2Etype::checksum_type_id`.
- `crypto::AesSha2Etype::ename`.
- `crypto::AesSha2Etype::key_len`.
- `crypto::AesSha2Etype::confounder_len`.
- `crypto::AesSha2Etype::hmac_len`.
- `crypto::AesSha2Etype::default_s2kparams`.
- `crypto::AesSha2Etype::saltp`.
- `crypto::AesSha2Etype::string_to_pbkdf2`.
- `crypto::AesSha2Etype::verify_checksum`.
- `crypto::Des3CbcSha1KdEtype::from_etype_id`.
- `crypto::Des3CbcSha1KdEtype::from_checksum_type_id`.
- `crypto::Des3CbcSha1KdEtype::etype_id`.
- `crypto::Des3CbcSha1KdEtype::checksum_type_id`.
- `crypto::Des3CbcSha1KdEtype::key_len`.
- `crypto::Des3CbcSha1KdEtype::confounder_len`.
- `crypto::Des3CbcSha1KdEtype::hmac_len`.
- `crypto::Des3CbcSha1KdEtype::default_s2kparams`.
- `crypto::Des3CbcSha1KdEtype::verify_checksum`.
- `crypto::Rc4HmacEtype::from_etype_id`.
- `crypto::Rc4HmacEtype::from_checksum_type_id`.
- `crypto::Rc4HmacEtype::etype_id`.
- `crypto::Rc4HmacEtype::checksum_type_id`.
- `crypto::Rc4HmacEtype::key_len`.
- `crypto::Rc4HmacEtype::confounder_len`.
- `crypto::Rc4HmacEtype::hmac_len`.
- `crypto::Rc4HmacEtype::default_s2kparams`.
- `crypto::Rc4HmacEtype::random_to_key`.
- `crypto::Rc4HmacEtype::verify_checksum`.
- `crypto::KerberosEtype::etype_id`.
- `crypto::KerberosEtype::checksum_type_id`.
- `crypto::KerberosEtype::key_len`.
- `crypto::KerberosEtype::confounder_len`.
- `crypto::KerberosEtype::hmac_len`.
- `crypto::KerberosEtype::default_s2kparams`.
- `crypto::KerberosEtype::verify_checksum`.
- `crypto::iterations_to_s2kparams`.
- `crypto::kerb_checksum_hmac_md5`.
- `evaluation::data::Candidate::name`.
- `evaluation::data::Candidate::license`.
- `evaluation::data::DerType::name`.
- `evaluation::data::CandidateAssessment::support_for`.
- `http::NegotiateLayer<'static>::from_keytab`.
- `kadmin::ChangePasswdMessageOptions::with_recipient_address`.
- `kadmin::<'request>PasswordEncryption<'request>::new`.
- `kadmin::ChangePasswordResult::is_success`.
- `keytab::Name::file_path`.
- `keytab::Name::into_file_path`.
- `keytab::Keytab::new`.
- `keytab::Keytab::version`.
- `keytab::Keytab::entries`.
- `keytab::Entry::system_time`.
- `keytab::Principal::default_password_salt`.
- `keytab::Principal::name_string`.
- `keytab::Principal::principal_string`.
- `krb_priv::EncKrbPrivPartOptions::with_timestamp`.
- `krb_priv::EncKrbPrivPartOptions::with_sequence_number`.
- `krb_priv::EncKrbPrivPartOptions::with_recipient_address`.
- `krb_priv::ipv4_host_address`.
- `krb_priv::ipv6_host_address`.
- `messages::PaPacOptions::from_bits`.
- `messages::PaPacOptions::bits`.
- `messages::PrincipalNameInfo::name`.
- `pac::Pac::buffer`.
- `pac::NtlmSupplementalCredential::has_lm_password`.
- `pac::NtlmSupplementalCredential::has_nt_password`.
- `pac::DeviceInfo::group_membership_sids`.
- `pac::ClaimValues::len`.
- `pac::ClaimValues::is_empty`.
- `pac::FileTime::from_ticks`.
- `pac::FileTime::ticks`.
- `pac::FileTime::system_time`.
- `pac::KerbValidationInfo::group_membership_sids`.
- `service::Principal::name`.
- `service::HostAddress::ipv4`.
- `service::ReplayCache::new`.
- `service::ReplayCache::len`.
- `service::ReplayCache::is_empty`.
- `service::SharedReplayCache::new`.
- `service::SharedReplayCache::from_cache`.
- `service::Validator<'static>::from_keytab`.
- `spnego::oid::ObjectIdentifier::krb5`.
- `spnego::oid::ObjectIdentifier::ms_legacy_krb5`.
- `spnego::oid::ObjectIdentifier::spnego`.
- `spnego::oid::ObjectIdentifier::arcs`.
- `spnego::oid::ObjectIdentifier::is_kerberos_mechanism`.
- `spnego::MicToken::new`.
- `spnego::MicToken::with_payload`.
- `spnego::WrapToken::new`.
- `spnego::WrapToken::with_payload`.
- `spnego::WrapToken::is_sealed`.
- `spnego::Krb5MechToken::ap_req`.
- `spnego::Krb5MechToken::ap_rep`.
- `spnego::Krb5MechToken::new`.
- `spnego::Krb5MechToken::ap_req_bytes`.
- `spnego::Krb5MechToken::ap_rep_bytes`.
- `spnego::NegTokenInit::krb5`.
- `spnego::NegTokenResp::accept_completed`.
- `spnego::NegTokenResp::accept_incomplete_krb5`.
- `spnego::NegTokenResp::reject`.
- `spnego::NegTokenResp::with_response_token`.
- `spnego::InitiatorContextOptions::new`.
- `spnego::InitiatorContextOptions::with_context_flags`.
- `spnego::InitiatorContextOptions::with_ap_option_bits`.
- `spnego::InitiatorContextOptions::with_subkey`.
- `spnego::InitiatorContextOptions::with_sequence_number`.
- `spnego::challenge_header`.
- `spnego::authenticator_checksum`.

#### Changed or added public signatures

- `ccache::CacheName::parse`: `pub fn parse<P>(name: P) -> Result<Self, Error> where P: AsRef<str>,`.
- `ccache::CCache::load`: `pub fn load<P>(path: P) -> Result<Self, Error> where P: AsRef<Path>,`.
- `ccache::CCache::load_name`: `pub fn load_name<P>(name: P) -> Result<Self, Error> where P: AsRef<str>,`.
- `ccache::CCache::save`: `pub fn save<P>(&self, path: P) -> Result<(), Error> where P: AsRef<Path>,`.
- `ccache::CCache::save_name`: `pub fn save_name<P>(&self, name: P) -> Result<(), Error> where P: AsRef<str>,`.
- `ccache::CCache::version`: `pub const fn version(&self) -> u8`.
- `ccache::CCache::header`: `pub const fn header(&self) -> &Header`.
- `ccache::CCache::header_mut`: `pub const fn header_mut(&mut self) -> &mut Header`.
- `ccache::CCache::default_principal`: `pub const fn default_principal(&self) -> &Principal`.
- `ccache::CCache::default_principal_mut`: `pub const fn default_principal_mut(&mut self) -> &mut Principal`.
- `ccache::CCache::credentials_mut`: `pub const fn credentials_mut(&mut self) -> &mut Vec<Credential>`.
- `ccache::CCache::upsert_config_entry`: `pub fn upsert_config_entry<P, Q>( &mut self, key: P, principal: Option<String>, value: Q, ) -> Option<Credential> where P: Into<String>, Q: Into<Vec<u8>>,`.
- `ccache::Principal::new`: `pub fn new<P>(realm: P, name_type: i32, components: Vec<String>) -> Self where P: Into<String>,`.
- `ccache::Credential::config_entry`: `pub fn config_entry<P, Q>( client: Principal, key: P, principal: Option<String>, value: Q, ) -> Self where P: Into<String>, Q: Into<Vec<u8>>,`.
- `client::kpasswd::RequestOptions::new`: `pub const fn new( timestamp: SystemTime, cusec: u32, sequence_number: u32, sender_address: rasn_kerberos::HostAddress, ) -> Self`.
- `client::kpasswd::build_kpasswd_request_with_confounders`: `pub fn build_kpasswd_request_with_confounders( service_ticket: &TgsRepSession, change_data: &kadmin::ChangePasswdData, reply_key: EncryptionKey, options: &RequestOptions, ap_req_confounder: &[u8], krb_priv_confounder: &[u8], ) -> Result<BuiltKpasswdRequest, Error>`.
- `client::kpasswd::build_kpasswd_request`: `pub fn build_kpasswd_request( service_ticket: &TgsRepSession, change_data: &kadmin::ChangePasswdData, options: &RequestOptions, ) -> Result<BuiltKpasswdRequest, Error>`.
- `client::negotiate::Client::from_tokio_client`: `pub const fn from_tokio_client(client: Tokio) -> Self`.
- `client::negotiate::Client::with_password`: `pub fn with_password<P>(config: Config, client: Principal, password: P) -> Self where P: Into<Vec<u8>>,`.
- `client::negotiate::Client::with_keytab`: `pub const fn with_keytab(config: Config, client: Principal, keytab: Keytab) -> Self`.
- `client::negotiate::Client::with_keytab_name`: `pub fn with_keytab_name<P>( config: Config, client: Principal, keytab_name: P, ) -> Result<Self, Error> where P: AsRef<str>,`.
- `client::negotiate::Client::from_ccache_name`: `pub fn from_ccache_name<P>(config: Config, cache_name: P) -> Result<Self, Error> where P: AsRef<str>,`.
- `client::negotiate::Client::inner`: `pub const fn inner(&self) -> &Tokio`.
- `client::negotiate::Client::inner_mut`: `pub const fn inner_mut(&mut self) -> &mut Tokio`.
- `client::negotiate::Client::authorization_header_for_host`: `pub async fn authorization_header_for_host<P, Q>( &mut self, service: P, host: Q, ) -> Result<String, Error> where P: AsRef<str>, Q: AsRef<str>,`.
- `client::negotiate::Client::authorization_context_for_host`: `pub async fn authorization_context_for_host<P, Q>( &mut self, service: P, host: Q, ) -> Result<InitiatorContext, Error> where P: AsRef<str>, Q: AsRef<str>,`.
- `client::negotiate::Client::change_password`: `pub async fn change_password<P>( &mut self, new_password: P, sender_address: rasn_kerberos::HostAddress, ) -> Result<ChangePasswordResult, Error> where P: AsRef<[u8]>,`.
- `client::negotiate::Client::change_password_for`: `pub async fn change_password_for<P>( &mut self, target: Principal, new_password: P, sender_address: rasn_kerberos::HostAddress, ) -> Result<ChangePasswordResult, Error> where P: AsRef<[u8]>,`.
- `client::negotiate::Client::change_password_with_options`: `pub async fn change_password_with_options<P>( &mut self, new_password: P, options: RequestOptions, ) -> Result<ChangePasswordResult, Error> where P: AsRef<[u8]>,`.
- `client::negotiate::Client::change_password_for_with_options`: `pub async fn change_password_for_with_options<P>( &mut self, target: Principal, new_password: P, options: RequestOptions, ) -> Result<ChangePasswordResult, Error> where P: AsRef<[u8]>,`.
- `client::negotiate::BlockingClient::with_password`: `pub fn with_password<P>(config: Config, client: Principal, password: P) -> Result<Self, Error> where P: Into<Vec<u8>>,`.
- `client::negotiate::BlockingClient::with_keytab_name`: `pub fn with_keytab_name<P>( config: Config, client: Principal, keytab_name: P, ) -> Result<Self, Error> where P: AsRef<str>,`.
- `client::negotiate::BlockingClient::from_ccache_name`: `pub fn from_ccache_name<P>(config: Config, cache_name: P) -> Result<Self, Error> where P: AsRef<str>,`.
- `client::negotiate::BlockingClient::client`: `pub const fn client(&self) -> &NegotiateClient`.
- `client::negotiate::BlockingClient::client_mut`: `pub const fn client_mut(&mut self) -> &mut NegotiateClient`.
- `client::negotiate::BlockingClient::authorization_header_for_host`: `pub fn authorization_header_for_host<P, Q>( &mut self, service: P, host: Q, ) -> Result<String, Error> where P: AsRef<str>, Q: AsRef<str>,`.
- `client::negotiate::BlockingClient::authorization_context_for_host`: `pub fn authorization_context_for_host<P, Q>( &mut self, service: P, host: Q, ) -> Result<InitiatorContext, Error> where P: AsRef<str>, Q: AsRef<str>,`.
- `client::negotiate::BlockingClient::change_password`: `pub fn change_password<P>( &mut self, new_password: P, sender_address: rasn_kerberos::HostAddress, ) -> Result<ChangePasswordResult, Error> where P: AsRef<[u8]>,`.
- `client::negotiate::BlockingClient::change_password_for`: `pub fn change_password_for<P>( &mut self, target: Principal, new_password: P, sender_address: rasn_kerberos::HostAddress, ) -> Result<ChangePasswordResult, Error> where P: AsRef<[u8]>,`.
- `client::negotiate::BlockingClient::change_password_with_options`: `pub fn change_password_with_options<P>( &mut self, new_password: P, options: RequestOptions, ) -> Result<ChangePasswordResult, Error> where P: AsRef<[u8]>,`.
- `client::negotiate::BlockingClient::change_password_for_with_options`: `pub fn change_password_for_with_options<P>( &mut self, target: Principal, new_password: P, options: RequestOptions, ) -> Result<ChangePasswordResult, Error> where P: AsRef<[u8]>,`.
- `client::options::AsReq::with_ticket_lifetime`: `pub const fn with_ticket_lifetime(mut self, ticket_lifetime: Duration) -> Self`.
- `client::options::AsReq::with_renew_lifetime`: `pub const fn with_renew_lifetime(mut self, renew_lifetime: Option<Duration>) -> Self`.
- `client::options::AsReq::with_etypes`: `pub fn with_etypes<P>(mut self, etypes: P) -> Self where P: Into<Vec<i32>>,`.
- `client::options::AsReq::with_kdc_option_bits`: `pub const fn with_kdc_option_bits(mut self, kdc_option_bits: u32) -> Self`.
- `client::options::AsReq::with_padata`: `pub fn with_padata<P>(mut self, padata: P) -> Self where P: Into<Vec<rasn_kerberos::PaData>>,`.
- `client::options::AsReq::with_assume_preauthentication`: `pub const fn with_assume_preauthentication(mut self, assume_preauthentication: bool) -> Self`.
- `client::options::AsReq::with_fast_negotiation`: `pub const fn with_fast_negotiation(mut self, fast_negotiation: bool) -> Self`.
- `client::options::TgsReq::with_ticket_lifetime`: `pub const fn with_ticket_lifetime(mut self, ticket_lifetime: Duration) -> Self`.
- `client::options::TgsReq::with_renew_lifetime`: `pub const fn with_renew_lifetime(mut self, renew_lifetime: Option<Duration>) -> Self`.
- `client::options::TgsReq::with_etypes`: `pub fn with_etypes<P>(mut self, etypes: P) -> Self where P: Into<Vec<i32>>,`.
- `client::options::TgsReq::with_kdc_option_bits`: `pub const fn with_kdc_option_bits(mut self, kdc_option_bits: u32) -> Self`.
- `client::options::TgsReq::with_padata`: `pub fn with_padata<P>(mut self, padata: P) -> Self where P: Into<Vec<rasn_kerberos::PaData>>,`.
- `client::options::TgsReq::with_additional_tickets`: `pub fn with_additional_tickets<P>(mut self, additional_tickets: P) -> Self where P: Into<Vec<rasn_kerberos::Ticket>>,`.
- `client::options::TgsReq::with_renewal`: `pub const fn with_renewal(mut self) -> Self`.
- `client::options::ApReq::new`: `pub const fn new() -> Self`.
- `client::options::ApReq::with_ap_option_bits`: `pub const fn with_ap_option_bits(mut self, ap_option_bits: u32) -> Self`.
- `client::options::ApReq::with_sequence_number`: `pub const fn with_sequence_number(mut self, sequence_number: Option<u32>) -> Self`.
- `client::principal::Principal::new`: `pub fn new<I, S, P>(realm: P, name_type: i32, components: I) -> Self where I: IntoIterator<Item = S>, S: Into<String>, P: Into<String>,`.
- `client::principal::Principal::user`: `pub fn user<P, Q>(realm: P, name: Q) -> Self where P: Into<String>, Q: Into<String>,`.
- `client::principal::Principal::parse_user`: `pub fn parse_user<P>(value: P) -> Result<Self, Error> where P: AsRef<str>,`.
- `client::principal::Principal::parse_service`: `pub fn parse_service<P>(value: P) -> Result<Self, Error> where P: AsRef<str>,`.
- `client::principal::Principal::host_based_service`: `pub fn host_based_service<P, Q>(service: P, host: Q) -> Result<Self, Error> where P: AsRef<str>, Q: AsRef<str>,`.
- `client::principal::Principal::host_based_service_in_realm`: `pub fn host_based_service_in_realm<P, Q, R>( service: P, host: Q, realm: R, ) -> Result<Self, Error> where P: AsRef<str>, Q: AsRef<str>, R: AsRef<str>,`.
- `client::principal::Principal::tgt_service`: `pub fn tgt_service<P>(realm: P) -> Self where P: Into<String>,`.
- `client::transport::Tokio::new`: `pub const fn new() -> Self`.
- `client::transport::Tokio::with_timeout`: `pub const fn with_timeout(mut self, timeout: Duration) -> Self`.
- `client::transport::Tokio::with_udp_response_limit`: `pub const fn with_udp_response_limit(mut self, udp_response_limit: usize) -> Self`.
- `client::transport::Tokio::with_tcp_response_limit`: `pub const fn with_tcp_response_limit(mut self, tcp_response_limit: usize) -> Self`.
- `client::TokioClientDiagnostics::is_ok`: `pub const fn is_ok(&self) -> bool`.
- `client::PrunedSessions::is_empty`: `pub const fn is_empty(&self) -> bool`.
- `client::Tokio::with_password`: `pub fn with_password<P>( config: Config, protocol: KdcProtocol, client: Principal, password: P, ) -> Self where P: Into<Vec<u8>>,`.
- `client::Tokio::with_keytab`: `pub const fn with_keytab( config: Config, protocol: KdcProtocol, client: Principal, keytab: Keytab, ) -> Self`.
- `client::Tokio::with_keytab_name`: `pub fn with_keytab_name<P>( config: Config, protocol: KdcProtocol, client: Principal, keytab_name: P, ) -> Result<Self, Error> where P: AsRef<str>,`.
- `client::Tokio::with_password_credential`: `pub fn with_password_credential<P>(mut self, password: P) -> Self where P: Into<Vec<u8>>,`.
- `client::Tokio::from_ccache_name`: `pub fn from_ccache_name<P>( config: Config, protocol: KdcProtocol, cache_name: P, ) -> Result<Self, Error> where P: AsRef<str>,`.
- `client::Tokio::save_ccache`: `pub fn save_ccache<P>(&self, path: P) -> Result<(), Error> where P: AsRef<Path>,`.
- `client::Tokio::save_ccache_name`: `pub fn save_ccache_name<P>(&self, cache_name: P) -> Result<(), Error> where P: AsRef<str>,`.
- `client::Tokio::update_ccache_file`: `pub fn update_ccache_file<P>(&self, path: P) -> Result<(), Error> where P: AsRef<Path>,`.
- `client::Tokio::update_ccache_name`: `pub fn update_ccache_name<P>(&self, cache_name: P) -> Result<(), Error> where P: AsRef<str>,`.
- `client::Tokio::with_transport`: `pub const fn with_transport(mut self, transport: Tokio) -> Self`.
- `client::Tokio::with_assume_preauthentication`: `pub const fn with_assume_preauthentication(mut self, assume_preauthentication: bool) -> Self`.
- `client::Tokio::with_fast_negotiation`: `pub const fn with_fast_negotiation(mut self, fast_negotiation: bool) -> Self`.
- `client::Tokio::config`: `pub const fn config(&self) -> &Config`.
- `client::Tokio::protocol`: `pub const fn protocol(&self) -> KdcProtocol`.
- `client::Tokio::client_principal`: `pub const fn client_principal(&self) -> &Principal`.
- `client::Tokio::assume_preauthentication`: `pub const fn assume_preauthentication(&self) -> bool`.
- `client::Tokio::fast_negotiation`: `pub const fn fast_negotiation(&self) -> bool`.
- `client::Tokio::tgt_session`: `pub const fn tgt_session(&self) -> Option<&AsRepSession>`.
- `client::build_tgs_req_for_realm`: `pub fn build_tgs_req_for_realm<P>( tgt: &AsRepSession, kdc_realm: P, service: Principal, options: TgsReq, ) -> Result<BuiltTgsReq, Error> where P: Into<String>,`.
- `client::build_tgs_req_for_realm_with_confounder`: `pub fn build_tgs_req_for_realm_with_confounder<P>( tgt: &AsRepSession, kdc_realm: P, service: Principal, options: TgsReq, timestamp: SystemTime, cusec: u32, confounder: &[u8], ) -> Result<BuiltTgsReq, Error> where P: Into<String>,`.
- `client::build_tgs_req_for_realm_with_confounder_and_subkey`: `pub fn build_tgs_req_for_realm_with_confounder_and_subkey<R>( tgt: &AsRepSession, kdc_realm: R, service: Principal, parts: TgsRequestParts<'_>, ) -> Result<TgsFastRequestParts, Error> where R: Into<String>,`.
- `client::<'request>TgsRequestParts<'request>::new`: `pub const fn new( options: TgsReq, confounder: &'request [u8], subkey: &'request EncryptionKey, ) -> Self`.
- `client::<'request>TgsRequestParts<'request>::with_timestamp`: `pub const fn with_timestamp(mut self, timestamp: SystemTime, cusec: u32) -> Self`.
- `config::Config::load`: `pub fn load<P>(path: P) -> Result<Self, Error> where P: AsRef<Path>,`.
- `config::Toggle::from_bool`: `pub const fn from_bool(value: bool) -> Self`.
- `config::Toggle::is_enabled`: `pub const fn is_enabled(self) -> bool`.
- `config::LibDefaults::with_allow_weak_crypto`: `pub const fn with_allow_weak_crypto(mut self, value: Toggle) -> Self`.
- `config::LibDefaults::with_canonicalize`: `pub const fn with_canonicalize(mut self, value: Toggle) -> Self`.
- `config::LibDefaults::with_dns_canonicalize_hostname`: `pub const fn with_dns_canonicalize_hostname(mut self, value: Toggle) -> Self`.
- `config::LibDefaults::with_dns_lookup_kdc`: `pub const fn with_dns_lookup_kdc(mut self, value: Toggle) -> Self`.
- `config::LibDefaults::with_dns_lookup_realm`: `pub const fn with_dns_lookup_realm(mut self, value: Toggle) -> Self`.
- `config::LibDefaults::with_forwardable`: `pub const fn with_forwardable(mut self, value: Toggle) -> Self`.
- `config::LibDefaults::with_ignore_acceptor_hostname`: `pub const fn with_ignore_acceptor_hostname(mut self, value: Toggle) -> Self`.
- `config::LibDefaults::with_k5login_authoritative`: `pub const fn with_k5login_authoritative(mut self, value: Toggle) -> Self`.
- `config::LibDefaults::with_no_addresses`: `pub const fn with_no_addresses(mut self, value: Toggle) -> Self`.
- `config::LibDefaults::with_permitted_enctypes_explicit`: `pub const fn with_permitted_enctypes_explicit(mut self, value: Toggle) -> Self`.
- `config::LibDefaults::with_proxiable`: `pub const fn with_proxiable(mut self, value: Toggle) -> Self`.
- `config::LibDefaults::with_rdns`: `pub const fn with_rdns(mut self, value: Toggle) -> Self`.
- `config::LibDefaults::with_verify_ap_req_nofail`: `pub const fn with_verify_ap_req_nofail(mut self, value: Toggle) -> Self`.
- `crypto::AesSha1Etype::from_etype_id`: `pub const fn from_etype_id(etype_id: i32) -> Option<Self>`.
- `crypto::AesSha1Etype::etype_id`: `pub const fn etype_id(self) -> i32`.
- `crypto::AesSha1Etype::checksum_type_id`: `pub const fn checksum_type_id(self) -> i32`.
- `crypto::AesSha1Etype::key_len`: `pub const fn key_len(self) -> usize`.
- `crypto::AesSha1Etype::confounder_len`: `pub const fn confounder_len() -> usize`.
- `crypto::AesSha1Etype::hmac_len`: `pub const fn hmac_len() -> usize`.
- `crypto::AesSha1Etype::default_s2kparams`: `pub const fn default_s2kparams() -> &'static str`.
- `crypto::AesSha2Etype::from_etype_id`: `pub const fn from_etype_id(etype_id: i32) -> Option<Self>`.
- `crypto::AesSha2Etype::etype_id`: `pub const fn etype_id(self) -> i32`.
- `crypto::AesSha2Etype::checksum_type_id`: `pub const fn checksum_type_id(self) -> i32`.
- `crypto::AesSha2Etype::ename`: `pub const fn ename(self) -> &'static str`.
- `crypto::AesSha2Etype::key_len`: `pub const fn key_len(self) -> usize`.
- `crypto::AesSha2Etype::confounder_len`: `pub const fn confounder_len() -> usize`.
- `crypto::AesSha2Etype::hmac_len`: `pub const fn hmac_len(self) -> usize`.
- `crypto::AesSha2Etype::default_s2kparams`: `pub const fn default_s2kparams() -> &'static str`.
- `crypto::Des3CbcSha1KdEtype::from_etype_id`: `pub const fn from_etype_id(etype_id: i32) -> Option<Self>`.
- `crypto::Des3CbcSha1KdEtype::from_checksum_type_id`: `pub const fn from_checksum_type_id(checksum_type_id: i32) -> Option<Self>`.
- `crypto::Des3CbcSha1KdEtype::etype_id`: `pub const fn etype_id() -> i32`.
- `crypto::Des3CbcSha1KdEtype::checksum_type_id`: `pub const fn checksum_type_id() -> i32`.
- `crypto::Des3CbcSha1KdEtype::key_len`: `pub const fn key_len() -> usize`.
- `crypto::Des3CbcSha1KdEtype::confounder_len`: `pub const fn confounder_len() -> usize`.
- `crypto::Des3CbcSha1KdEtype::hmac_len`: `pub const fn hmac_len() -> usize`.
- `crypto::Des3CbcSha1KdEtype::default_s2kparams`: `pub const fn default_s2kparams() -> &'static str`.
- `crypto::Des3CbcSha1KdEtype::string_to_key`: `pub fn string_to_key(secret: &[u8], salt: &[u8], s2kparams: &str) -> Result<Vec<u8>, Error>`.
- `crypto::Des3CbcSha1KdEtype::random_to_key`: `pub fn random_to_key(bytes: &[u8]) -> Result<Vec<u8>, Error>`.
- `crypto::Des3CbcSha1KdEtype::derive_key`: `pub fn derive_key(protocol_key: &[u8], usage: &[u8]) -> Result<Vec<u8>, Error>`.
- `crypto::Des3CbcSha1KdEtype::derive_random`: `pub fn derive_random(protocol_key: &[u8], usage: &[u8]) -> Result<Vec<u8>, Error>`.
- `crypto::Des3CbcSha1KdEtype::checksum`: `pub fn checksum(protocol_key: &[u8], data: &[u8], usage: u32) -> Result<Vec<u8>, Error>`.
- `crypto::Des3CbcSha1KdEtype::verify_checksum`: `pub fn verify_checksum(protocol_key: &[u8], data: &[u8], checksum: &[u8], usage: u32) -> bool`.
- `crypto::Des3CbcSha1KdEtype::encrypt_data`: `pub fn encrypt_data(key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error>`.
- `crypto::Des3CbcSha1KdEtype::decrypt_data`: `pub fn decrypt_data(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error>`.
- `crypto::Des3CbcSha1KdEtype::encrypt_message_with_confounder`: `pub fn encrypt_message_with_confounder( protocol_key: &[u8], message: &[u8], usage: u32, confounder: &[u8], ) -> Result<Vec<u8>, Error>`.
- `crypto::Des3CbcSha1KdEtype::decrypt_message`: `pub fn decrypt_message( protocol_key: &[u8], ciphertext: &[u8], usage: u32, ) -> Result<Vec<u8>, Error>`.
- `crypto::Rc4HmacEtype::from_etype_id`: `pub const fn from_etype_id(etype_id: i32) -> Option<Self>`.
- `crypto::Rc4HmacEtype::from_checksum_type_id`: `pub const fn from_checksum_type_id(checksum_type_id: i32) -> Option<Self>`.
- `crypto::Rc4HmacEtype::etype_id`: `pub const fn etype_id() -> i32`.
- `crypto::Rc4HmacEtype::checksum_type_id`: `pub const fn checksum_type_id() -> i32`.
- `crypto::Rc4HmacEtype::key_len`: `pub const fn key_len() -> usize`.
- `crypto::Rc4HmacEtype::confounder_len`: `pub const fn confounder_len() -> usize`.
- `crypto::Rc4HmacEtype::hmac_len`: `pub const fn hmac_len() -> usize`.
- `crypto::Rc4HmacEtype::default_s2kparams`: `pub const fn default_s2kparams() -> &'static str`.
- `crypto::Rc4HmacEtype::string_to_key`: `pub fn string_to_key(secret: &[u8], _salt: &[u8], _s2kparams: &str) -> Result<Vec<u8>, Error>`.
- `crypto::Rc4HmacEtype::random_to_key`: `pub fn random_to_key(bytes: &[u8]) -> Vec<u8>`.
- `crypto::Rc4HmacEtype::derive_key`: `pub fn derive_key(protocol_key: &[u8], usage: &[u8]) -> Result<Vec<u8>, Error>`.
- `crypto::Rc4HmacEtype::checksum`: `pub fn checksum(protocol_key: &[u8], data: &[u8], usage: u32) -> Result<Vec<u8>, Error>`.
- `crypto::Rc4HmacEtype::verify_checksum`: `pub fn verify_checksum(protocol_key: &[u8], data: &[u8], checksum: &[u8], usage: u32) -> bool`.
- `crypto::Rc4HmacEtype::encrypt_data`: `pub fn encrypt_data(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error>`.
- `crypto::Rc4HmacEtype::decrypt_data`: `pub fn decrypt_data(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error>`.
- `crypto::Rc4HmacEtype::encrypt_message_with_confounder`: `pub fn encrypt_message_with_confounder( protocol_key: &[u8], message: &[u8], usage: u32, confounder: &[u8], ) -> Result<Vec<u8>, Error>`.
- `crypto::Rc4HmacEtype::decrypt_message`: `pub fn decrypt_message( protocol_key: &[u8], ciphertext: &[u8], usage: u32, ) -> Result<Vec<u8>, Error>`.
- `crypto::KerberosEtype::etype_id`: `pub const fn etype_id(self) -> i32`.
- `crypto::KerberosEtype::checksum_type_id`: `pub const fn checksum_type_id(self) -> i32`.
- `crypto::KerberosEtype::key_len`: `pub const fn key_len(self) -> usize`.
- `crypto::KerberosEtype::confounder_len`: `pub const fn confounder_len(self) -> usize`.
- `crypto::KerberosEtype::hmac_len`: `pub const fn hmac_len(self) -> usize`.
- `crypto::KerberosEtype::default_s2kparams`: `pub const fn default_s2kparams(self) -> &'static str`.
- `http::<B>NegotiateHttpResponse<B>::did_negotiate`: `pub const fn did_negotiate(&self) -> bool`.
- `http::NegotiateLayer<'static>::from_keytab_name`: `pub fn from_keytab_name<P>(keytab_name: P) -> Result<Self> where P: AsRef<str>,`.
- `http::<S>NegotiateService<'static,S>::from_keytab_name`: `pub fn from_keytab_name<P>(inner: S, keytab_name: P) -> Result<Self> where P: AsRef<str>,`.
- `kadmin::ChangePasswdData::new`: `pub fn new<P>(new_passwd: P) -> Self where P: AsRef<[u8]>,`.
- `kadmin::ChangePasswdData::for_target`: `pub fn for_target<I, S, P>( new_passwd: P, name_type: i32, components: I, realm: &str, ) -> Result<Self, Error> where I: IntoIterator<Item = S>, S: AsRef<str>, P: AsRef<[u8]>,`.
- `kadmin::build_enc_krb_priv_part`: `pub fn build_enc_krb_priv_part<P>( user_data: P, options: EncKrbPrivPartOptions, ) -> rasn_kerberos::EncKrbPrivPart where P: AsRef<[u8]>,`.
- `kadmin::build_krb_priv_with_confounder`: `pub fn build_krb_priv_with_confounder<P>( user_data: P, options: EncKrbPrivPartOptions, key: &EncryptionKey, confounder: &[u8], ) -> Result<rasn_kerberos::KrbPriv, Error> where P: AsRef<[u8]>,`.
- `kadmin::build_krb_priv`: `pub fn build_krb_priv<P>( user_data: P, options: EncKrbPrivPartOptions, key: &EncryptionKey, ) -> Result<rasn_kerberos::KrbPriv, Error> where P: AsRef<[u8]>,`.
- `kadmin::ChangePasswdMessageOptions::new`: `pub const fn new( timestamp: rasn_kerberos::KerberosTime, cusec: u32, sequence_number: u32, sender_address: rasn_kerberos::HostAddress, ) -> Self`.
- `kadmin::build_change_password_message_with_confounders`: `pub fn build_change_password_message_with_confounders( client_principal: rasn_kerberos::PrincipalName, client_realm: &str, change_data: &ChangePasswdData, service_ticket: rasn_kerberos::Ticket, session_key: &EncryptionKey, options: ChangePasswdMessageOptions, encryption: PasswordEncryption<'_>, ) -> Result<BuiltChangePasswordRequest, Error>`.
- `kadmin::<'request>PasswordEncryption<'request>::new`: `pub const fn new( reply_key: EncryptionKey, ap_req_confounder: &'request [u8], krb_priv_confounder: &'request [u8], ) -> Self`.
- `kadmin::Reply::is_krb_error`: `pub const fn is_krb_error(&self) -> bool`.
- `kadmin::ChangePasswordResult::is_success`: `pub const fn is_success(&self) -> bool`.
- `keytab::Name::parse`: `pub fn parse<P>(name: P) -> Result<Self, Error> where P: AsRef<str>,`.
- `keytab::Keytab::new`: `pub const fn new() -> Self`.
- `keytab::Keytab::load`: `pub fn load<P>(path: P) -> Result<Self, Error> where P: AsRef<Path>,`.
- `keytab::Keytab::load_name`: `pub fn load_name<P>(name: P) -> Result<Self, Error> where P: AsRef<str>,`.
- `keytab::Keytab::save`: `pub fn save<P>(&self, path: P) -> Result<(), Error> where P: AsRef<Path>,`.
- `keytab::Keytab::save_name`: `pub fn save_name<P>(&self, name: P) -> Result<(), Error> where P: AsRef<str>,`.
- `keytab::Keytab::version`: `pub const fn version(&self) -> u8`.
- `keytab::Keytab::entries_mut`: `pub const fn entries_mut(&mut self) -> &mut Vec<Entry>`.
- `keytab::Keytab::add_entry_from_password`: `pub fn add_entry_from_password<P>( &mut self, principal: Principal, password: P, timestamp: SystemTime, kvno: u8, etype: i32, ) -> Result<(), Error> where P: AsRef<[u8]>,`.
- `keytab::Keytab::add_entry_from_password_name`: `pub fn add_entry_from_password_name<P, Q, R>( &mut self, principal_name: P, realm: Q, password: R, timestamp: SystemTime, kvno: u8, etype: i32, ) -> Result<(), Error> where P: AsRef<str>, Q: Into<String>, R: AsRef<[u8]>,`.
- `keytab::Principal::new`: `pub fn new<I, S, P>(realm: P, name_type: i32, components: I) -> Self where I: IntoIterator<Item = S>, S: Into<String>, P: Into<String>,`.
- `keytab::Principal::from_name`: `pub fn from_name<P, Q>(realm: P, name_type: i32, principal_name: Q) -> Result<Self, Error> where P: Into<String>, Q: AsRef<str>,`.
- `krb_priv::EncKrbPrivPartOptions::new`: `pub const fn new(sender_address: rasn_kerberos::HostAddress) -> Self`.
- `krb_priv::EncKrbPrivPartOptions::with_sequence_number`: `pub const fn with_sequence_number(mut self, seq_number: u32) -> Self`.
- `krb_priv::host_address`: `pub fn host_address<P>(addr_type: i32, address: P) -> rasn_kerberos::HostAddress where P: AsRef<[u8]>,`.
- `krb_priv::build_enc_krb_priv_part`: `pub fn build_enc_krb_priv_part<P>( user_data: P, options: EncKrbPrivPartOptions, ) -> rasn_kerberos::EncKrbPrivPart where P: AsRef<[u8]>,`.
- `krb_priv::build`: `pub fn build_krb_priv<P>( user_data: P, options: EncKrbPrivPartOptions, key: &EncryptionKey, kvno: Option<u32>, ) -> Result<rasn_kerberos::KrbPriv, Error> where P: AsRef<[u8]>,`.
- `krb_priv::build_krb_priv_with_confounder`: `pub fn build_krb_priv_with_confounder<P>( user_data: P, options: EncKrbPrivPartOptions, key: &EncryptionKey, kvno: Option<u32>, confounder: &[u8], ) -> Result<rasn_kerberos::KrbPriv, Error> where P: AsRef<[u8]>,`.
- `pac::NtlmSupplementalCredential::has_lm_password`: `pub const fn has_lm_password(&self) -> bool`.
- `pac::NtlmSupplementalCredential::has_nt_password`: `pub const fn has_nt_password(&self) -> bool`.
- `pac::ClaimValues::len`: `pub const fn len(&self) -> usize`.
- `pac::ClaimValues::is_empty`: `pub const fn is_empty(&self) -> bool`.
- `pac::FileTime::from_ticks`: `pub const fn from_ticks(ticks: u64) -> Self`.
- `pac::FileTime::ticks`: `pub const fn ticks(self) -> u64`.
- `service::ValidatedApReq::build_ap_rep_with_confounder`: `pub fn build_ap_rep_with_confounder( &self, confounder: &[u8], options: &ApRepOptions, ) -> Result<Vec<u8>, Error>`.
- `service::Validator<'static>::from_keytab_name`: `pub fn from_keytab_name<P>(keytab_name: P) -> Result<Self, Error> where P: AsRef<str>,`.
- `spnego::oid::validate_arcs`: `pub(super) const fn validate_arcs(arcs: &[u32]) -> Result<(), Error>`.
- `spnego::MicToken::new`: `pub const fn new(flags: u8, snd_seq_num: u64) -> Self`.
- `spnego::MicToken::with_payload`: `pub fn with_payload<P>(mut self, payload: P) -> Self where P: Into<Vec<u8>>,`.
- `spnego::MicToken::new_initiator`: `pub fn new_initiator<P>(payload: P, key: &EncryptionKey) -> Result<Self, Error> where P: Into<Vec<u8>>,`.
- `spnego::WrapToken::new`: `pub const fn new(flags: u8, snd_seq_num: u64) -> Self`.
- `spnego::WrapToken::with_payload`: `pub fn with_payload<P>(mut self, payload: P) -> Self where P: Into<Vec<u8>>,`.
- `spnego::WrapToken::new_initiator`: `pub fn new_initiator<P>(payload: P, key: &EncryptionKey) -> Result<Self, Error> where P: Into<Vec<u8>>,`.
- `spnego::WrapToken::new_initiator_sealed`: `pub fn new_initiator_sealed<P>(payload: P, key: &EncryptionKey) -> Result<Self, Error> where P: Into<Vec<u8>>,`.
- `spnego::WrapToken::new_initiator_sealed_with_confounder`: `pub fn new_initiator_sealed_with_confounder<P>( payload: P, key: &EncryptionKey, confounder: &[u8], ) -> Result<Self, Error> where P: Into<Vec<u8>>,`.
- `spnego::WrapToken::is_sealed`: `pub const fn is_sealed(&self) -> bool`.
- `spnego::NegTokenResp::reject`: `pub const fn reject() -> Self`.
- `spnego::InitiatorContextOptions::with_context_flags`: `pub fn with_context_flags<P>(mut self, context_flags: P) -> Self where P: Into<Vec<u32>>,`.
- `spnego::InitiatorContextOptions::with_ap_option_bits`: `pub const fn with_ap_option_bits(mut self, ap_option_bits: u32) -> Self`.
- `spnego::InitiatorContextOptions::with_sequence_number`: `pub const fn with_sequence_number(mut self, sequence_number: Option<u32>) -> Self`.
- `spnego::AcceptedContext::ap_rep_response_header`: `pub fn ap_rep_response_header(&self, options: &ApRepOptions) -> Result<String, Error>`.
- `spnego::AcceptedContext::ap_rep_response_header_with_confounder`: `pub fn ap_rep_response_header_with_confounder( &self, confounder: &[u8], options: &ApRepOptions, ) -> Result<String, Error>`.
- `spnego::challenge_header`: `pub const fn challenge_header() -> &'static str`.

## Renamed paths

The following map is exhaustive. Paths are relative to `rskrb5_ng`; error
texts and runtime behavior are unchanged.

| From | To |
| --- | --- |
| `Error` | `error::Any` |
| `ap_rep::Error` | `error::ApRep` |
| `ap_req::Error` | `error::ApReq` |
| `ccache::Error` | `error::Ccache` |
| `client::Error` | `error::Client` |
| `config::Error` | `error::Config` |
| `crypto::Error` | `error::Crypto` |
| `http::Error` | `error::Http` |
| `kadmin::Error` | `error::Kadmin` |
| `kdc_rep::Error` | `error::KdcRep` |
| `kdc_req::Error` | `error::KdcReq` |
| `keytab::Error` | `error::Keytab` |
| `krb_cred::Error` | `error::KrbCred` |
| `krb_error::Error` | `error::KrbErrorCodec` |
| `krb_priv::Error` | `error::KrbPriv` |
| `krb_safe::Error` | `error::KrbSafe` |
| `messages::Error` | `error::Messages` |
| `pac::Error` | `error::Pac` |
| `service::Error` | `error::Service` |
| `spnego::Error` | `error::Spnego` |
| `ticket::Error` | `error::Ticket` |
| `ap_rep::build_ap_rep` | `ap_rep::build` |
| `ap_rep::decode_ap_rep` | `ap_rep::decode` |
| `ap_rep::encode_ap_rep` | `ap_rep::encode` |
| `ap_rep::validate_ap_rep` | `ap_rep::validate` |
| `ap_rep::encode_build_ap_rep` | `ap_rep::build_encoded` |
| `ap_req::build_ap_req` | `ap_req::build` |
| `ap_req::decode_ap_req` | `ap_req::decode` |
| `ap_req::encode_ap_req` | `ap_req::encode` |
| `ap_req::validate_ap_req` | `ap_req::validate` |
| `ap_req::encode_build_ap_req` | `ap_req::build_encoded` |
| `ticket::build_ticket` | `ticket::build` |
| `ticket::decode_ticket` | `ticket::decode` |
| `ticket::encode_ticket` | `ticket::encode` |
| `ticket::validate_ticket` | `ticket::validate` |
| `ticket::encode_build_ticket` | `ticket::build_encoded` |
| `krb_priv::build_krb_priv` | `krb_priv::build` |
| `krb_priv::decode_krb_priv` | `krb_priv::decode` |
| `krb_priv::encode_krb_priv` | `krb_priv::encode` |
| `krb_priv::validate_krb_priv` | `krb_priv::validate` |
| `krb_safe::build_krb_safe` | `krb_safe::build` |
| `krb_safe::decode_krb_safe` | `krb_safe::decode` |
| `krb_safe::encode_krb_safe` | `krb_safe::encode` |
| `krb_error::decode_krb_error` | `krb_error::decode` |
| `krb_error::encode_krb_error` | `krb_error::encode` |
| `krb_error::validate_krb_error` | `krb_error::validate` |
| `krb_safe::krb_safe_checksum` | `krb_safe::checksum` |
| `krb_error::krb_error_info` | `krb_error::info` |
| `krb_cred::decode_krb_cred` | `krb_cred::decode` |
| `krb_cred::encrypt_ccache_credentials_to_krb_cred` | `krb_cred::encrypt_ccache_credentials` |
| `krb_cred::encode_encrypt_ccache_credentials_to_krb_cred` | `krb_cred::encode_encrypted_ccache_credentials` |
| `client::TokioClient` | `client::Tokio` |
| `client::NegotiateClient` | `client::negotiate::Client` |
| `client::BlockingNegotiateClient` | `client::negotiate::BlockingClient` |
| `service::ServiceValidator` | `service::Validator` |
| `keytab::KeytabName` | `keytab::Name` |
| `keytab::KeytabEntryMetadata` | `keytab::EntryMetadata` |
| `spnego::SpnegoToken` | `spnego::Token` |
| `spnego::ObjectIdentifier` | `spnego::oid::ObjectIdentifier` |
| `krb_error::KrbErrorInfo` | `messages::KrbErrorInfo` |
| `krb_error::PrincipalNameInfo` | `messages::PrincipalNameInfo` |
| `client::Principal` | `client::principal::Principal` |
| `client::AsReqOptions` | `client::options::AsReq` |
| `client::TgsReqOptions` | `client::options::TgsReq` |
| `client::ApReqOptions` | `client::options::ApReq` |
| `client::KdcEndpoint` | `client::transport::KdcEndpoint` |
| `client::KdcEndpointSource` | `client::transport::KdcEndpointSource` |
| `client::KdcProtocol` | `client::transport::KdcProtocol` |
| `client::TokioKdcTransport` | `client::transport::Tokio` |
| `client::BuiltKpasswdRequest` | `client::kpasswd::BuiltKpasswdRequest` |
| `client::KpasswdRequestOptions` | `client::kpasswd::RequestOptions` |
| `client::VerifiedKpasswdApRep` | `client::kpasswd::VerifiedKpasswdApRep` |
| `client::build_kpasswd_request` | `client::kpasswd::build_kpasswd_request` |
| `client::build_kpasswd_request_with_confounders` | `client::kpasswd::build_kpasswd_request_with_confounders` |
| `client::verify_kpasswd_ap_rep` | `client::kpasswd::verify_kpasswd_ap_rep` |
| `kadmin::EncKrbPrivPartOptions` | `krb_priv::EncKrbPrivPartOptions` |
| `kadmin::KRB_PRIV_ENCPART_USAGE` | `krb_priv::KRB_PRIV_ENCPART_USAGE` |
| `kadmin::KRB_PRIV_MSG_TYPE` | `krb_priv::KRB_PRIV_MSG_TYPE` |
| `kadmin::KRB_PRIV_PVNO` | `krb_priv::KRB_PRIV_PVNO` |
| `kadmin::host_address` | `krb_priv::host_address` |
| `kadmin::ipv4_host_address` | `krb_priv::ipv4_host_address` |
| `kadmin::ipv6_host_address` | `krb_priv::ipv6_host_address` |
| `evaluation::ASN1_FIXTURES` | `evaluation::data::ASN1_FIXTURES` |
| `evaluation::ASSESSMENTS` | `evaluation::data::ASSESSMENTS` |
| `evaluation::Asn1Fixture` | `evaluation::data::Asn1Fixture` |
| `evaluation::Candidate` | `evaluation::data::Candidate` |
| `evaluation::CandidateAssessment` | `evaluation::data::CandidateAssessment` |
| `evaluation::CandidateReport` | `evaluation::data::CandidateReport` |
| `evaluation::Capability` | `evaluation::data::Capability` |
| `evaluation::ContractArea` | `evaluation::data::ContractArea` |
| `evaluation::DerType` | `evaluation::data::DerType` |
| `evaluation::REPORTS` | `evaluation::data::REPORTS` |
| `evaluation::Support` | `evaluation::data::Support` |
| `evaluation::SupportByArea` | `evaluation::data::SupportByArea` |
| `evaluation::V8_CONTRACT` | `evaluation::data::V8_CONTRACT` |
| `client::Error::ClientPrincipalMismatch` | `error::Client::PrincipalMismatch` |
| `config::Error::NoDefaultConfig` | `error::Config::NoDefault` |
| `kadmin::Error::MissingKrbError` | `error::Kadmin::MissingKrb` |
| `Error::KrbError` | `error::Any::Krb` |

The newly public defining modules are `client::{kpasswd, negotiate, options,
principal, transport}`, `spnego::oid`, and `evaluation::data`; `error` is new.
The only public re-exports are the crate-root facade: `Principal`,
`TokioClient`, `NegotiateClient`, `BlockingNegotiateClient`, `Config`, and
`ServiceValidator`. These keep their familiar root names. References in the
API dump normalize these aliases to their defining paths; duplicate alias
expansions do not represent distinct items.

The old module-local error path is private and no longer resolves externally:

```compile_fail
use rskrb5_ng::client::Error;
```

Use the public domain error instead:

```rust
# #[cfg(feature = "messages")]
# {
use rskrb5_ng::error::Client;
let error = Client::PrincipalMismatch {
    expected: "alice@EXAMPLE.COM".to_owned(),
    actual: "bob@EXAMPLE.COM".to_owned(),
};
assert!(matches!(error, Client::PrincipalMismatch { .. }));
# }
```
