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

## Signature changes

### Earlier compliance passes

The lifetime parameter on `service::ServiceValidator`, `http::NegotiateLayer`,
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
- `service::ServiceValidator::{new, require_client_address, shared_replay_cache,
  with_client_address, with_keytab_principal, with_max_clock_skew, with_now,
  with_shared_replay_cache, without_shared_replay_cache}`;
- `evaluation::render_markdown`.

The earlier pass also made these public APIs `const fn`:

- `service::ServiceValidator::{with_now, with_max_clock_skew,
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
- `client::{build_kpasswd_request, build_kpasswd_request_with_confounders}` borrow
  their `KpasswdRequestOptions`; `service::ValidatedApReq::build_ap_rep_with_confounder`
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
- `client::kpasswd::KpasswdRequestOptions::with_recipient_address`.
- `client::negotiate::NegotiateClient::from_tokio_client`.
- `client::negotiate::NegotiateClient::with_keytab`.
- `client::negotiate::NegotiateClient::inner`.
- `client::negotiate::NegotiateClient::into_inner`.
- `client::options::AsReqOptions::new`.
- `client::options::AsReqOptions::from_libdefaults`.
- `client::options::AsReqOptions::with_ticket_lifetime`.
- `client::options::AsReqOptions::with_renew_lifetime`.
- `client::options::AsReqOptions::with_etypes`.
- `client::options::AsReqOptions::with_kdc_option_bits`.
- `client::options::AsReqOptions::with_padata`.
- `client::options::AsReqOptions::with_assume_preauthentication`.
- `client::options::AsReqOptions::with_fast_negotiation`.
- `client::options::TgsReqOptions::new`.
- `client::options::TgsReqOptions::from_libdefaults`.
- `client::options::TgsReqOptions::with_ticket_lifetime`.
- `client::options::TgsReqOptions::with_renew_lifetime`.
- `client::options::TgsReqOptions::with_etypes`.
- `client::options::TgsReqOptions::with_kdc_option_bits`.
- `client::options::TgsReqOptions::with_padata`.
- `client::options::TgsReqOptions::with_additional_tickets`.
- `client::options::TgsReqOptions::with_renewal`.
- `client::options::ApReqOptions::new`.
- `client::options::ApReqOptions::with_ap_option_bits`.
- `client::options::ApReqOptions::with_checksum`.
- `client::options::ApReqOptions::with_subkey`.
- `client::options::ApReqOptions::with_sequence_number`.
- `client::principal::Principal::name`.
- `client::transport::KdcEndpoint::authority`.
- `client::transport::TokioKdcTransport::new`.
- `client::transport::TokioKdcTransport::with_timeout`.
- `client::transport::TokioKdcTransport::with_udp_response_limit`.
- `client::transport::TokioKdcTransport::with_tcp_response_limit`.
- `client::TokioClientDiagnostics::is_ok`.
- `client::PrunedSessions::is_empty`.
- `client::TokioClientAutoRenewal::is_finished`.
- `client::TokioClient::with_keytab`.
- `client::TokioClient::with_password_credential`.
- `client::TokioClient::with_keytab_credential`.
- `client::TokioClient::from_ccache`.
- `client::TokioClient::from_tgt_session`.
- `client::TokioClient::with_transport`.
- `client::TokioClient::with_assume_preauthentication`.
- `client::TokioClient::with_fast_negotiation`.
- `client::TokioClient::config`.
- `client::TokioClient::protocol`.
- `client::TokioClient::client_principal`.
- `client::TokioClient::is_configured`.
- `client::TokioClient::assume_preauthentication`.
- `client::TokioClient::fast_negotiation`.
- `client::TokioClient::tgt_session`.
- `client::TokioClient::tgt_refresh_due`.
- `client::TokioClient::tgt_session_count`.
- `client::TokioClient::tgt_session_for_realm`.
- `client::TokioClient::cached_service_ticket_count`.
- `client::TokioClient::cached_service_ticket`.
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
- `keytab::KeytabName::file_path`.
- `keytab::KeytabName::into_file_path`.
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
- `service::ServiceValidator<'static>::from_keytab`.
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
- `client::kpasswd::KpasswdRequestOptions::new`: `pub const fn new( timestamp: SystemTime, cusec: u32, sequence_number: u32, sender_address: rasn_kerberos::HostAddress, ) -> Self`.
- `client::kpasswd::build_kpasswd_request_with_confounders`: `pub fn build_kpasswd_request_with_confounders( service_ticket: &TgsRepSession, change_data: &kadmin::ChangePasswdData, reply_key: EncryptionKey, options: &KpasswdRequestOptions, ap_req_confounder: &[u8], krb_priv_confounder: &[u8], ) -> Result<BuiltKpasswdRequest, Error>`.
- `client::kpasswd::build_kpasswd_request`: `pub fn build_kpasswd_request( service_ticket: &TgsRepSession, change_data: &kadmin::ChangePasswdData, options: &KpasswdRequestOptions, ) -> Result<BuiltKpasswdRequest, Error>`.
- `client::negotiate::NegotiateClient::from_tokio_client`: `pub const fn from_tokio_client(client: TokioClient) -> Self`.
- `client::negotiate::NegotiateClient::with_password`: `pub fn with_password<P>(config: Config, client: Principal, password: P) -> Self where P: Into<Vec<u8>>,`.
- `client::negotiate::NegotiateClient::with_keytab`: `pub const fn with_keytab(config: Config, client: Principal, keytab: Keytab) -> Self`.
- `client::negotiate::NegotiateClient::with_keytab_name`: `pub fn with_keytab_name<P>( config: Config, client: Principal, keytab_name: P, ) -> Result<Self, Error> where P: AsRef<str>,`.
- `client::negotiate::NegotiateClient::from_ccache_name`: `pub fn from_ccache_name<P>(config: Config, cache_name: P) -> Result<Self, Error> where P: AsRef<str>,`.
- `client::negotiate::NegotiateClient::inner`: `pub const fn inner(&self) -> &TokioClient`.
- `client::negotiate::NegotiateClient::inner_mut`: `pub const fn inner_mut(&mut self) -> &mut TokioClient`.
- `client::negotiate::NegotiateClient::authorization_header_for_host`: `pub async fn authorization_header_for_host<P, Q>( &mut self, service: P, host: Q, ) -> Result<String, Error> where P: AsRef<str>, Q: AsRef<str>,`.
- `client::negotiate::NegotiateClient::authorization_context_for_host`: `pub async fn authorization_context_for_host<P, Q>( &mut self, service: P, host: Q, ) -> Result<InitiatorContext, Error> where P: AsRef<str>, Q: AsRef<str>,`.
- `client::negotiate::NegotiateClient::change_password`: `pub async fn change_password<P>( &mut self, new_password: P, sender_address: rasn_kerberos::HostAddress, ) -> Result<ChangePasswordResult, Error> where P: AsRef<[u8]>,`.
- `client::negotiate::NegotiateClient::change_password_for`: `pub async fn change_password_for<P>( &mut self, target: Principal, new_password: P, sender_address: rasn_kerberos::HostAddress, ) -> Result<ChangePasswordResult, Error> where P: AsRef<[u8]>,`.
- `client::negotiate::NegotiateClient::change_password_with_options`: `pub async fn change_password_with_options<P>( &mut self, new_password: P, options: KpasswdRequestOptions, ) -> Result<ChangePasswordResult, Error> where P: AsRef<[u8]>,`.
- `client::negotiate::NegotiateClient::change_password_for_with_options`: `pub async fn change_password_for_with_options<P>( &mut self, target: Principal, new_password: P, options: KpasswdRequestOptions, ) -> Result<ChangePasswordResult, Error> where P: AsRef<[u8]>,`.
- `client::negotiate::BlockingNegotiateClient::with_password`: `pub fn with_password<P>(config: Config, client: Principal, password: P) -> Result<Self, Error> where P: Into<Vec<u8>>,`.
- `client::negotiate::BlockingNegotiateClient::with_keytab_name`: `pub fn with_keytab_name<P>( config: Config, client: Principal, keytab_name: P, ) -> Result<Self, Error> where P: AsRef<str>,`.
- `client::negotiate::BlockingNegotiateClient::from_ccache_name`: `pub fn from_ccache_name<P>(config: Config, cache_name: P) -> Result<Self, Error> where P: AsRef<str>,`.
- `client::negotiate::BlockingNegotiateClient::client`: `pub const fn client(&self) -> &NegotiateClient`.
- `client::negotiate::BlockingNegotiateClient::client_mut`: `pub const fn client_mut(&mut self) -> &mut NegotiateClient`.
- `client::negotiate::BlockingNegotiateClient::authorization_header_for_host`: `pub fn authorization_header_for_host<P, Q>( &mut self, service: P, host: Q, ) -> Result<String, Error> where P: AsRef<str>, Q: AsRef<str>,`.
- `client::negotiate::BlockingNegotiateClient::authorization_context_for_host`: `pub fn authorization_context_for_host<P, Q>( &mut self, service: P, host: Q, ) -> Result<InitiatorContext, Error> where P: AsRef<str>, Q: AsRef<str>,`.
- `client::negotiate::BlockingNegotiateClient::change_password`: `pub fn change_password<P>( &mut self, new_password: P, sender_address: rasn_kerberos::HostAddress, ) -> Result<ChangePasswordResult, Error> where P: AsRef<[u8]>,`.
- `client::negotiate::BlockingNegotiateClient::change_password_for`: `pub fn change_password_for<P>( &mut self, target: Principal, new_password: P, sender_address: rasn_kerberos::HostAddress, ) -> Result<ChangePasswordResult, Error> where P: AsRef<[u8]>,`.
- `client::negotiate::BlockingNegotiateClient::change_password_with_options`: `pub fn change_password_with_options<P>( &mut self, new_password: P, options: KpasswdRequestOptions, ) -> Result<ChangePasswordResult, Error> where P: AsRef<[u8]>,`.
- `client::negotiate::BlockingNegotiateClient::change_password_for_with_options`: `pub fn change_password_for_with_options<P>( &mut self, target: Principal, new_password: P, options: KpasswdRequestOptions, ) -> Result<ChangePasswordResult, Error> where P: AsRef<[u8]>,`.
- `client::options::AsReqOptions::with_ticket_lifetime`: `pub const fn with_ticket_lifetime(mut self, ticket_lifetime: Duration) -> Self`.
- `client::options::AsReqOptions::with_renew_lifetime`: `pub const fn with_renew_lifetime(mut self, renew_lifetime: Option<Duration>) -> Self`.
- `client::options::AsReqOptions::with_etypes`: `pub fn with_etypes<P>(mut self, etypes: P) -> Self where P: Into<Vec<i32>>,`.
- `client::options::AsReqOptions::with_kdc_option_bits`: `pub const fn with_kdc_option_bits(mut self, kdc_option_bits: u32) -> Self`.
- `client::options::AsReqOptions::with_padata`: `pub fn with_padata<P>(mut self, padata: P) -> Self where P: Into<Vec<rasn_kerberos::PaData>>,`.
- `client::options::AsReqOptions::with_assume_preauthentication`: `pub const fn with_assume_preauthentication(mut self, assume_preauthentication: bool) -> Self`.
- `client::options::AsReqOptions::with_fast_negotiation`: `pub const fn with_fast_negotiation(mut self, fast_negotiation: bool) -> Self`.
- `client::options::TgsReqOptions::with_ticket_lifetime`: `pub const fn with_ticket_lifetime(mut self, ticket_lifetime: Duration) -> Self`.
- `client::options::TgsReqOptions::with_renew_lifetime`: `pub const fn with_renew_lifetime(mut self, renew_lifetime: Option<Duration>) -> Self`.
- `client::options::TgsReqOptions::with_etypes`: `pub fn with_etypes<P>(mut self, etypes: P) -> Self where P: Into<Vec<i32>>,`.
- `client::options::TgsReqOptions::with_kdc_option_bits`: `pub const fn with_kdc_option_bits(mut self, kdc_option_bits: u32) -> Self`.
- `client::options::TgsReqOptions::with_padata`: `pub fn with_padata<P>(mut self, padata: P) -> Self where P: Into<Vec<rasn_kerberos::PaData>>,`.
- `client::options::TgsReqOptions::with_additional_tickets`: `pub fn with_additional_tickets<P>(mut self, additional_tickets: P) -> Self where P: Into<Vec<rasn_kerberos::Ticket>>,`.
- `client::options::TgsReqOptions::with_renewal`: `pub const fn with_renewal(mut self) -> Self`.
- `client::options::ApReqOptions::new`: `pub const fn new() -> Self`.
- `client::options::ApReqOptions::with_ap_option_bits`: `pub const fn with_ap_option_bits(mut self, ap_option_bits: u32) -> Self`.
- `client::options::ApReqOptions::with_sequence_number`: `pub const fn with_sequence_number(mut self, sequence_number: Option<u32>) -> Self`.
- `client::principal::Principal::new`: `pub fn new<I, S, P>(realm: P, name_type: i32, components: I) -> Self where I: IntoIterator<Item = S>, S: Into<String>, P: Into<String>,`.
- `client::principal::Principal::user`: `pub fn user<P, Q>(realm: P, name: Q) -> Self where P: Into<String>, Q: Into<String>,`.
- `client::principal::Principal::parse_user`: `pub fn parse_user<P>(value: P) -> Result<Self, Error> where P: AsRef<str>,`.
- `client::principal::Principal::parse_service`: `pub fn parse_service<P>(value: P) -> Result<Self, Error> where P: AsRef<str>,`.
- `client::principal::Principal::host_based_service`: `pub fn host_based_service<P, Q>(service: P, host: Q) -> Result<Self, Error> where P: AsRef<str>, Q: AsRef<str>,`.
- `client::principal::Principal::host_based_service_in_realm`: `pub fn host_based_service_in_realm<P, Q, R>( service: P, host: Q, realm: R, ) -> Result<Self, Error> where P: AsRef<str>, Q: AsRef<str>, R: AsRef<str>,`.
- `client::principal::Principal::tgt_service`: `pub fn tgt_service<P>(realm: P) -> Self where P: Into<String>,`.
- `client::transport::TokioKdcTransport::new`: `pub const fn new() -> Self`.
- `client::transport::TokioKdcTransport::with_timeout`: `pub const fn with_timeout(mut self, timeout: Duration) -> Self`.
- `client::transport::TokioKdcTransport::with_udp_response_limit`: `pub const fn with_udp_response_limit(mut self, udp_response_limit: usize) -> Self`.
- `client::transport::TokioKdcTransport::with_tcp_response_limit`: `pub const fn with_tcp_response_limit(mut self, tcp_response_limit: usize) -> Self`.
- `client::TokioClientDiagnostics::is_ok`: `pub const fn is_ok(&self) -> bool`.
- `client::PrunedSessions::is_empty`: `pub const fn is_empty(&self) -> bool`.
- `client::TokioClient::with_password`: `pub fn with_password<P>( config: Config, protocol: KdcProtocol, client: Principal, password: P, ) -> Self where P: Into<Vec<u8>>,`.
- `client::TokioClient::with_keytab`: `pub const fn with_keytab( config: Config, protocol: KdcProtocol, client: Principal, keytab: Keytab, ) -> Self`.
- `client::TokioClient::with_keytab_name`: `pub fn with_keytab_name<P>( config: Config, protocol: KdcProtocol, client: Principal, keytab_name: P, ) -> Result<Self, Error> where P: AsRef<str>,`.
- `client::TokioClient::with_password_credential`: `pub fn with_password_credential<P>(mut self, password: P) -> Self where P: Into<Vec<u8>>,`.
- `client::TokioClient::from_ccache_name`: `pub fn from_ccache_name<P>( config: Config, protocol: KdcProtocol, cache_name: P, ) -> Result<Self, Error> where P: AsRef<str>,`.
- `client::TokioClient::save_ccache`: `pub fn save_ccache<P>(&self, path: P) -> Result<(), Error> where P: AsRef<Path>,`.
- `client::TokioClient::save_ccache_name`: `pub fn save_ccache_name<P>(&self, cache_name: P) -> Result<(), Error> where P: AsRef<str>,`.
- `client::TokioClient::update_ccache_file`: `pub fn update_ccache_file<P>(&self, path: P) -> Result<(), Error> where P: AsRef<Path>,`.
- `client::TokioClient::update_ccache_name`: `pub fn update_ccache_name<P>(&self, cache_name: P) -> Result<(), Error> where P: AsRef<str>,`.
- `client::TokioClient::with_transport`: `pub const fn with_transport(mut self, transport: TokioKdcTransport) -> Self`.
- `client::TokioClient::with_assume_preauthentication`: `pub const fn with_assume_preauthentication(mut self, assume_preauthentication: bool) -> Self`.
- `client::TokioClient::with_fast_negotiation`: `pub const fn with_fast_negotiation(mut self, fast_negotiation: bool) -> Self`.
- `client::TokioClient::config`: `pub const fn config(&self) -> &Config`.
- `client::TokioClient::protocol`: `pub const fn protocol(&self) -> KdcProtocol`.
- `client::TokioClient::client_principal`: `pub const fn client_principal(&self) -> &Principal`.
- `client::TokioClient::assume_preauthentication`: `pub const fn assume_preauthentication(&self) -> bool`.
- `client::TokioClient::fast_negotiation`: `pub const fn fast_negotiation(&self) -> bool`.
- `client::TokioClient::tgt_session`: `pub const fn tgt_session(&self) -> Option<&AsRepSession>`.
- `client::build_tgs_req_for_realm`: `pub fn build_tgs_req_for_realm<P>( tgt: &AsRepSession, kdc_realm: P, service: Principal, options: TgsReqOptions, ) -> Result<BuiltTgsReq, Error> where P: Into<String>,`.
- `client::build_tgs_req_for_realm_with_confounder`: `pub fn build_tgs_req_for_realm_with_confounder<P>( tgt: &AsRepSession, kdc_realm: P, service: Principal, options: TgsReqOptions, timestamp: SystemTime, cusec: u32, confounder: &[u8], ) -> Result<BuiltTgsReq, Error> where P: Into<String>,`.
- `client::build_tgs_req_for_realm_with_confounder_and_subkey`: `pub fn build_tgs_req_for_realm_with_confounder_and_subkey<R>( tgt: &AsRepSession, kdc_realm: R, service: Principal, parts: TgsRequestParts<'_>, ) -> Result<TgsFastRequestParts, Error> where R: Into<String>,`.
- `client::<'request>TgsRequestParts<'request>::new`: `pub const fn new( options: TgsReqOptions, confounder: &'request [u8], subkey: &'request EncryptionKey, ) -> Self`.
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
- `keytab::KeytabName::parse`: `pub fn parse<P>(name: P) -> Result<Self, Error> where P: AsRef<str>,`.
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
- `krb_priv::build_krb_priv`: `pub fn build_krb_priv<P>( user_data: P, options: EncKrbPrivPartOptions, key: &EncryptionKey, kvno: Option<u32>, ) -> Result<rasn_kerberos::KrbPriv, Error> where P: AsRef<[u8]>,`.
- `krb_priv::build_krb_priv_with_confounder`: `pub fn build_krb_priv_with_confounder<P>( user_data: P, options: EncKrbPrivPartOptions, key: &EncryptionKey, kvno: Option<u32>, confounder: &[u8], ) -> Result<rasn_kerberos::KrbPriv, Error> where P: AsRef<[u8]>,`.
- `pac::NtlmSupplementalCredential::has_lm_password`: `pub const fn has_lm_password(&self) -> bool`.
- `pac::NtlmSupplementalCredential::has_nt_password`: `pub const fn has_nt_password(&self) -> bool`.
- `pac::ClaimValues::len`: `pub const fn len(&self) -> usize`.
- `pac::ClaimValues::is_empty`: `pub const fn is_empty(&self) -> bool`.
- `pac::FileTime::from_ticks`: `pub const fn from_ticks(ticks: u64) -> Self`.
- `pac::FileTime::ticks`: `pub const fn ticks(self) -> u64`.
- `service::ValidatedApReq::build_ap_rep_with_confounder`: `pub fn build_ap_rep_with_confounder( &self, confounder: &[u8], options: &ApRepOptions, ) -> Result<Vec<u8>, Error>`.
- `service::ServiceValidator<'static>::from_keytab_name`: `pub fn from_keytab_name<P>(keytab_name: P) -> Result<Self, Error> where P: AsRef<str>,`.
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
