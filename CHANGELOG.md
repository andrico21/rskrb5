# Changelog

## [0.3.0] - unreleased

The first release as `rskrb5-ng` (library `rskrb5_ng`), which continues
`rskrb5` independently from upstream `clelange/rskrb5` `main` at `6f4abc9`.
Changes are listed against `rskrb5-patched` 0.2.2, the last published
version; they include everything prepared for an `rskrb5-patched` 0.3.0 that
was never published. Upgrade steps, with every renamed path and changed
signature, are in
[`docs/migration-from-rskrb5-patched.md`](docs/migration-from-rskrb5-patched.md);
the lineage is in [`PROVENANCE.md`](PROVENANCE.md).

### Crate, library and repository

- The package is `rskrb5-ng` (was `rskrb5-patched`) and the library
  `rskrb5_ng` (was `rskrb5`): depend on `rskrb5-ng = "0.3"` and replace
  `use rskrb5::` with `use rskrb5_ng::`.
- The compatibility-report binary is `rskrb5-ng-compat-report` and the fuzz
  crate `rskrb5-ng-fuzz`.
- The repository is `https://github.com/andrico21/rskrb5-ng`, a standalone
  repository (the old `andrico21/rskrb5` URL redirects there).

### API

- Add opt-in `service::TransitPolicy::{direct, domain_x500_paths}` presets for
  AD cross-domain tickets without TRANSITED-POLICY-CHECKED. Both pin endpoint
  realms; the latter allow-lists exact complete encoded paths. Default rejection
  and rejection of unknown encodings remain unchanged (RSK-3E3C2278).

- Kpasswd preserves definite pre-send errors and reports possible-delivery
  failures as `Client::KpasswdOutcomeUnknown` exactly once, including malformed
  replies. Connection refusal is safely retryable; unknown outcomes are not
  (RSK-14E2755A).

These are breaking; the migration guide maps each one.

- Public structs and enums are `#[non_exhaustive]` and gain constructors or
  `with_*` builders; struct literals no longer compile outside the crate.
- The module-local error types move into the new `error` module
  (`client::Error` is `error::Client`, the crate-level `Error` is
  `error::Any`, and so on); the old paths are private.
- Module-repeating names are dropped (`ap_req::build_ap_req` is
  `ap_req::build`, `service::ServiceValidator` is `service::Validator`,
  `client::TokioClient` is `client::Tokio`), and items move to new public
  modules (`client::{kpasswd, negotiate, options, principal, transport}`,
  `spnego::oid`, `evaluation::data`). The crate-root re-exports `Principal`,
  `TokioClient`, `NegotiateClient`, `BlockingNegotiateClient`, `Config` and
  `ServiceValidator` keep their names.
- `config::LibDefaults` stores enctype names only:
  `default_tkt_enctype_ids`, `default_tgs_enctype_ids` and
  `permitted_enctype_ids` are methods that derive the ids; update the
  `*_enctypes` name lists directly or through `with_*_enctypes` builders. Its
  thirteen boolean options use `config::Toggle`, and the new `allow_rc4` and
  `allow_des3` options join them.
- `config::Realm::realm` is `name`. Several functions borrow their option
  structs, group arguments into parameter structs
  (`client::TgsRequestParts`, `kadmin::PasswordEncryption`) or become
  associated functions; argument-position `impl Trait` becomes a named
  generic; many functions gain `#[must_use]` or become `const fn`.
- New error variants, among them `error::Client::{EnctypeNotRequested,
  EnctypeNotPermitted, KpasswdOutcomeUnknown, UdpResponseTooLarge,
  DnsServiceUnavailable}`, `error::Config::{EnctypeNotPermitted,
      NoPermittedEnctypes, NoUsableEnctypes, UnsupportedEnctype, EnctypeDisabled}`,
  `error::Kadmin::UnauthenticatedSuccess`,
  `error::Ccache::IdentityUnavailable` and
  `http::NegotiateHttpError::MutualAuthenticationNotProven`.
  `http::NegotiateHttpError<E>` becomes `NegotiateHttpError<E, B>`, where `B`
  is the response body type the new variant carries.
- New public fields: `LibDefaults.permitted_enctypes_explicit` and
  `InitiatorContext.context_flags`.

### Dependencies and toolchain

- `rust-version` is 1.99 (was 1.88).
- Every direct dependency is on its latest major version: `base64` 0.23,
  `getrandom` 0.4, `rasn` and `rasn-kerberos` 0.29, `compcol` 0.7,
  `picky-krb` 0.13 (optional, `evaluation`), dev `toml` 1.1, and `pbkdf2`
  0.13 instead of the `=0.13.0-rc.10` pre-release pin. `proptest` is a new
  dev-dependency. No runtime dependency was added.

### Behaviour changes

- Ccache parsing bounds every record count (principal components, addresses,
  authorization data) against the remaining input before reserving memory, so
  a short malformed cache returns `error::Ccache::Truncated` instead of
  aborting the process on a multi-GB allocation.
- kpasswd: a success result is accepted only with authenticated provenance. An
  unsigned KRB-ERROR reply carrying result code 0 is rejected with
  `error::Kadmin::UnauthenticatedSuccess`, and the high-level client keeps
  its stored password; non-zero error results keep their
  `PasswordChangeFailed` behaviour.
- `[libdefaults] permitted_enctypes` is an enctype allowlist when it's set
  explicitly: request lists are narrowed to it and the config-driven AS/TGS
  exchanges reject a session key outside it
  (`error::Client::EnctypeNotPermitted`). An explicit `default_tkt_enctypes`
  or `default_tgs_enctypes` naming an enctype outside an explicit allowlist is
  a parse error (`error::Config::EnctypeNotPermitted`) rather than a silent
  narrowing, checked once on the final values across included files. The
  explicit flag (`LibDefaults.permitted_enctypes_explicit`) survives a serde
  round-trip.
- An explicit allowlist fails closed when it resolves to no supported enctype:
  a parsed `permitted_enctypes` naming only unsupported or disabled names is a
  parse error (`error::Config::NoPermittedEnctypes`) instead of meaning "no
  policy", and a `LibDefaults` built with the explicit flag and an empty
  `permitted_enctypes` list requests no enctype
  (`error::Client::EmptyEtypes`) and rejects every session key
  (`error::Client::EnctypeNotPermitted`).
- MIT's DES3 names `des3-cbc-sha1` and `des3-hmac-sha1` resolve to enctype 16
  like `des3-cbc-sha1-kd`, so an explicit list using them is honoured (subject
  to `allow_des3`, below) instead of silently dropping DES3.
- AS and TGS replies are bound to the requested enctype list: the AS-REP reply
  key enctype and the AS/TGS session-key enctype must appear in the request's
  `etype` list, otherwise `error::Client::EnctypeNotRequested`.
- The TGT refresh band is measured from the current ticket life
  (`end_time - start_time`) instead of `auth_time`, so a just-renewed TGT is no
  longer immediately due.
- Auto-renewal waits `retry_delay` when a refresh fails or leaves the TGT
  unchanged, so a due, non-renewable, cache-only TGT no longer spins a core.
- Automatic paths (`affirm_login`, `refresh_tgt_if_needed`,
  `get_service_ticket`, auto-renewal) recover through an AS exchange when the
  cached TGT has expired or its renewal is refused and a password or keytab is
  configured. Cache-only clients keep the renewal error.
- Host-based service principals fold the DNS host component to lower case
  (RFC 4120 section 6.2.1), so host-case variants name one SPN and share one
  cached service ticket. Service names, realms and `Principal::parse_service`
  keep their case.
- `[libdefaults] clockskew` reaches the `Config`-driven acceptors
  (`service::Validator::from_default_keytab_name`/`from_default_keytab`,
  `NegotiateLayer::from_default_keytab_name`/`from_default_keytab`). The plain
  constructors keep the 300 s default.
- `[domain_realm]` lookups fold the DNS name to lower case (realm values stay
  case-sensitive).
- A bare `[domain_realm]` tag covers its subdomains, as MIT krb5.conf(5)
  defines; at each suffix level the leading-dot tag wins over the bare one.
- Mutual authentication fails closed. The classifier treats a completion
  without an AP-REP as `InvalidToken` when the `mutual-required` AP option or
  `CONTEXT_FLAG_MUTUAL` was requested, and the send wrappers return
  `NegotiateHttpError::MutualAuthenticationNotProven` unless the final
  response carries an AP-REP that verifies against the initiator context.
  Callers that don't request mutual authentication see no change.
- The AP-REQ replay cache also indexes a digest of the authenticator
  ciphertext, so an authenticator re-presented under a rewritten cleartext
  ticket `sname` (for example a keytab alias sharing the service key) is
  rejected (clelange/rskrb5 PR #20, updated).

#### From the review backlog

Each fixed review item with an observable behaviour change, by area. The
dispositions, tests and commits are indexed in `docs/review/README.md`.

SPNEGO, GSS tokens, DER and OIDs:

- OIDs under arc 2 encode, decode and round-trip for every valid `u32` arc;
  a malformed first subidentifier is `InvalidOidEncoding` (RSK-7487E947).
- DER state values and OID arcs that overflow are rejected instead of
  truncated, and so are redundant integer sign octets and non-minimal arcs
  (RSK-2A2C1928).
- Initiation that requests delegation (DELEG) without a credential fails with
  `DelegationRequiresCredential`; the raw checksum helper no longer fabricates
  delegation fields (RSK-622F4664).
- Sealed DES3 Wrap tokens round-trip for payloads of every length, and an
  EC overflow is rejected (RSK-2A906A3A).
- Unsealed Wrap tokens apply the right-rotation count (RRC) on encode and
  decode (RFC 4121 §4.2.5) (RSK-84FA90AE).
- The SPNEGO acceptor accepts an optimistic token for any offered standard or
  Microsoft Kerberos OID. Non-first selection requires a valid mechListMIC;
  supplied first-choice MICs also verify before replay insertion. Replies select
  that OID and include a reciprocal MIC over the received mechanism list when
  one was verified. Missing or invalid MICs fail closed (`MissingMechListMic`,
  `InvalidMechListMic`); stateless continuations remain `NegotiationRequiresState`
  (RFC 4178 §§4-5, RFC 4121 §2) (RSK-C4BE57A0, F2 M1).
- GSS acceptance checks the RFC 4121 §4.1.1 authenticator checksum type and
  framing and requires a sequence number before replay insertion
  (RSK-FAF64A85, run-2 lead `mandatory-gss-authenticator-fields`).
- A Negotiate header longer than 65,536 bytes is rejected with
  `NegotiateHeaderTooLong` before base64 decoding (upstream issue #9).

Service acceptor and HTTP layer:

- The Axum example sets the overlay's security response headers and removes
  `Server`, `X-Powered-By` and the ASP.NET fingerprint headers on every status
  (overlay deviation 8).
- Nonzero fractional seconds in ticket times, the authenticator `ctime` and
  AP-REP construction or verification are rejected with
  `Service::FractionalKerberosTime` (RFC 4120 §5.2.3) (RSK-B161A328).
- Authenticator and AP-REP microseconds outside 0..=999999 are rejected
  (RSK-985742B6).
- Replay caches own their skew and capacity (300 s and 65,536 records by
  default), expire entries automatically, reject a wider shared skew and a
  clock rollback larger than the configured maximum skew, tolerate smaller or
  equal backward steps without lowering the high-water mark, and fail closed
  when full (RSK-7D80FA41, run-2 lead
  `ReplayCache:indefinite-entry-retention`).
- Ticket and authenticator authorization data are validated before success:
  unknown critical elements and unsupported AD-KDCIssued or AD-AND-OR are
  rejected, within eight wrappers and 1 MiB of decoded payload (RFC 4120
  §5.2.6) (RSK-D1D6BDC3, run-2 lead `mandatory-authorization-data-discarded`).
- A cross-realm ticket without TRANSITED-POLICY-CHECKED is rejected unless a
  caller-supplied `TransitValidator` accepts its path (RFC 4120 §§2.7,
  3.3.3.2) (RSK-3E3C2278, run-2 lead `unchecked-cross-realm-transit`).
- Tickets with `tkt-vno` other than 5 and authenticators with
  `authenticator-vno` other than 5 are rejected (RSK-39F18D3B).

Cryptography and key derivation:

- RC4-HMAC encodes key usages as four-byte little-endian (RFC 4757 §3), so
  high usages no longer alias (RSK-11BF294C).
- The AES-SHA2 PRF accepts an empty input string (RFC 8009) (RSK-FA2BF25E).
- AES string-to-key and password reply-key derivation reject iteration counts
  above 2^24 with `Crypto::IterationCountTooHigh` before running PBKDF2
  (RSK-F240C18F, run-2 lead
  `s2kparams_to_iterations:unauthenticated-pbkdf2-work`).
- AES-SHA2 decryption verifies the HMAC before decrypting (RFC 8009 §5)
  (RSK-CE4ACA12).
- AES-SHA1 and DES3 key derivation reject constants longer than the cipher
  block with `Crypto::DerivationConstantTooLong` (RSK-8F3B02EE).
- Key-derived scratch buffers are zeroized: password encodings, PBKDF2 and
  DR intermediates, derived keys, decrypted buffers and HMAC key blocks
  (RSK-DEF6C438, upstream issue #6).

PAC and NDR:

- PAC lookup in authorization data stops at eight wrappers and 1 MiB of
  visited payload (RSK-6DF06BE8, run-2 lead
  `pac.authorization-data.unbounded-if-relevant-recursion`).
- Claims decompression has an independent 1 MiB output ceiling
  (RSK-B5912AE2, run-2 lead `pac.claims-decompression.peer-controlled-cap`).
- Credential counts (at most 1,000,000) are checked against the remaining
  input before reserving memory (RSK-A9B8B032, run-2 lead
  `pac.ndr.supplemental-credentials-unbounded-capacity`).
- PAC_CREDENTIAL_DATA parsing consumes and checks the NDR conformant count
  (MS-PAC 2.6.2) (RSK-DB101DC5).
- NTLM supplemental credentials use the validity masks 1 and 2 and reject a
  record with neither (MS-PAC 2.6.4) (RSK-8BA3D269).
- Both fixed NTLM hash slots are consumed whatever the validity flags say
  (RSK-59B45280).
- Boolean claims decode as aligned 64-bit values and reject values other than
  0 and 1 (RSK-8E17F182).
- Decrypted PAC credentials are zeroized and print redacted (RSK-5E15962F).
- The NDR private-header object length must equal the object extent
  (RSK-6A286805).
- SID summaries deduplicate with a set and keep first-seen order
  (RSK-D33671B2).

Client AS/TGS exchanges, renewal and caches:

- TGS authenticators carry the client realm, not the ticket issuer realm
  (RFC 4120 §5.5.1) (RSK-AFE184E0).
- Password and keytab preauthentication retries echo the latest PA-FX-COOKIE
  (RFC 6113 §5.2) (RSK-34601373).
- Initial password AS replies use the reply's ETYPE-INFO2, ETYPE-INFO or
  PW-SALT salt and parameters (RSK-072A268D).
- AS request-integrity checks no longer require FAST to be advertised
  (RFC 6806 §11) (RSK-2099CE19).
- TGS replies are checked for the negotiated request checksum (RFC 6806 §11)
  (RSK-BC016031).
- An explicit login always replaces the primary TGT and clears dependent
  service tickets (RSK-F526D18D).
- Tickets with the INVALID flag are not used and not renewed in place of
  validation (RSK-E48DA39B).
- Service-ticket cache keys keep realm and component boundaries
  (RSK-1922A31B).
- Unarmored AS requests no longer set the canonicalize option (RFC 6806 §6)
  (RSK-45397760).
- S4U2Self and S4U2Proxy bind the delegated client to the decrypted ticket
  and the request; a missing service key fails with `DelegationKeyRequired`,
  a mismatch with `DelegationPrincipalMismatch` (run-2 lead
  `s4u-delegation:delegated-client-unbound-to-ticket-payload`).

kpasswd, KRB-PRIV/KRB-SAFE messages and secrets:

- KRB-SAFE checksums are generated and verified over the whole DER KRB-SAFE
  with an empty checksum placeholder (RFC 4120 §5.6.1), not over the body
  only (RSK-A5F7D975).
- Bare RFC 3244 KRB-ERROR replies to kpasswd are accepted and keep their
  encoding; they never count as success (RSK-3B6BA222).
- The kpasswd result checks the KRB-PRIV sequence number or timestamp (within
  300 s), microseconds and sender addresses (RSK-789A6FBB).
- Whole-message decoders (AP, KDC, ticket and KRB messages) reject trailing
  bytes, and kpasswd frames must match their declared length
  (RSK-0C0007B7).
- Microsecond and whole-second KerberosTime limits apply to KRB-ERROR
  diagnostics, kpasswd request values and kpasswd AP-REP times
  (RSK-6A673A85).
- Password plaintext copies are zeroized and print redacted (RSK-471362A3,
  upstream issue #1).
- A kpasswd exchange that fails after the request may have been delivered
  returns `Client::KpasswdOutcomeUnknown` (RSK-14E2755A, upstream issue #8).

Transport, DNS, IPv6, SRV and kpasswd retry:

- Bare IPv6 literals keep their full address and the default port; an IPv6
  port needs brackets (RSK-03EDCC7E).
- The admin-server fallback for kpasswd keeps IPv6 hosts and uses port 464
  (RSK-3F13B5FE).
- UDP transport reaches IPv6-only endpoints (RSK-0D8D7D97).
- An oversized UDP datagram is `Client::UdpResponseTooLarge`, never a
  truncated success (RSK-484961E9).
- The transport no longer reads `RSKRB5_DNS_SERVER`; set a DNS server with
  `Tokio::with_dns_server` (ambient input `RSKRB5_DNS_SERVER`).
- DNS admin-server fallback for kpasswd uses port 464 (RSK-4AD555A5).
- An SRV record with target `.` returns `Client::DnsServiceUnavailable` and
  stops the fallback (RSK-DF8D47BE).
- DNS resolution keeps every address of each SRV target (RSK-521F824C).
- SRV weights select targets by probability within a priority (RFC 2782)
  (RSK-DBD57F3E).
- KDC TCP framing uses 31-bit lengths and rejects the reserved high bit
  (RFC 4120 §7.2.2); kpasswd framing is unchanged (RSK-351DC798).
- kpasswd never retries on another endpoint or protocol once the request may
  have been delivered; it returns `Client::KpasswdOutcomeUnknown`
  (RSK-4DB854C8, upstream issue #7, run-2 lead
  `send_to_endpoints/post-send-mutation-retry`).

Config and enctype policy:

- Repeated `[realms]` sections, path lists and includes merge per realm the
  way MIT does, so configured KDCs no longer fall back to DNS (RSK-40161D92,
  run-2 lead `apply_section/realms-replacement-dns-fallback`).
- Enctype names are the only stored policy; the wire ids are derived through
  methods, and an empty request list fails closed (RSK-77250646, upstream
  issue #4).
- Explicit enctype lists skip unimplemented names (including camellia) and
  policy-disabled entries, retaining usable names in order. A list with no
  usable entry fails with `Config::NoUsableEnctypes` (request lists) or
  `Config::NoPermittedEnctypes` (allowlist), never defaults or empty policy.
  As in 0.2.2, family names, `DEFAULT` and `-name` are not expanded; they are
  skipped and an all-selector list fails closed (RSK-45AC5D3A).
- The default enctypes are AES only. RC4 and DES3 need the
  `[libdefaults]` flags `allow_rc4` and `allow_des3` (both false by
  default); disabled explicit entries are skipped, with a named error if
  no usable entry remains. Export RC4 also needs `allow_weak_crypto`
  (RSK-5ECE9681, run-2 lead `DEFAULT_ENCTYPES/deprecated-rc4-default`,
  upstream issue #3).
- `LibDefaults::new()` reads no environment; `LibDefaults::from_env()` reads
  `HOME`. The default client keytab keeps the `%{euid}` template and
  `k5login_directory` defaults to empty (upstream issue #10, project rule
  (13)).

Ccache, keytab and credential files:

- Ccache upsert replaces a record with the same principal regardless of the
  name type (RSK-7F30E854).
- Serde rejects ccache versions outside 1-4 (RSK-01B7A90E).
- Keytab serialization rejects counts, strings, keys and enctypes the parser
  would reject (RSK-98FEE876).
- `%{uid}` and `%{euid}` come from `/proc/self/status` on Linux and never from
  the environment. **On macOS, Windows and other platforms these tokens now
  fail with `IdentityUnavailable`** (RSK-DC80DC52, run-2 lead
  `file-name/uid-token-environment-substitution`).
- Credential files are saved with mode 0600 on Unix, through a new file and
  a rename, and existing permissions are never widened. Unix saves also sync
  the parent directory after replacement; cleanup failures preserve the
  original write/rename/sync error (RSK-DF3180A2, run-2
  lead `credential-file/save/inherited-permissions`).
- Saves reject a symlinked destination file, and DIR primary initialization
  rejects a symlink; parent-directory symlinks still work (RSK-58A6D5DD, run-2
  lead `credential-file/path-write/followed-symlink`).
- File read buffers, save buffers and partial serializer output holding key
  material are zeroized (RSK-361F35CC).

Release workflow, CI docs and fixture scripts:

- The Release workflow has a secret-free `find-tag` job and a `publish` job
  that runs only for a `vN.N.N` tag, in the `release` environment (required
  reviewer), on a commit that is an ancestor of `main` (run-2 lead
  `release.publish.crates-io-token.unprotected-tag-authorization`).
  **Owner action:** move `CARGO_REGISTRY_TOKEN` from the repository secrets
  into the `release` environment
  (`gh secret set CARGO_REGISTRY_TOKEN --env release`, then
  `gh secret delete CARGO_REGISTRY_TOKEN`); until then the environment gate
  does not protect the token.
- `scripts/check-github-ad-gate.py --dispatch` refuses to dispatch inputs the
  CI workflow does not declare, and the parity manifest names the fork CI job
  for each gate (RSK-E0AFE152).
- The gated-integration runner writes its environment file with mode 0600 in
  a private directory and prints keytab values as `<redacted>`;
  `RSKRB5_INTEGRATION_ENV_FILE` is replaced by `RSKRB5_INTEGRATION_ENV_DIR`
  (RSK-A8D595D8).

### Lint compliance

- The crate passes the core Section 9 lint profile of the vendored Rust
  guidelines unchanged, with `clippy.toml`, `rustfmt.toml` and
  `.cargo/config.toml` (`build.warnings = "deny"`). There is no baseline, no
  `allow` attribute and no `unsafe` code; the only `expect` attributes are
  the six sanctioned forms in `docs/lint-policy.md`.
- Every feature closure (36, computed from `[features]`) passes
  `cargo clippy --all-targets -- -D warnings` and its tests, and clippy is
  clean on Windows.
- The core's non-lint rules apply to the whole tree: cancel-safety sections
  on async functions (`NOT cancel-safe` on credential-mutating ones), test
  docs, `Result`-returning tests, Drop audits and emptiness messages.
- The tests set environment variables in a child test process instead of
  through `unsafe` `set_var`; shared test helpers live under
  `tests/support/`.
- The universal Rust guidelines and the project overlay are vendored at
  `docs/rust-guidelines/` (pinned and checksummed), indexed by
  `RUST_GUIDELINES.md`.

### Fuzzing, tests and CI

- Twelve `cargo fuzz` targets cover every attacker-facing parser
  (`kpasswd_reply`, `ccache_parse`, `keytab_parse`, `pac_parse`,
  `spnego_token`, `gss_token`, `kdc_reply`, `krb5_conf`, `der_oid`,
  `krb_messages`, `name_parse`, `http_negotiate`), seeded from the test
  fixtures; `docs/review/fuzz.md` maps each parser to its target. Ccache and
  config property tests run with `proptest`, including a ccache
  serialization round-trip.
- CI runs on floating stable: rustfmt (`nightly-2026-10-03`), strict clippy
  and the tests in each of the 36 feature closures (`closures`, held equal to
  `feature_closures.py list`), clippy on Windows, library-only feature sets,
  the README commands, the test suite on Linux, macOS and Windows, i686,
  rustdoc on stable and nightly, MSRV 1.99.0, `cargo semver-checks` once a
  published `rskrb5-ng` baseline exists, a publish dry run, a path-dependency
  consumer build, `cargo deny`, `cargo audit`, `cargo vet`, `cargo machete`,
  `taplo`, an offline link check with the guideline checksums, the lint gates,
  a build of every fuzz target and `cargo package`. Advisory: `geiger`, a
  floating-nightly rustdoc canary, and on schedule or dispatch the
  whole-crate mutants run in eight shards and 300 s of fuzzing per target.
- The `Release` workflow publishes only a `vN.N.N` tag on a CI-green commit
  of `main`, after the owner approves the `release` environment
  (`docs/RELEASING.md`).
- The Docker MIT KDC and Active Directory integration gates run locally with
  `scripts/run-gated-integration.sh`; the upstream workflow-dispatch jobs
  aren't part of this CI, and `docs/gokrb5-parity.toml` records their upstream
  runs as historical evidence.

## [0.2.2] - 2026-10-07

Patched fork of `rskrb5`, still based on upstream `clelange/rskrb5` `main` at
`6f4abc9`, adding the changes below on top of the 0.2.1 set. The upstream
references are in `PROVENANCE.md` (formerly `FORK-NOTES.md`).

- AP-REQ replay identity is canonicalized over the advisory name-type: a
  name-type-only replay of a captured AP-REQ is rejected, and the replay key
  binds the service component to the key identity that accepted the ticket
  (clelange/rskrb5 PR #20).
- The authenticator client realm is bound to the KDC-authenticated ticket
  realm, and `ValidatedApReq.client` returns the ticket-derived identity, so
  no authenticator-supplied value reaches callers (clelange/rskrb5 PR #21).
- TCP transport: the record mark and the request body are written as one
  segment, `TCP_NODELAY` is set, and the preauth retry rides the pinned stream
  that answered the first AS phase (third-party PR #19's commits, authorship
  preserved), plus a pinning extension for the `Auto` fallback (Gittingc0dez
  stacked PR #1).
- Documentation: detailed fix plans for the remaining audit findings live in
  `docs/fix-plans/` (now `docs/history/fix-plans/`, excluded from packaging).

## [0.2.1] - 2026-10-06

Patched fork of `rskrb5`, based on upstream `clelange/rskrb5` `main` at
`6f4abc9` plus the changes below - published as `rskrb5-patched` so consumers
can depend on a registry version that carries them while they wait upstream.
The upstream references are in `PROVENANCE.md` (formerly `FORK-NOTES.md`).

- Clippy lints reported by Rust 1.98 (PR #15).
- `hex` as a dev-dependency so the crate's own integration tests build
  (issue #12, PR #16).
- `PA_FX_COOKIE`, `PA_AS_FRESHNESS` and `random_nonce` exported (issue #14,
  PR #17).
- `ChangePasswordResult` and `PasswordChangeFailed` carry the result bytes as
  received (`text_raw`), instead of `String::from_utf8_lossy`; the test
  fixtures are completed (issue #2, PR #18).
- `Config`/`LibDefaults` constructors that read no environment
  (`new_without_env`, `parse_without_env`) (issue #10).
- `include`/`includedir` support in `krb5.conf`, with depth/count/byte bounds
  and named errors; cycle detection for root files and directories; the scan
  cap enforced while scanning; non-UTF-8 `.conf` names read, MIT-style
  (issue #11).
- TGS-REQ builder returns the AP-REQ bytes and the authenticator subkey
  (RFC 6113 implicit FAST armor inputs) (issue #13).
- `TCP_NODELAY` on the KDC TCP connect (the record mark and body are two
  writes; Nagle holds the body) (equivalent third-party PR #19).
