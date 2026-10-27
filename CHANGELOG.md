# Changelog

## [Unreleased]

### Lint tooling

- Removed the transition baseline machinery: the empty `lint-migration:`
  baseline and its gates (`baseline_gate.py`, `generate_baseline.py`,
  `closure_report.py`, `clean-paths.txt`) are deleted with
  `scripts/lint-ratchet/`. The remaining gates live in `scripts/lint-gates/`,
  joined by `exception_gate.py`, which admits only the six sanctioned
  `expect` forms. `docs/lint-policy.md` replaces `docs/lint-baseline.md`.
- CI runs strict clippy and the tests in every feature closure (a static
  36-leg `closures` matrix held equal to `feature_closures.py list` by
  `feature_closures.py check-ci`), clippy on Windows and a build of every fuzz
  target; the K1-K7 `features-matrix` and the `release/**` trigger are gone.
  `prek.toml` mirrors the fast jobs plus a three-closure smoke.

## [0.3.0] - 2026-10-24

Patched fork of `rskrb5`, still based on upstream `clelange/rskrb5` `main` at
`6f4abc9`, adding the changes below on top of the 0.2.2 set. They close the
medium and low findings of the second audit run; the detailed plans live in
`docs/fix-plans/`. See `FORK-NOTES.md` for the upstream references and the
retirement trigger.

- Ccache parsing bounds every record count (principal components, addresses,
  authorization data) against the remaining input before reserving memory, so
  a short malformed cache returns `Error::Truncated` instead of aborting the
  process on a multi-GB allocation.
- kpasswd: a success result is accepted only with authenticated provenance. An
  unsigned KRB-ERROR reply carrying result code 0 is rejected with
  `kadmin::Error::UnauthenticatedSuccess`, and the high-level client keeps its
  stored password; non-zero error results keep their `PasswordChangeFailed`
  behaviour.
- `[libdefaults] permitted_enctypes` is an enctype allowlist when it's set
  explicitly: request lists are narrowed to it and the config-driven AS/TGS
  exchanges reject a session key outside it
  (`client::Error::EnctypeNotPermitted`). An explicit `default_tkt_enctypes`
  or `default_tgs_enctypes` naming an enctype outside an explicit allowlist is
  a parse error (`config::Error::EnctypeNotPermitted`) rather than a silent
  narrowing, checked once on the final values across included files. The
  seeded default list changes nothing, and the explicit flag
  (`LibDefaults.permitted_enctypes_explicit`) survives a serde round-trip.
- An explicit allowlist fails closed when it resolves to no supported enctype:
  a parsed `permitted_enctypes` naming only unsupported names (or only weak
  ones without `allow_weak_crypto`) is a parse error
  (`config::Error::NoPermittedEnctypes`) instead of meaning "no policy", and a
  hand-built `LibDefaults` with the explicit flag and an empty
  `permitted_enctype_ids` requests no enctype (`client::Error::EmptyEtypes`)
  and rejects every session key (`client::Error::EnctypeNotPermitted`).
- MIT's DES3 names `des3-cbc-sha1` and `des3-hmac-sha1` resolve to enctype 16
  like `des3-cbc-sha1-kd`, so an explicit list using them is honoured (or
  rejected against an explicit allowlist) instead of silently dropping DES3.
  The seeded default list no longer names `des3-cbc-sha1` (gokrb5's
  unimplemented etype 7), so the defaults still request 18, 17 and 23 only.
- AS and TGS replies are bound to the requested enctype list: the AS-REP reply
  key enctype and the AS/TGS session-key enctype must appear in the request's
  `etype` list, otherwise `client::Error::EnctypeNotRequested`.
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
  (`ServiceValidator::from_default_keytab_name`/`from_default_keytab`,
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
- Lockfile refreshed to the latest Rust 1.99-compatible dependency versions
  (`crossbeam-epoch` 0.9.18 to 0.9.21 and `crypto-bigint` 0.7.6 to 0.7.8
  among them).

### Behaviour changes from the review

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
- The SPNEGO acceptor accepts only a first-choice Kerberos mechanism and keeps
  its OID in the reply. A non-first Kerberos offer, a continuation or any
  mechListMIC fails closed (`NegotiationRequiresState`,
  `MechListMicRequiresState`), before AP-REQ validation and the replay cache
  (RFC 4178 §§4-5) (RSK-C4BE57A0).
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
  clock rollback, and fail closed when full (RSK-7D80FA41, run-2 lead
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
- An explicit enctype list naming an unsupported enctype is a parse error,
  `Config::UnsupportedEnctype` (RSK-45AC5D3A).
- The default enctypes are AES only. RC4 and DES3 need the
  `[libdefaults]` flags `allow_rc4` and `allow_des3` (both false by
  default); a disabled explicit entry is `Config::EnctypeDisabled`
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
  a rename, and existing permissions are never widened (RSK-DF3180A2, run-2
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

### Breaking

- New enum variants on exhaustive enums: `client::Error::EnctypeNotRequested`,
  `client::Error::EnctypeNotPermitted`, `config::Error::EnctypeNotPermitted`,
  `config::Error::NoPermittedEnctypes`,
  `kadmin::Error::UnauthenticatedSuccess` and
  `http::NegotiateHttpError::MutualAuthenticationNotProven`.
- `http::NegotiateHttpError<E>` becomes `NegotiateHttpError<E, B>`, where `B`
  is the response body type carried by the new variant.
- New public fields on constructible structs:
  `LibDefaults.permitted_enctypes_explicit` and
  `InitiatorContext.context_flags`.
- Lint pass on fork-only API: `client::TgsFastRequestParts` is
  `#[non_exhaustive]`, and `build_tgs_req_for_realm_with_subkey` and
  `build_tgs_req_for_realm_with_confounder_and_subkey` take a generic
  `R: Into<String>` realm instead of `impl Into<String>` (ordinary calls
  compile unchanged).
- Behaviour: an unsigned kpasswd success is rejected; a KDC reply or session
  key outside the requested (or explicitly permitted) enctypes is rejected,
  and so is a config whose explicit request list falls outside an explicit
  `permitted_enctypes`, or whose explicit `permitted_enctypes` names no
  supported enctype; `des3-cbc-sha1` and `des3-hmac-sha1` now mean enctype
  16; host-based SPNs carry a lower-cased host; and the send
  wrappers return an error when requested mutual authentication isn't proven.

### Lint profile, rules and tooling

- The crate adopts the core Section 9 lint profile of the vendored Rust
  guidelines (equal to rmcp-server-kit `b7f6b66`), with `clippy.toml`,
  `.cargo/config.toml` (`build.warnings = "deny"`) and no `allow` attributes.
  Upstream code keeps its existing violations as generated, item-level
  `lint-migration:` expectations listed in a generated baseline manifest
  (7,396 at adoption, 6,514 now), which can only shrink. Fork code passes the
  profile outright. Gates: fork-lines (differential diagnostics), prose (the
  core's non-lint rules), baseline ratchet, profile equality, profile
  completeness and allow. See `docs/lint-policy.md` (the baseline is gone).
- CI floats on `stable`; rustfmt and the second rustdoc run use
  `nightly-2026-10-03` with rmcp-server-kit's `rustfmt.toml`.
- **Breaking:** `rust-version` is raised from 1.88 to 1.99. The lockfile holds
  the latest Rust 1.99-compatible versions, and `proptest` is a new
  dev-dependency.
- The universal Rust guidelines are vendored at `docs/rust-guidelines/`
  (pinned and checksummed) with the `RUST_GUIDELINES.md` index, which names
  the pin.
- **Breaking** for configs that relied on silent narrowing: an explicit
  `default_tkt_enctypes` or `default_tgs_enctypes` naming an enctype outside an
  explicit `permitted_enctypes` is a parse error
  (`config::Error::EnctypeNotPermitted`).
- The fuzz crate depends on the renamed package key, and a `ccache_parse`
  fuzz target joins `kpasswd_reply`; ccache and config property tests run with
  `proptest`. The release workflow publishes with `--locked`.
- CI jobs added: an OS matrix (Linux, macOS, Windows), i686 (check and the
  ccache tests), MSRV (1.99.0), a K1 to K7 feature matrix, lib-only checks of
  the `messages`, `spnego`, `http` and `evaluation` feature sets and the
  compatibility-report binary, the README commands, `cargo deny`, `cargo audit`, `cargo vet`,
  `cargo machete`, `cargo semver-checks`, `taplo`, publish dry-run, a
  path-dependency consumer build, docs-validate (guideline checksums and an
  offline link check), lint-gates, fork-lines and package. Geiger, a floating
  nightly rustdoc canary, mutants and fuzz stay advisory. The prek hooks mirror
  the fast gates.
- The tests set environment variables in a child test process instead of
  through `unsafe` `set_var`, and the shared test helpers are split by use
  under `tests/support/`.

## [0.2.2] - 2026-10-07

Patched fork of `rskrb5`, still based on upstream `clelange/rskrb5` `main` at
`6f4abc9`, adding the changes below on top of the 0.2.1 set. See
`FORK-NOTES.md` for the upstream references and the retirement trigger.

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
  `docs/fix-plans/` (excluded from packaging).

## [0.2.1] - 2026-10-06

Patched fork of `rskrb5`, based on upstream `clelange/rskrb5` `main` at
`6f4abc9` plus the changes below - published as `rskrb5-patched` so consumers
can depend on a registry version that carries them while they wait upstream.
See `FORK-NOTES.md` for the change list, the upstream references and the
retirement trigger.

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
