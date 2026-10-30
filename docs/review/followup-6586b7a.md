# Follow-up review register for `6586b7a`

## Purpose

This register closes the independent review of `rskrb5-ng` at `6586b7a`. Every
finding, nit included, ends with a final status backed by a proof.

## Method

Review sources: the Oracle cross-cutting review, six unit critics, the revmux
runs on the strongest units (u2-u6) and unit u1 run 02, the worker's own
leftover notes, and the mutation-testing artifacts. A planner consolidated them
into a ledger of canonical rows (`FU-<AREA>-<NN>`). The ledger is not committed;
this register is self-contained. Revmux finder availability and degraded-round
limits are recorded under FU-OPS-03.

## Status vocabulary

- `open`: not yet acted on (initial state of every row).
- `fixed`: fixed with a named proof (a failing-first test or a check) and commit.
- `dismissed`: shown not to be a defect; evidence recorded.
- `transferred`: a parity feature moved to a named plan-2 todo.

## Register

| ID | Sev | Title | Status | Proof | Behaviour change | Evidence or plan-2 todo |
| --- | --- | --- | --- | --- | --- | --- |
| FU-SPN-01 | major | MIC/Wrap plaintext owners and Debug expose payloads | open | - | - | - |
| FU-SPN-02 | major | Initiator/context Debug prints live Authorization tokens | open | - | - | - |
| FU-SPN-03 | minor | SPNEGO SEQUENCE permits duplicate/reordered known fields | open | - | - | - |
| FU-SPN-04 | minor | Unknown SPNEGO extensions are rejected | open | - | - | - |
| FU-SPN-05 | minor | DER reader accepts nonminimal length forms | open | - | - | - |
| FU-HTTP-01 | minor | Example invokes handler after AP-REP construction failure | open | - | - | - |
| FU-HTTP-02 | major | Credential HeaderValues lack sensitivity flags | open | - | - | - |
| FU-HTTP-03 | major | Combined context masks bypass mutual-required enforcement | open | - | - | - |
| FU-HTTP-04 | minor | Library responses lack required hardening policy | open | - | - | - |
| FU-HTTP-05 | major | Client accepts unfinished/unbound SPNEGO metadata | open | - | - | - |
| FU-HTTP-06 | minor | Erased Tower future loses Send unconditionally | open | - | - | - |
| FU-SVC-01 | minor | Alleged missing default-cache capacity validation is a checked-correct item | open | - | - | - |
| FU-SVC-02 | major | Claim that a 900-second cache rejects a 300-second validator | open | - | - | - |
| FU-SVC-03 | major | Administrative pruning can reopen live authenticators | open | - | - | - |
| FU-SVC-04 | major | Admission scans live digest table under shared mutex | open | - | - | - |
| FU-SVC-05 | info | Bulk expiry performs one paired key removal per expired digest | open | - | - | - |
| FU-SVC-06 | info | Hypothetical orphan key does not self-heal during digest purge | open | - | - | - |
| FU-SVC-07 | info | Paired replay retention increases capacity pressure | open | - | - | - |
| FU-SVC-08 | nit | Built-in TransitPolicy represents one endpoint pair | open | - | - | - |
| FU-SVC-09 | major | Larger configured skew conflicts with internally owned default cache | open | - | - | - |
| FU-SVC-10 | major | Equal-realm tickets bypass nonempty transit-path policy | open | - | - | - |
| FU-SVC-11 | major | Mandatory-wrapper PAC is recognized but not discovered/verified | open | - | - | - |
| FU-SVC-12 | nit | Replay tests use out-of-line module instead of inline convention | open | - | - | - |
| FU-CLI-01 | minor | Auto-renewal cancellation handle is not must_use | open | - | - | - |
| FU-CLI-02 | major | Cached credentials bypass configured enctype policy | open | - | - | - |
| FU-CLI-03 | minor | Failed in-memory ccache export mutates destination | open | - | - | - |
| FU-CLI-04 | minor | INVALID/future primary TGT delays auto-refresh until expiry band | open | - | - | - |
| FU-CLI-05 | minor | Diagnostics compare preauth padata numbers with keytab enctypes | open | - | - | - |
| FU-CLI-06 | major | Public cache insertion admits another client identity | open | - | - | - |
| FU-CLI-07 | major | Moved password argument's original allocation is not erased | open | - | - | - |
| FU-CLI-08 | minor | Own-password rotation treats advisory name type as identity | open | - | - | - |
| FU-CLI-09 | minor | TGT diagnostic JSON labels issuer as destination | open | - | - | - |
| FU-CLI-10 | major | Cross-realm TGT renewal changes server and routes to destination | open | - | - | - |
| FU-CLI-11 | major | Optimistic preauth cannot recover from error 24 | open | - | - | - |
| FU-CLI-12 | minor | AS/TGS reply validation omits requested time/flag constraints | open | - | - | - |
| FU-CLI-13 | minor | PREAUTH_FAILED METHOD-DATA is discarded | open | - | - | - |
| FU-CLI-14 | minor | INVALID flag and PA-PW-SALT remain duplicated bare constants | open | - | - | - |
| FU-CLI-15 | major | Keytab challenge selects offered enctype without available key | open | - | - | - |
| FU-CLI-16 | minor | Renewal predicate ignores renewable flag and valid time window | open | - | - | - |
| FU-CLI-17 | minor | Blocking runtime operations and destruction may panic in async context | open | - | - | - |
| FU-TRN-01 | minor | Local request-time errors are labeled authenticated reply-control errors | fixed | `client::kpasswd::request::tests::{fractional_request_time_is_local,excessive_request_microseconds_are_local,maximum_request_microseconds_build}`; commit `kpasswd: classify invalid request times before delivery (FU-TRN-01)` | Fractional request timestamps and cusec >= 1000000 return Client::Encode with target kpasswd request time, not KpasswdReplyControl; no frame is built or sent | Red: 2 failed / 1 passed; green: 3 passed; task-4 evidence; pure split `36539fa` preceded red |
| FU-TRN-02 | major | Reflected request KRB-PRIV can become password-bearing failure text | fixed | `genuine_ap_rep_cannot_authorize_reflected_ciphertext`, `dummy_ap_rep_cannot_hide_reflected_ciphertext` in 389a7e0; `checked_helpers_reject_invalid_contexts`; commit `transport: validate checked kpasswd reply contexts (FU-TRN-10)` | Shared validator rejects ciphertext equality independently of outer kvno before parsing password bytes; both checked helpers invoke it and report unknown | Red shared-validator tests both failed; green both passed. Both transport helpers reject reflection with one unknown wrapper and no second connection; task-4 evidence |
| FU-TRN-03 | major | Unsigned rejection is treated as definitive password-change failure | open | Partial: `bare_unsigned_rejection_is_not_definitive`, `framed_unsigned_rejection_is_not_definitive`; commit `kpasswd: classify unsigned refusals as unauthenticated (FU-TRN-03)` | Adds Kadmin::UnauthenticatedRejection carrying code and raw bytes; shared validator no longer returns unsigned refusal as a checked result; raw Reply::decrypt_result remains diagnostic | Red: both failed; green: both passed with exact variant and non-UTF-8 bytes preserved. Transport helper wiring and delivery/rotation proof pending; todo 10 owns client.rs contribution; task-4 evidence |
| FU-TRN-04 | minor | Windows oversized UDP reports Io instead of promised size error | open | - | - | - |
| FU-TRN-05 | minor | Final configured-kpasswd mapping branch is unreachable | open | Implementation complete: `configured_password_errors_are_precise` and existing configured-server tests; commit `transport: make absent password configuration explicit (FU-TRN-05)` | none; dead successful mapping replaced with explicit NoRealm/NoKpasswdServer errors | Pure split9692e5f; exact-error test passed before and after (unreachable branch has no behavioral red). Structural before check found configured_kpasswd_servers mapping; after absent. Strict per-row red requirement remains unresolved; task-4 evidence |
| FU-TRN-06 | minor | Config Auto path discards pinned TCP conversation | open | - | - | - |
| FU-TRN-07 | minor | Password endpoint errors omit endpoint authority | fixed | `password_failures_name_each_endpoint`; commit `transport: attribute password endpoint failures (FU-TRN-07)` | Aggregated pre-delivery failures include endpoint.authority(); uncertain outcomes still return immediately | Pure split54b1f19; red missing endpoint attribution, green1 passed; existing lost-reply no-retry test passed before change; scoped clippy and LSP clean; task-4 evidence |
| FU-TRN-08 | minor | Obsolete Clone bounds constrain password address APIs | fixed | `password_address_bound_is_resolver_only`; commit `transport: remove obsolete password address Clone bounds (FU-TRN-08)` | Password request/result address APIs and private single-send delegation require only ToSocketAddrs, not Clone | Red E0277 A:Clone, green1 passed; scoped clippy passed. Tokio resolver trait is sealed, so downstream generic-bound proof replaces impossible custom trait implementation; task-4 evidence |
| FU-TRN-09 | minor | Password UDP duplicates bounded transport primitives | open | - | - | - |
| FU-TRN-10 | major | Public checked-result helpers omit AP-REP/context verification | fixed | `checked_helpers_reject_invalid_contexts`, `checked_reply_fixtures_are_valid`; commit `transport: validate checked kpasswd reply contexts (FU-TRN-10)` | Both checked helpers now take BuiltKpasswdRequest and RequestOptions instead of raw Request and reply key; authenticate AP-REP, select server subkey and validate freshness, sequence, addresses and reflection. Raw helpers document Security boundary | Red wire regression accepted invalid AP-REP; green both-helper matrix covers bad AP-REP, wrong AP-REP time, missing freshness, wrong sequence/address, stale time, wrong key and reflection; authenticated rejection and server-subkey success pass; task-4 evidence |
| FU-TRN-11 | major | Delivered decrypt/validation failure loses unknown-outcome wrapper | open | Partial: `tests::password_results::tokio_transport_rejects_unauthenticated_kpasswd_success_result`; commit `transport: preserve uncertainty on delivered result errors (FU-TRN-11)` | Both checked helpers share a consumer wrapping decrypt/parse errors in one KpasswdOutcomeUnknown | Same-input assertion deliberately changed from bare Kadmin::UnauthenticatedSuccess to exactly one unknown wrapper; red1 failed/1 passed, green2 passed. Both-helper wrong-key and request-count matrix still pending with FU-TRN-10; task-4 evidence |
| FU-TRN-12 | minor | UDP kpasswd admin fallback queries nonexistent protocol variant | fixed | `udp_password_discovers_admin_tcp_service`; commit `transport: discover password fallback through admin TCP (FU-TRN-12)` | Always query _kerberos-adm._tcp, then select password port464 and requested protocol | Pure split909248a; red DNS query used nonexistent admin UDP, green1 passed with admin-TCP-only fixture; scoped clippy passed; task-4 evidence |
| FU-TRN-13 | minor | One unresolvable explicit-DNS SRV target aborts all failover | open | - | - | - |
| FU-TRN-14 | info | Password-specific ASN.1 owner retains dependency plaintext | fixed | `password_storage_is_zeroizing`, `password_der_matches_rasn`, `private_der_matches_rasn`; 38 kadmin regressions; commit `kadmin: own password storage and DER staging (FU-TRN-14)` | ChangePasswdData::new_passwd is kadmin::password::Bytes, a redacted zeroizing owner; request builders encode payload and application-28 envelope directly into zeroizing buffers; encode_der returns caller-owned Vec with documented erasure duty | Red: OctetString failed Zeroize/ZeroizeOnDrop bounds; green: ownership and DER equivalence tests pass, including length boundaries, target metadata, time/usec, sequence and addresses. Generic rasn output/cipher-internal copies remain outside guarantee; constructor ownership change belongs to todo 10 |
| FU-CRY-01 | major | Unauthenticated peer s2k count can weaken password derivation to one round | open | - | - | - |
| FU-CRY-02 | minor | Hand-written MAC equality lacks audited constant-time primitive | open | - | - | - |
| FU-CRY-03 | minor | Aggregate erasure counters do not pin each sensitive crypto owner | open | - | - | - |
| FU-CRY-04 | info | Cipher-setup backlog dismissal remains justified | open | - | - | - |
| FU-MSG-01 | major | Secret-bearing message DER staging is not zeroized | open | - | - | - |
| FU-MSG-02 | major | Strict AP-REP/KRB-CRED decode rejects valid DES3 padding | open | - | - | - |
| FU-MSG-03 | minor | KRB-CRED semantic import truncates fractional times | open | - | - | - |
| FU-MSG-04 | minor | General KRB-PRIV builder emits invalid time scalars | open | - | - | - |
| FU-MSG-05 | minor | Typed message decoders retain accidental prefix acceptance | open | - | - | - |
| FU-PAC-01 | major | Unsigned HMAC-MD5 checksum ID cannot map to RC4 | open | - | - | - |
| FU-PAC-02 | minor | Supplemental-credential count ceiling lacks independent regression | open | - | - | - |
| FU-CFG-01 | minor | Top-level configuration I/O error loses failing path | open | - | - | - |
| FU-CFG-02 | minor | Environment-free seed/twin machinery is redundant | open | - | - | - |
| FU-CFG-03 | major | Last-wins scalar composition diverges from claimed MIT order | open | - | - | - |
| FU-CFG-04 | major | Explicit disabled/unknown enctypes disappear before policy validation | open | - | - | - |
| FU-CFG-05 | major | Negative enctype directives are silently ignored | open | - | - | - |
| FU-CFG-06 | minor | Standard final section/subsection markers are ignored | open | - | - | - |
| FU-CFG-07 | minor | Plain zero duration rejects a supported zero value | open | - | - | - |
| FU-CFG-08 | minor | Public supported-ID helper is mistaken for current enctype policy | open | - | - | - |
| FU-CFG-09 | minor | Unbalanced ignored-section braces suppress include expansion | open | - | - | - |
| FU-FIL-01 | minor | Legacy ccache versions silently lose admitted fields | open | - | - | - |
| FU-FIL-02 | minor | Global file erasure counters mask missing individual owners | open | - | - | - |
| FU-FIL-03 | minor | DIR primary is published before initialization completes | open | - | - | - |
| FU-FIL-04 | minor | Partial next-entry keytab size is accepted as EOF | open | - | - | - |
| FU-FIL-05 | minor | Keytab parser/writer disagree on negative enctype domain | open | - | - | - |
| FU-FIL-06 | minor | Zero extended KVNO changes identity after reload | open | - | - | - |
| FU-API-01 | minor | Public non-exhaustive inputs lack usable construction paths | open | - | - | - |
| FU-API-02 | minor | Secret Debug implementations lack exhaustive field audit | open | - | - | - |
| FU-API-03 | minor | Crate-wide Result cannot propagate Messages/Http domains | open | - | - | - |
| FU-API-04 | minor | Retained causal errors disappear from source chains | open | - | - | - |
| FU-API-05 | minor | Dead public error variants advertise impossible library failures | open | - | - | - |
| FU-API-06 | minor | Shared KerberosTime conversions and AP-REQ metadata diverge | open | - | - | - |
| FU-AMB-01 | minor | Forwarding ambient entry points are absent from structural docs inventory | open | - | - | - |
| FU-AMB-02 | major | Ambient guard misses reader APIs and leaks cfg exemptions/owner identity | open | - | - | - |
| FU-TST-01 | minor | Example security-header tests are never selected by gates | open | - | - | - |
| FU-TST-02 | minor | Cookie regressions do not exclude unrelated METHOD-DATA | open | - | - | - |
| FU-TST-03 | minor | INVALID “never renewed” half is not regression-pinned | open | - | - | - |
| FU-TST-04 | minor | Abort regression never observes cancellation or Drop cleanup | open | - | - | - |
| FU-TST-05 | minor | Explicit MIT integration requests can pass with no live assertions | open | Partial: `preflight::tests::{required_closed_fixture_fails,optional_closed_fixture_skips,required_missing_executable_fails}`; commit `test: fail required integration preflight instead of skipping (FU-TST-05)` | INTEGRATION_REQUIRED=1 turns unavailable requested endpoints, HTTP fixtures and missing requested kinit/kvno into errors; default opt-in skips remain | Pure split 3ac67d4 before red; required closed fixture failed before fix, optional control passed; green 3 passed. Per-test fixture scoping and runner integration remain unverified; task-4 evidence |
| FU-TST-06 | minor | AD password-reply interoperability is an open question | transferred | Plan-1 todo-4 contested-row ruling; commit `docs: transfer AD kpasswd interoperability to plan 2 (FU-TST-06)` | none; existing reply controls remain enforced | parity: Samba AD kpasswd reply interop; plan-2 todo 1 |
| FU-TST-07 | minor | Live harness IPv6 authority helpers disagree with production parser | fixed | `endpoints::tests::service_authorities_preserve_ipv6`; commit `test: preserve IPv6 literals in live service authorities (FU-TST-07)` | Live harness parses complete IPv6 before colon-port detection; all six services bracket bare IPv6 and use selected service port | Pure split 08c5fca before red; red ::1 != [::1]:1088, green child matrix covers ::1, 2001:db8::1:2, [::1]:2088, IPv4 and hostname with six distinct ports; task-4 evidence |
| FU-TST-08 | minor | Transport ambient-read regression is a bypassable substring check | open | - | - | - |
| FU-TST-09 | minor | Auto TCP-first test does not observe an unwanted UDP probe | open | - | - | - |
| FU-TST-10 | minor | Environment-selected live TCP probe is unbounded | open | - | - | - |
| FU-GATE-01 | major | Whole-tree scans omit build scripts/custom Cargo target paths | open | - | - | - |
| FU-GATE-02 | minor | Removed baseline machinery leaves ineffective flags/dead helper work | open | - | - | - |
| FU-GATE-03 | major | Spaced/raw lint paths bypass exception allowlist | open | - | - | - |
| FU-GATE-04 | minor | Closure matrix guard ignores lint-capping environment/config/shell | open | - | - | - |
| FU-GATE-05 | minor | Fuzz coverage passes empty inventory and CI omits inventory enforcement | open | - | - | - |
| FU-GATE-06 | minor | Inventory validator never checks rows still name defined symbols | open | - | - | - |
| FU-GATE-07 | major | Prose checks miss macro-generated items and non-src production | open | - | - | - |
| FU-GATE-08 | minor | Nearby unrelated/empty cancellation prose satisfies another function | open | - | - | - |
| FU-GATE-09 | nit | SemVer helper orders prerelease numbers lexically | open | - | - | - |
| FU-GATE-10 | minor | Semver baseline tag need not match manifest version | open | - | - | - |
| FU-GATE-11 | major | Published equal-version baseline is skipped as first release | open | - | - | - |
| FU-GATE-12 | major | Fixture env writer turns operator values into shell code | open | - | - | - |
| FU-GATE-13 | major | Multiline keytab values bypass line-based secret redaction | open | - | - | - |
| FU-CI-01 | minor | docs.rs default build omits advertised HTTP/Tower APIs | open | - | - | - |
| FU-CI-02 | minor | AD helper regression suites are not automated | open | - | - | - |
| FU-CI-03 | minor | Advisory geiger fails scanning rather than reporting complete unsafe inventory | open | - | - | - |
| FU-CI-04 | minor | Mutation timeout has no kill deadline/completeness aggregation | open | - | - | - |
| FU-CI-05 | minor | Release toolchain action pin is not exercised by CI | open | - | - | - |
| FU-CI-06 | minor | Verify-build and later registry token share one runner | open | - | - | - |
| FU-CI-07 | major | Upload-success/release-failure cannot recover by rerun | open | - | - | - |
| FU-FUZ-01 | major | Mutation campaign is incomplete and missed mutants are untriaged | open | - | - | - |
| FU-FUZ-02 | info | TCP outer record-mark parser lacks fuzz target by current organization | fixed | `reserved_record_bit_is_rejected`, `empty_record_is_rejected`, `record_cap_is_inclusive`; kdc_tcp_frame 120-second run; commit `fuzz: exercise production KDC TCP record validation (FU-FUZ-02)` | Adds public client::transport::kdc_tcp_record_length([u8;4], usize); production shares its existing reserved-bit and cap semantics, rejecting zero before body allocation | Red unresolved public API; green 3 tests. Done 24229707 runs in 121 seconds, 0 artifacts; seed-only coverage matched exact public symbol/source with count20 using fuzz_coverage.py; separate fuzz-t4 directory deleted after run and coverage export |
| FU-DOC-01 | minor | Config comments reference nonexistent contributor/editor files | open | - | - | - |
| FU-DOC-02 | minor | Packaged Markdown links target excluded files | open | - | - | - |
| FU-DOC-03 | minor | Changelog0.2.2 tag date conflicts with publication date | open | - | - | - |
| FU-DOC-04 | nit | Branch ledger claims observations missing from its own table | open | - | - | - |
| FU-DOC-05 | info | RC4 permission versus request-ID behavior is unclear in worker note | open | - | - | - |
| FU-DOC-06 | info | Brief versus NoPermittedEnctypes wording cannot be independently established | open | - | - | - |
| FU-DOC-07 | info | Migration guide omits TransitValidator method name | open | - | - | - |
| FU-DOC-08 | minor | Migration inventory advertises removed reexports/malformed generic paths | open | - | - | - |
| FU-DOC-09 | minor | Fuzz inventory still maps removed config parser | open | - | - | - |
| FU-DOC-10 | info | Wrapper cancellation-contract dismissal is supported | open | - | - | - |
| FU-DOC-11 | info | HTTP replay-scope dismissal is supported within documented limits | open | - | - | - |
| FU-DOC-12 | info | Service review incorrectly says fractional-time rejection has no negative tests | open | - | - | - |
| FU-DOC-13 | minor | Vendored project facts name deleted semver path/incomplete blocking jobs | open | - | - | - |
| FU-DOC-14 | minor | File/config module docs describe pre-rename porting milestones | open | - | - | - |
| FU-DOC-15 | minor | File-name docs omit procfs I/O and IdentityUnavailable | open | - | - | - |
| FU-DOC-16 | minor | Cache insert-or-replace docs hide keep-better behavior | open | - | - | - |
| FU-DOC-17 | minor | DNS override docs omit bracket requirement for IPv6 ports | open | - | - | - |
| FU-DOC-18 | minor | Transport Errors docs omit newly named framing/discovery errors | open | - | - | - |
| FU-DOC-19 | minor | Single-timeout comment omits deliberate password two-phase exception | open | - | - | - |
| FU-DOC-20 | minor | Password transport comments contradict no-retry/discovery boundaries | open | - | - | - |
| FU-DOC-21 | minor | Enctype policy docs describe old defaults/construction/validation phase | open | - | - | - |
| FU-DOC-22 | minor | Ccache I/O display calls write failures read failures | open | - | - | - |
| FU-DOC-23 | nit | Bare kpasswd reply profile is omitted from parse contract | fixed | Reply::parse attached rustdoc contract check; `tests::kpasswd_bare_error_roundtrips`; commit `docs: explain standalone kpasswd reply parsing (FU-DOC-23)` | none; documents existing standalone application-30 dispatch and synthetic 0xff80 version | Before: contract terms absent; after: all present at Reply::parse; round-trip passed; rustdoc -D warnings passed; task-4 evidence |
| FU-DOC-24 | minor | KRB-ERROR scalar validation docs describe obsolete u32-only checks | open | - | - | - |
| FU-DOC-25 | nit | Stale helper prose and repeated test cfg attributes | open | - | - | - |
| FU-DOC-26 | nit | NDR rejection test comment describes unrelated PAC discovery | open | - | - | - |
| FU-OPS-01 | minor | Release token owner migration is outstanding despite fixed status | fixed | Verified 2026-10-29 via `gh api`: the repository secret list lacks `CARGO_REGISTRY_TOKEN`; the `release` environment has it (updated 2026-10-29T09:33:33Z); `can_admins_bypass=false`; the environment deployment policy is only `[0-9]*.[0-9]*.[0-9]*` (type tag); ruleset 25943056 includes `refs/tags/[0-9]*.[0-9]*.[0-9]*` | none | - |
| FU-OPS-02 | nit | Main checkout/boulder/review worktree need later housekeeping | open | - | - | - |
| FU-OPS-03 | info | Review-finder tool availability/degraded round limits independence | open | - | - | - |
| FU-HTTP-R01 | minor | Example `load_keytab` re-implements keytab-name parsing: `WRFILE:` fails and keytab bytes are not zeroized (`examples/axum-negotiate.rs`) | open | - | - | - |
| FU-HTTP-R02 | major | Tower `NegotiateService` maps every Spnego error, including replay-cache and keytab faults, to a 401 reject and discards the cause (internal faults must be 5xx-class, logged without secrets; auth failures stay 401) (`src/http.rs`) | open | - | - | - |
| FU-HTTP-R03 | major | `NegotiateService` is not `Clone`, preventing use as an axum/tower service in multithreaded routers (`src/http.rs`; the `Send` half is FU-HTTP-06) | open | - | - | - |
| FU-SPN-R01 | minor | Dead binding and unreachable return in the `Token::Resp` branch of `accept_sec_context_header` (`src/spnego.rs`) | open | - | - | - |
| FU-SPN-R02 | minor | `WrapToken::encrypt_payload_with_confounder` sets SEALED before fallible steps, leaving a partially updated token on error (`src/spnego.rs`) | open | - | - | - |
| FU-SPN-R03 | minor | `client_error_to_spnego` erases the crate's own `Client` error to a string (keep the typed source) (`src/spnego.rs`) | open | - | - | - |
| FU-SPN-R04 | minor | `MicToken::verify`/`WrapToken::verify` return `Result<bool, _>` that can never be `Ok(false)` (make them `Result<(), _>`) (`src/spnego.rs`) | open | - | - | - |
| FU-SVC-R01 | major | Replay-cache capacity is one global pool that any ticket holder can fill with distinct authenticators, locking every other client out (bound per-client-principal share; never evict live evidence; document) (`src/service.rs`) | open | - | - | - |
| FU-SVC-R02 | minor | `ValidatedApReq.service` reports the cleartext ticket sname, not the key identity that decrypted the ticket (`src/service.rs`) | open | - | - | - |
| FU-SVC-R03 | minor | Ticket PAC accepted without binding PAC_CLIENT_INFO name and authtime to the ticket client (`src/service.rs`) | open | - | - | - |
| FU-SVC-R04 | minor | The acceptor applies no enctype policy (`permitted_enctypes`, `allow_rc4`, `allow_des3` ignored by Config-driven constructors) (`src/service.rs`) | open | - | - | - |
| FU-DOC-R01 | minor | Stale `# Errors` documentation on `encryption_key_from_rasn` describes a Result the function no longer returns (`src/service.rs`) | open | - | - | - |
| FU-TST-R01 | minor | Ticket client-address matching has no test: `with_client_address` and `BadClientAddress` are never exercised (`tests/service.rs`) | open | - | - | - |

## Source notes

Findings of revmux unit-1 run 02 that duplicate an existing row (no new row):

- RVX-u1-01 → FU-TST-01 (also: the test never exercises the router wiring cited by the review doc; covered by FU-TST-01's Proof)
- RVX-u1-03 → FU-HTTP-03
- RVX-u1-04 → FU-SVC-09
- RVX-u1-06 → FU-API-01
- RVX-u1-07 → FU-SVC-04
- RVX-u1-08 → FU-AMB-01

## Added rows

Rows added after the ledger from revmux unit-1 run 02, with the owning todo of plan `rskrb5-ng-zero-open-items`:

- FU-HTTP-R01 ← RVX-u1-02 → todo 3
- FU-HTTP-R02 ← RVX-u1-12 → todo 3
- FU-HTTP-R03 ← RVX-u1-13 → todo 3
- FU-SPN-R01 ← RVX-u1-10 → todo 3
- FU-SPN-R02 ← RVX-u1-17 → todo 3
- FU-SPN-R03 ← RVX-u1-18 → todo 3
- FU-SPN-R04 ← RVX-u1-19 → todo 3
- FU-SVC-R01 ← RVX-u1-05 → todo 9
- FU-SVC-R02 ← RVX-u1-14 → todo 9
- FU-SVC-R03 ← RVX-u1-15 → todo 9
- FU-SVC-R04 ← RVX-u1-16 → todo 14
- FU-DOC-R01 ← RVX-u1-09 → todo 9
- FU-TST-R01 ← RVX-u1-11 → todo 9
