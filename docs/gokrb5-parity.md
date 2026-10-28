# gokrb5 Parity Plan

This document tracks feature parity against `github.com/jcmturner/gokrb5/v8`
`v8.4.4`. The machine-readable source is
[`gokrb5-parity.toml`](gokrb5-parity.toml); update both files when a parity
area moves.

The parity target is the pure Go `gokrb5` client/service feature set: keytab,
ccache, krb5.conf, Kerberos crypto/messages, AS/TGS client flows, service-side
AP-REQ verification, GSSAPI/SPNEGO HTTP, PAC parsing, kpasswd, Docker MIT KDC
integration, and AD-gated behavior. Platform credential stores, PKINIT, full
FAST armor, and system GSSAPI/SSPI facades are useful future work but are not
required for `gokrb5/v8` parity.

## Status

| Area | Status | Next closure step |
|---|---|---|
| krb5.conf configuration | covered | Keep translated config tests current. |
| Keytab parsing, writing, and lookup | covered | Keep keytab fixture tests current. |
| Credential cache parsing, writing, and collection names | covered-with-gated-evidence | The privileged `kinit`/`kvno` gate has upstream evidence only; run it locally before a release; CI has no Docker job. |
| Kerberos cryptography | covered | Keep RFC/gokrb5 vectors current. |
| ASN.1 and Kerberos message wrappers | covered | Keep fixture matrix current. |
| RFC 3244 password change | covered-with-gated-evidence | The `TEST_KPASSWD=1` gate has upstream evidence only; run it locally before a release; CI has no Docker job. |
| AS/TGS client flows | covered-with-gated-evidence | The full Docker MIT gate has upstream evidence only; run it locally before a release; CI has no Docker job. |
| AP-REQ/AP-REP service validation | covered-with-gated-evidence | The Docker HTTP/SPNEGO gate has upstream evidence only; run it locally before a release; CI has no Docker job. |
| GSSAPI, SPNEGO, and HTTP Negotiate tokens | covered-with-gated-evidence | The HTTP wrapper tests run in CI (`test`); the Docker SPNEGO gate has upstream evidence only. |
| PAC and NDR parsing | covered-needs-ad-evidence | Run `TESTAD=1` against a maintained AD lab. |
| Docker MIT KDC integration fixtures | covered-with-gated-evidence | Run `scripts/run-gated-integration.sh` locally; the upstream workflow-dispatch job isn't part of this CI. |
| Active Directory integration | blocked-on-lab | Blocked until reachable USER/RESOURCE AD endpoints exist; do not claim AD parity. |
| Out-of-scope non-gokrb5 platform features | intentionally-out-of-scope | Keep typed unsupported-store errors and do not block parity on these. |

Intentional divergences from the gokrb5 baseline are recorded as they land:

- **AP-REQ client identity (hardening).** `Validator::validate_ap_req`
  compares the authenticator's client realm with the ticket's `crealm` in
  addition to the ordered name components, per RFC 4120 section 3.2.3, and
  returns the ticket-derived client identity in `ValidatedApReq.client`.
  gokrb5 v8.4.4 compares principal components only
  (`types.PrincipalName.Equal`) and exposes authenticator-derived credentials;
  this divergence is deliberate hardening and is revisited if upstream changes.
- **AS/TGS reply enctypes and `permitted_enctypes` (hardening).** The client
  rejects an AS-REP whose reply-key enctype, or an AS/TGS reply whose session
  key enctype, is not in the request's `etype` list
  (`rskrb5_ng::error::Client::EnctypeNotRequested`). An explicitly configured
  `[libdefaults] permitted_enctypes` narrows the request lists, rejects
  session keys outside it in the config-driven exchanges
  (`rskrb5_ng::error::Client::EnctypeNotPermitted`), and makes an explicit
  `default_tkt_enctypes`/`default_tgs_enctypes` entry outside it a parse error
  (`rskrb5_ng::error::Config::EnctypeNotPermitted`); the seeded default list changes
  nothing. An explicit `permitted_enctypes` that resolves to no supported
  enctype is a parse error (`rskrb5_ng::error::Config::NoPermittedEnctypes`) rather than
  "no policy". gokrb5 v8.4.4 derives the reply key from the reply's own
  `EncPart.EType` without consulting the request list
  (`messages.ASRep.DecryptEncPart`) and parses `PermittedEnctypeIDs` without
  consuming it. MIT krb5 enforces `permitted_enctypes`; this follows MIT and is
  revisited if upstream changes.
- **DES3 enctype names (MIT spelling).** `des3-cbc-sha1`, `des3-hmac-sha1`
  and `des3-cbc-sha1-kd` all resolve to enctype 16, as in MIT krb5's enctype
  table, and the seeded default list no longer names `des3-cbc-sha1`. gokrb5
  v8.4.4 (`iana/etypeID`) maps `des3-cbc-sha1` to its unimplemented etype 7
  and `des3-hmac-sha1` to 8, and lists `des3-cbc-sha1` in its default
  enctypes, where it is ignored; only `des3-cbc-sha1-kd` means 16 there. This follows MIT, whose
  `krb5.conf` files use the shorter names, and is revisited if upstream
  changes.
- **kpasswd success provenance (hardening).** A kpasswd reply reports success
  only through a verified AP-REP and KRB-PRIV; a bare KRB-ERROR carrying result
  code 0 fails with `rskrb5_ng::error::Kadmin::UnauthenticatedSuccess`, and the
  high-level client keeps its stored password. gokrb5 v8.4.4 reaches the same
  outcome by a different path (`kadmin.Reply.Decrypt` returns any KRB-ERROR
  reply as an error), so this entry records a behaviour change against earlier
  `rskrb5` releases rather than a new gap against gokrb5.
- **Host-based SPN case (RFC 4120 section 6.2.1).**
  `Principal::host_based_service` and `host_based_service_in_realm` fold the
  DNS host component to lower case, so host-case variants name one service
  principal and share one cached service ticket. Service names, realms and
  `Principal::parse_service` keep their case. gokrb5 v8.4.4 keeps the host
  text as given (`spnego.setRequestSPN` lower-cases only a CNAME-resolved
  name, and `types.NewPrincipalName` never folds).
- **Mutual authentication in the HTTP wrappers (hardening).** When the
  initiator requests mutual authentication (the `mutual-required` AP option or
  `CONTEXT_FLAG_MUTUAL`), a completion without an AP-REP classifies as
  `InvalidToken`, and `send_with_negotiate_options` and
  `send_with_blocking_negotiate_options` return
  `NegotiateHttpError::MutualAuthenticationNotProven` unless the final
  response carries an AP-REP that verifies against the initiator context.
  Requests without a mutual flag behave as before. gokrb5 v8.4.4's
  `spnego.Client.Do` returns the retried response without inspecting a
  response token; this divergence is deliberate hardening.
- **`[domain_realm]` lookup (MIT `krb5.conf(5)`).** `Config::resolve_realm`
  folds the queried host name to ASCII lower case after dropping a trailing
  dot, and at each suffix level, most specific first, consults the leading-dot
  tag and then the bare tag. A bare tag such as `example.com` therefore covers
  the domain and its subdomains, a leading-dot tag still does not match the
  domain itself, and realm values keep their case. gokrb5 v8.4.4 lower-cases
  the tags when parsing (`config.DomainRealm.parseLines`) but compares the
  query as given and walks leading-dot tags only (`config.Config.ResolveRealm`),
  so a mixed-case host misses its mapping and a bare tag matches only that
  exact host. This follows MIT krb5 and is revisited if upstream changes.
- **`[libdefaults] clockskew` on the `Config`-driven acceptors.**
  `Validator::from_default_keytab_name` and
  `Validator::from_default_keytab`, and the `NegotiateLayer` and
  `NegotiateService` constructors of the same names, apply the parsed
  `clockskew` to authenticator freshness and to the ticket start and end time
  checks. The plain constructors (`Validator::new`, `from_keytab`,
  `from_keytab_cow`) keep the 300 s default. Earlier `rskrb5` releases ignored
  a configured `clockskew` in these constructors. gokrb5 v8.4.4 reads
  `clockskew` on the client side only (`messages.ASRep.Verify`,
  `messages.TGSRep.Verify`); its AP-REQ acceptor (`service.VerifyAPREQ`,
  `spnego.SPNEGOService`) takes no krb5.conf and uses the
  `service.MaxClockSkew` setting or a 5-minute default
  (`service.Settings.MaxClockSkew`).
- **TGT refresh and renewal series.** A TGT is due for refresh in the last
  sixth of its current ticket life, `end_time - start_time`: a renewal
  advances `start_time` while `auth_time` stays fixed (RFC 4120), so a
  just-renewed TGT is not due again at once.
  `Tokio::spawn_auto_renewal_with_retry` (and `spawn_auto_renewal`,
  60 s) sleeps the retry delay after a refresh that fails or leaves the TGT
  still due, so a cache-only, non-renewable TGT does not spin through the
  band. With a configured password or keytab, an expired TGT whose
  `renew_till` is still in the future goes straight to the AS exchange, and a
  refused renewal falls back to it (`affirm_login`, `refresh_tgt_if_needed`,
  `get_service_ticket` and auto-renewal); cache-only clients keep the renewal
  error. gokrb5 v8.4.4 measures the band from `end_time - auth_time`
  (`client.Client.ensureValidSession`), sleeps five sixths of the remaining
  validity between automatic attempts
  (`client.Client.enableAutoSessionRenewal`), and returns the renewal error
  without an AS fallback while `renew_till` is in the future
  (`client.Client.refreshSession`). Earlier `rskrb5` releases matched gokrb5
  on the band and the missing fallback, and re-ran a no-progress auto-renewal
  without pause; this entry records a behaviour change against them.
- **Credential-cache record counts (hardening).** `CCache::parse` checks
  every principal component, address and authorization-data count against the
  bytes left in the input before reserving memory, and reports an impossible
  count as `rskrb5_ng::error::Ccache::Truncated` (`rskrb5_ng::error::Ccache::LengthOverflow` when
  the count's byte size does not fit `usize`, as on 32-bit targets). Earlier
  `rskrb5` releases reserved capacity straight from these counts, so a short
  malformed cache could abort the process on a failed allocation; this entry
  records a behaviour change against them. gokrb5 v8.4.4 also sizes the
  address and authorization-data slices from the embedded counts (`make` in
  `credentials.parseCredential`) and slices the input without bounds checks
  (`credentials.readBytes`), so a malformed cache can panic its parser.

The 0.3.0 review backlog adds the divergences below. Each one is a fix with a
regression test, indexed in [`review/README.md`](review/README.md); the
gokrb5 behaviour cited is from the v8.4.4 source.

- **Enctype defaults and unsupported names.** The default enctype lists are
  AES only; RC4 and DES3 need `[libdefaults] allow_rc4` or `allow_des3`, and
explicit lists skip unsupported or disabled names and fail if none is usable
(`rskrb5_ng::error::Config::NoUsableEnctypes` for requests,
`rskrb5_ng::error::Config::NoPermittedEnctypes` for allowlists). Family names,
`DEFAULT` and `-name` tokens are not expanded, as in 0.2.2. gokrb5 v8.4.4 defaults to a
  list that includes `des3-cbc-sha1` and `arcfour-hmac-md5`
  (`config.newLibDefaults`) and silently drops names it doesn't support
  (`config.parseETypes`).
- **Ticket and authenticator versions, transited policy.** Tickets with
  `tkt-vno` other than 5 and authenticators with `authenticator-vno` other
  than 5 are rejected, and a cross-realm ticket without
  TRANSITED-POLICY-CHECKED is rejected unless a caller-supplied
  `TransitValidator` accepts its path (RFC 4120 sections 2.7 and 3.3.3.2).
  gokrb5 v8.4.4 checks neither version field nor the transited encoding
  outside its tests.
- **SPNEGO negotiation.** The acceptor verifies supplied mechListMICs and
  requires one for non-first Kerberos selection, replying with a reciprocal MIC
  (RFC 4178 sections 4 and 5). Stateless continuations fail closed. gokrb5 v8.4.4 marks
  `MechListMIC` as unused for Kerberos (`spnego/negotiationToken.go`).
- **Replay cache bounds.** Replay caches have their own skew and a capacity
  (300 s and 65,536 records by default), expire entries and fail closed when
  full. gokrb5 v8.4.4 keeps one process-wide map without a capacity
  (`service.GetReplayCache`).
- **AES-SHA2 decryption order.** The HMAC is verified before decryption
  (RFC 8009 section 5). gokrb5 v8.4.4 decrypts first and verifies after
  (`rfc8009.DecryptMessage`).
- **KDC transport limits.** KDC TCP framing uses 31-bit lengths and rejects
  the reserved high bit (RFC 4120 section 7.2.2), and an oversized UDP
  datagram is `rskrb5_ng::error::Client::UdpResponseTooLarge`. gokrb5 v8.4.4
  reads a full 32-bit length (`client.sendTCP`) and returns the first 4,096
  bytes of a UDP reply as the response (`client.sendUDP`).
- **kpasswd retries.** Once a kpasswd request may have been delivered, the
  client never retries it on another endpoint or protocol and returns
  `rskrb5_ng::error::Client::KpasswdOutcomeUnknown`. gokrb5 v8.4.4 moves to
  the next server after any send or receive error (`client.dialSendUDP`,
  `client.dialSendTCP`, used by `client.Client.sendToKPasswd`).

## Parity Gates

These gates are the parity proof points for gokrb5 behaviour. The CI workflow
of this repository has no Docker integration job and no Active Directory job
([`gated-integration.md`](gated-integration.md)), so the five Docker MIT gates
have the status `historical-upstream`: their only green runs are GitHub
Actions runs of the upstream `clelange/rskrb5` workflow, attributed as such in
[`gokrb5-parity.toml`](gokrb5-parity.toml). They are not
`required_for_release`; run them locally with the command shown before a
release that touches the code they prove.

| Gate | Status | Proves | Command | Evidence and next action |
|---|---|---|---|---|
| Full Linux Docker MIT integration | historical-upstream | docker-mit, client, service, ccache | `scripts/run-gated-integration.sh run --test client_integration` | Upstream run `28073249506` passed 40 Docker MIT `client_integration` tests on `ubuntu-latest`. Run locally. |
| Linux Docker MIT password-change integration | historical-upstream | kadmin-kpasswd, client | `TEST_KPASSWD=1 scripts/run-gated-integration.sh run --test client_integration` | Upstream run `28073249506` passed `docker_mit_kdc_tokio_client_change_password`. Run locally. |
| Linux Docker DNS-SRV KDC discovery | historical-upstream | docker-mit, client | `TEST_DNS_KDC=1 scripts/run-gated-integration.sh run --test client_integration docker_mit_kdc_dns_srv_as_login -- --nocapture` | Upstream run `28073249506` passed `docker_mit_kdc_dns_srv_as_login`. Run locally. |
| Linux Docker privileged external ccache | historical-upstream | ccache, client | `TESTPRIVILEGED=1 scripts/run-gated-integration.sh run --test client_integration` | Upstream run `28073249506` passed the external `kinit` and `kvno` ccache tests. Run locally. |
| Linux Docker HTTP SPNEGO service integration | historical-upstream | service, gssapi-spnego, client | `scripts/run-gated-integration.sh run --test client_integration docker_mit_kdc_spnego_header_authenticates_to_docker_http -- --nocapture` | Upstream run `28073249506` passed HTTP SPNEGO, raw KRB5 Negotiate and replay rejection tests. Run locally. |
| Active Directory TESTAD integration | blocked-on-lab | active-directory, PAC, client, service | `scripts/check-github-ad-gate.py` | Upstream run [`28119806826`](https://github.com/clelange/rskrb5/actions/runs/28119806826) passed the hosted keytab-secret dry-run, and upstream run [`28117082548`](https://github.com/clelange/rskrb5/actions/runs/28117082548) decoded the four keytab secrets before failing on the absent endpoint secrets. There is no hosted AD job here; see [`ad-integration.md`](ad-integration.md). |
| Ready-to-use HTTP Negotiate client wrapper | proven | gssapi-spnego, client | `cargo test --all-features --test http` | Runs in the CI `test` job. Async `send_with_negotiate` and blocking `send_with_blocking_negotiate` retry 401 Negotiate responses through replayable request factories. |

## Deferred Blockers

- Active Directory parity remains blocked on reachable endpoints:
  `TEST_AD_USER_KDC_ADDR`, `TEST_AD_RESOURCE_KDC_ADDR`,
  `TEST_AD_USER_ADMIN_ADDR`, and `TEST_AD_RESOURCE_ADMIN_ADDR`. The evidence
  so far is the upstream hosted keytab-secret dry-run plus the static AD
  keytab fixture coverage, which doesn't prove Windows AD PAC parity.
- Do not add random or placeholder AD endpoint secrets. Endpoint secrets should
  be set only for real services reachable from the selected runner.
- Restoring a hosted Docker or AD gate means adding the job and its
  `workflow_dispatch` inputs to `ci.yml`;
  `scripts/check-github-ad-gate.py --dispatch` refuses to dispatch until then.
- Use [`samba-ad-feasibility.md`](samba-ad-feasibility.md) as a backup spike
  only; do not treat Samba results as Windows AD parity evidence.

## Status Values

- `covered`: unit and fixture evidence is sufficient for this parity area.
- `covered-with-gated-evidence`: implemented and unit-covered, but release
  confidence depends on keeping a live Docker or privileged gate green.
- `covered-needs-ad-evidence`: implemented and unit-covered, but AD parity is
  not proven until `TESTAD=1` runs against a maintained lab.
- `partial`: meaningful implementation exists, but a user-facing gokrb5 parity
  behavior is still missing.
- `needs-live-evidence`: implementation may exist, but current proof is not
  broad enough for a release parity claim.
- `blocked-on-lab`: code exists, but external infrastructure is required.
- `historical-upstream`: the gate was captured green only by the upstream
  `clelange/rskrb5` workflow; this repository's CI doesn't run it.
- `proven`: the named gate has been captured green on the required platform and
  should stay green before release.
- `unproven`: the test, fixture, or implementation target is known, but the
  release-blocking proof has not been captured on the required platform.
- `missing-api`: supporting pieces exist, but the user-facing parity API is not
  implemented yet.
- `intentionally-out-of-scope`: not required for gokrb5/v8 parity.
