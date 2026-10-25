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
| Credential cache parsing, writing, and collection names | covered-with-gated-evidence | Keep privileged `kinit`/`kvno` ccache coverage green in Linux CI. |
| Kerberos cryptography | covered | Keep RFC/gokrb5 vectors current. |
| ASN.1 and Kerberos message wrappers | covered | Keep fixture matrix current. |
| RFC 3244 password change | covered-with-gated-evidence | Keep `TEST_KPASSWD=1` green in Linux CI. |
| AS/TGS client flows | covered-with-gated-evidence | Keep the full Linux Docker MIT gate green. |
| AP-REQ/AP-REP service validation | covered-with-gated-evidence | Keep Linux Docker HTTP/SPNEGO service coverage green. |
| GSSAPI, SPNEGO, and HTTP Negotiate tokens | covered-with-gated-evidence | Keep HTTP wrapper tests and Docker SPNEGO integration green. |
| PAC and NDR parsing | covered-needs-ad-evidence | Run `TESTAD=1` against a maintained AD lab. |
| Docker MIT KDC integration fixtures | covered-with-gated-evidence | Keep workflow-dispatched Docker-backed integration green. |
| Active Directory integration | blocked-on-lab | Deferred for 0.2.0 until reachable USER/RESOURCE AD endpoints are available; keep the dry-run evidence green and do not claim AD parity. |
| Out-of-scope non-gokrb5 platform features | intentionally-out-of-scope | Keep typed unsupported-store errors and do not block parity on these. |

Intentional divergences from the gokrb5 baseline are recorded as they land:

- **AP-REQ client identity (hardening).** `ServiceValidator::validate_ap_req`
  compares the authenticator's client realm with the ticket's `crealm` in
  addition to the ordered name components, per RFC 4120 section 3.2.3, and
  returns the ticket-derived client identity in `ValidatedApReq.client`.
  gokrb5 v8.4.4 compares principal components only
  (`types.PrincipalName.Equal`) and exposes authenticator-derived credentials;
  this divergence is deliberate hardening and is revisited if upstream changes.
- **AS/TGS reply enctypes and `permitted_enctypes` (hardening).** The client
  rejects an AS-REP whose reply-key enctype, or an AS/TGS reply whose session
  key enctype, is not in the request's `etype` list
  (`client::Error::EnctypeNotRequested`). An explicitly configured
  `[libdefaults] permitted_enctypes` narrows the request lists, rejects
  session keys outside it in the config-driven exchanges
  (`client::Error::EnctypeNotPermitted`), and makes an explicit
  `default_tkt_enctypes`/`default_tgs_enctypes` entry outside it a parse error
  (`config::Error::EnctypeNotPermitted`); the seeded default list changes
  nothing. gokrb5 v8.4.4 derives the reply key from the reply's own
  `EncPart.EType` without consulting the request list
  (`messages.ASRep.DecryptEncPart`) and parses `PermittedEnctypeIDs` without
  consuming it. MIT krb5 enforces `permitted_enctypes`; this follows MIT and is
  revisited if upstream changes.
- **kpasswd success provenance (hardening).** A kpasswd reply reports success
  only through a verified AP-REP and KRB-PRIV; a bare KRB-ERROR carrying result
  code 0 fails with `kadmin::Error::UnauthenticatedSuccess`, and the
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
  `ServiceValidator::from_default_keytab_name` and
  `ServiceValidator::from_default_keytab`, and the `NegotiateLayer` and
  `NegotiateService` constructors of the same names, apply the parsed
  `clockskew` to authenticator freshness and to the ticket start and end time
  checks. The plain constructors (`ServiceValidator::new`, `from_keytab`,
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
  `TokioClient::spawn_auto_renewal_with_retry` (and `spawn_auto_renewal`,
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
  count as `ccache::Error::Truncated` (`ccache::Error::LengthOverflow` when
  the count's byte size does not fit `usize`, as on 32-bit targets). Earlier
  `rskrb5` releases reserved capacity straight from these counts, so a short
  malformed cache could abort the process on a failed allocation; this entry
  records a behaviour change against them. gokrb5 v8.4.4 also sizes the
  address and authorization-data slices from the embedded counts (`make` in
  `credentials.parseCredential`) and slices the input without bounds checks
  (`credentials.readBytes`), so a malformed cache can panic its parser.

## Parity Gates

These gates are the release and parity proof points for gokrb5 behavior.
`required_for_release` means the gate should stay green before the next breaking
preview release unless the release notes explicitly call it out as skipped.

| Gate | Status | Proves | Command or blocker | Next action |
|---|---|---|---|---|
| Full Linux Docker MIT integration | proven | docker-mit, client, service, ccache | `scripts/run-gated-integration.sh run --test client_integration` | GitHub Actions run `28073249506` passed 40 Docker MIT `client_integration` tests on `ubuntu-latest`; keep this gate green. |
| Linux Docker MIT password-change integration | proven | kadmin-kpasswd, client | `TEST_KPASSWD=1 scripts/run-gated-integration.sh run --test client_integration` | GitHub Actions run `28073249506` passed `docker_mit_kdc_tokio_client_change_password`; keep this gate green. |
| Linux Docker DNS-SRV KDC discovery | proven | docker-mit, client | `TEST_DNS_KDC=1 scripts/run-gated-integration.sh run --test client_integration docker_mit_kdc_dns_srv_as_login -- --nocapture` | GitHub Actions run `28073249506` passed `docker_mit_kdc_dns_srv_as_login`; keep this gate green. |
| Linux Docker privileged external ccache | proven | ccache, client | `TESTPRIVILEGED=1 scripts/run-gated-integration.sh run --test client_integration` | GitHub Actions run `28073249506` passed external `kinit` and `kvno` ccache tests; keep this gate green. |
| Linux Docker HTTP SPNEGO service integration | proven | service, gssapi-spnego, client | `scripts/run-gated-integration.sh run --test client_integration docker_mit_kdc_spnego_header_authenticates_to_docker_http -- --nocapture` | GitHub Actions run `28073249506` passed HTTP SPNEGO, raw KRB5 Negotiate, and replay rejection tests; keep this gate green. |
| Active Directory TESTAD integration | blocked-on-lab | active-directory, PAC, client, service | GitHub Actions run [`28119806826`](https://github.com/clelange/rskrb5/actions/runs/28119806826) passed the hosted keytab-secret dry-run; strict run [`28117082548`](https://github.com/clelange/rskrb5/actions/runs/28117082548) reached hosted `ubuntu-latest` and decoded the four keytab secrets before failing because the endpoint secrets are absent. | Deferred for 0.2.0; revisit after reachable `TEST_AD_*_ADDR` secrets exist, then run `scripts/check-github-ad-gate.py --dispatch`. |
| Ready-to-use HTTP Negotiate client wrapper | proven | gssapi-spnego, client | `cargo test --all-features --test http` | Async `send_with_negotiate` and blocking `send_with_blocking_negotiate` retry 401 Negotiate responses through replayable request factories; keep this gate green. |

## Deferred Blockers

- Active Directory parity remains blocked on reachable endpoint secrets:
  `TEST_AD_USER_KDC_ADDR`, `TEST_AD_RESOURCE_KDC_ADDR`,
  `TEST_AD_USER_ADMIN_ADDR`, and `TEST_AD_RESOURCE_ADMIN_ADDR`. This is
  recorded but explicitly not a `0.2.0` release blocker.
- The current acceptable 0.2.0 evidence is the green hosted keytab-secret
  dry-run plus static AD keytab fixture coverage. These do not prove Windows AD
  PAC parity.
- Do not add random or placeholder AD endpoint secrets. Endpoint secrets should
  be set only for real services reachable from the selected runner; otherwise
  keep using the non-live keytab dry-run.

## Immediate Next Slices

1. Keep the workflow-dispatched Docker MIT gate green with `integration=true`,
   `test_kpasswd=true`, and `test_ad=false` before the next release.
2. Prepare release notes for the next breaking preview with the new API surface
   and the explicitly deferred AD gate called out.
3. Use [`samba-ad-feasibility.md`](samba-ad-feasibility.md) as a backup spike
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
- `proven`: the named gate has been captured green on the required platform and
  should stay green before release.
- `unproven`: the test, fixture, or implementation target is known, but the
  release-blocking proof has not been captured on the required platform.
- `missing-api`: supporting pieces exist, but the user-facing parity API is not
  implemented yet.
- `intentionally-out-of-scope`: not required for gokrb5/v8 parity.
