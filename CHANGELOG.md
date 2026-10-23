# Changelog

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
- Lockfile refreshed to the latest Rust 1.88-compatible dependency versions
  (`crossbeam-epoch` 0.9.18 to 0.9.21 among them).

### Breaking

- New enum variants on exhaustive enums: `client::Error::EnctypeNotRequested`,
  `client::Error::EnctypeNotPermitted`, `config::Error::EnctypeNotPermitted`,
  `kadmin::Error::UnauthenticatedSuccess` and
  `http::NegotiateHttpError::MutualAuthenticationNotProven`.
- `http::NegotiateHttpError<E>` becomes `NegotiateHttpError<E, B>`, where `B`
  is the response body type carried by the new variant.
- New public fields on constructible structs:
  `LibDefaults.permitted_enctypes_explicit` and
  `InitiatorContext.context_flags`.
- Behaviour: an unsigned kpasswd success is rejected; a KDC reply or session
  key outside the requested (or explicitly permitted) enctypes is rejected,
  and so is a config whose explicit request list falls outside an explicit
  `permitted_enctypes`; host-based SPNs carry a lower-cased host; and the send
  wrappers return an error when requested mutual authentication isn't proven.

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
