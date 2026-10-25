# Fix plans: rskrb5 audit findings

Internal working documents for the `rskrb5-patched` fork. Derived from the run-2
security audit (32 records: 14 confirmed, 18 needs-validation) against the fork
commit `f441b11`. Each plan re-verifies its source citations against upstream
`clelange/rskrb5` at `6f4abc9` (the PR target) and notes the fork line delta.

`docs/fix-plans/` is excluded from crate packaging (`Cargo.toml` `exclude`); it
is documentation for the fork and for the upstream PRs, not shipped code.

Fork release `0.2.2` (`58b27bb`) is published on crates.io. The next fork
release, `0.3.0`, is integrated on `release/0.3.0`: it merges
`chore/deps-refresh` (`4142dce`) and the 8 medium/low branches below at their
tips after the review corrections, cherry-picks the replay correction
(`b7fb459` as `a1ace38`), and adopts the strictest lint profile
([`../lint-baseline.md`](../lint-baseline.md)). All 14 confirmed findings are
implemented, and each has an open upstream PR against `clelange/rskrb5`
(`#20`-`#29`). The master checklist, with every follow-up and the open items,
is [`CHECKLIST.md`](CHECKLIST.md).

## HIGH and transport (shipped in 0.2.2)

The replay row's sname-alias digest index (`b7fb459`) is newer than 0.2.2; it
ships in 0.3.0 as `a1ace38`.

| Item | Branch @ tip | Upstream PR | PR material |
|---|---|---|---|
| HIGH: AP-REQ replay identity canonicalized over the advisory name-type | `fix/service-replay-name-type` @ `b7fb459` (`5148851`, sname-alias digest index `b7fb459`; base `6f4abc9`) | [#20](https://github.com/clelange/rskrb5/pull/20), body updated | [`pr-bodies/high-replay-name-type.md`](pr-bodies/high-replay-name-type.md) |
| HIGH: authenticator client realm bound to the ticket realm | `fix/service-authenticator-realm` @ `920f9b0` (base `6f4abc9`) | [#21](https://github.com/clelange/rskrb5/pull/21) | [`pr-bodies/high-authenticator-realm.md`](pr-bodies/high-authenticator-realm.md) |
| Transport: single-segment framing + pinned preauth stream (imported from upstream PR #19's branch) + `Auto`-fallback pinning extension | `fix/tcp-preauth-pinning` @ `b1153c7`, in `release/0.2.2` | [#19](https://github.com/clelange/rskrb5/pull/19); extension [Gittingc0dez/rskrb5#1](https://github.com/Gittingc0dez/rskrb5/pull/1) | [`upstream-nagle-pr19-analysis.md`](upstream-nagle-pr19-analysis.md); extension body in [`pr-bodies/followup-tcp-auto-pinning.md`](pr-bodies/followup-tcp-auto-pinning.md) |

## Medium

| Plan | Problem (one line) | Status |
|---|---|---|
| [medium-ccache-count-unvalidated.md](medium-ccache-count-unvalidated.md) | Ccache record counts reserve memory from an unvalidated 32-bit count; a 16-byte cache aborts the process on allocator refusal | implemented: `fix/ccache-count-bounds` @ `fdf641a` (`9701864`, `a37a4d1`, exact-bound tests `fdf641a`); PR [#22](https://github.com/clelange/rskrb5/pull/22) |
| [medium-kadmin-unauthenticated-krb-error-success.md](medium-kadmin-unauthenticated-krb-error-success.md) | An unsigned KRB-ERROR result code 0 is accepted as kpasswd success and replaces the stored password credential | implemented: `fix/kadmin-unsigned-success` @ `a089831`; PR [#23](https://github.com/clelange/rskrb5/pull/23) |
| [medium-permitted-enctypes-unconsumed.md](medium-permitted-enctypes-unconsumed.md) | `[libdefaults] permitted_enctypes` is parsed but consumed nowhere; requests and reply acceptance ignore the operator allowlist | implemented: `fix/enctype-policy` @ `752832b` (`6b64394`, explicit-only `f8ffc5e`, test fix `79a15db`, serde flag `31e5910`, reject-not-narrow `7c2c297`, fail-closed zero ids `cc8060c`, MIT DES3 names `752832b`); PR [#27](https://github.com/clelange/rskrb5/pull/27) |
| [medium-as-rep-enctype-downgrade.md](medium-as-rep-enctype-downgrade.md) | The initial AS-REP can select a reply/session enctype outside the caller's requested list (RC4 downgrade) | implemented: `fix/enctype-policy` @ `7c2c297` (`236c4ce`); PR [#27](https://github.com/clelange/rskrb5/pull/27) |
| [medium-renewal-window-auth-time.md](medium-renewal-window-auth-time.md) | Refresh scheduling measures lifetime from `auth_time`; a renewed TGT is immediately due and auto-renewal runs at round-trip rate | implemented: `fix/client-renewal-series` @ `fbf4320` (`29b6a51`, tests `fbf4320`); PR [#28](https://github.com/clelange/rskrb5/pull/28) |
| [medium-mutual-auth-classification.md](medium-mutual-auth-classification.md) | A requested mutual authentication is not enforced by HTTP completion classification (`Accepted { ap_rep: None }`) | implemented: `fix/mutual-auth-classification` @ `71cc63b` (`8b75cda`, send wrappers `71cc63b`); PR [#29](https://github.com/clelange/rskrb5/pull/29) |

Cross-plan notes: the two enctype plans both touch `process_as_rep` reply
acceptance; sequence them together. `permitted_enctypes` enforcement is opt-in
by explicit configuration (the seeded gokrb5 default list is narrower than
MIT's and would otherwise drop SHA2 request lists). The renewal plans share
`src/client.rs` refresh machinery.

## Low

| Plan | Problem (one line) | Status |
|---|---|---|
| [low-auto-renewal-busy-loop.md](low-auto-renewal-busy-loop.md) | Cache-only nonrenewable TGTs inside the refresh band make `spawn_auto_renewal` busy-loop at zero delay | implemented: `fix/client-renewal-series` @ `fbf4320` (`0a2cf65`, rework `20541ea`, pacing-after-renewal test `fbf4320`); PR [#28](https://github.com/clelange/rskrb5/pull/28) |
| [low-renewal-eligibility-expired-tgt.md](low-renewal-eligibility-expired-tgt.md) | An expired-but-"renewable" cached TGT keeps the automatic paths on TGS RENEW, so stored credentials never trigger a re-login | implemented: `fix/client-renewal-series` @ `fbf4320` (`9db3c87`, refused-renewal and service-ticket tests `fbf4320`); PR [#28](https://github.com/clelange/rskrb5/pull/28) |
| [low-host-case-service-principal.md](low-host-case-service-principal.md) | Host-based constructors preserve DNS host case; one DNS peer yields two Kerberos identities | implemented: `fix/host-case-spn` @ `5dd96f2` (`50e5284`, cache test `5dd96f2`); PR [#25](https://github.com/clelange/rskrb5/pull/25) |
| [low-clockskew-not-consumed.md](low-clockskew-not-consumed.md) | `[libdefaults] clockskew` never reaches the acceptor window, which stays at the hardcoded 300 s | implemented: `fix/config-clockskew-handoff` @ `3e4c6c5`; PR [#24](https://github.com/clelange/rskrb5/pull/24) |
| [low-domain-realm-case-normalization.md](low-domain-realm-case-normalization.md) | Mixed-case DNS text misses the lower-cased `[domain_realm]` mapping and moves the SPN into the client realm | implemented: `fix/domain-realm-normalization` @ `20e48ab` (`9ede05a`, tests `20e48ab`); PR [#26](https://github.com/clelange/rskrb5/pull/26) |
| [low-bare-domain-tag-subdomain.md](low-bare-domain-tag-subdomain.md) | A bare `[domain_realm]` tag is not applied to its subdomains | implemented: `fix/domain-realm-normalization` @ `20e48ab` (`9ede05a`, tests `20e48ab`); PR [#26](https://github.com/clelange/rskrb5/pull/26) |

Cross-plan notes: the three `resolve_realm`/`principal.rs` plans share the same
functions (`Config::resolve_realm`, `parse_domain_realm`, host-based
constructors); land them as one PR series to avoid overlapping hunks. The
clockskew plan edits the `Config`-driven constructors of the same
`src/service.rs` file as the two in-flight HIGH fixes (different functions).

## Not planned here

The 18 `needs_validation` records (PAC recursion/decompression chains, publish
tag authority, credential-file handling, S4U delegation, PBKDF2 work factor,
and others) remain open in the run-2 findings with their blockers and
owner-observed checks; they are candidates, not confirmed defects, and are
tracked in `run-2/NEEDS-VALIDATION.md`.
