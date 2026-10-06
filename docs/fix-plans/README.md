# Fix plans — rskrb5 audit findings

Internal working documents for the `rskrb5-patched` fork. Derived from the run-2
security audit (32 records: 14 confirmed, 18 needs-validation) against the fork
commit `f441b11`. Each plan re-verifies its source citations against upstream
`clelange/rskrb5` at `6f4abc9` (the PR target) and notes the fork line delta.

`docs/fix-plans/` is excluded from crate packaging (`Cargo.toml` `exclude`); it
is documentation for the fork and for the upstream PRs, not shipped code.

## In flight (implemented and tested on branches)

| Item | Branch | PR material |
|---|---|---|
| HIGH — AP-REQ replay identity canonicalized over the advisory name-type | `fix/service-replay-name-type` (base `6f4abc9`) | `pr-bodies/high-replay-name-type.md` |
| HIGH — authenticator client realm bound to the ticket realm | `fix/service-authenticator-realm` (base `6f4abc9`) | `pr-bodies/high-authenticator-realm.md` |
| Transport — single-segment framing + pinned preauth stream (imported from upstream PR #19's branch) + `Auto`-fallback pinning extension | `release/0.2.2` | `upstream-nagle-pr19-analysis.md`; extension body in `pr-bodies/followup-tcp-auto-pinning.md` |

## Medium (planned; not implemented)

| Plan | Problem (one line) |
|---|---|
| [medium-ccache-count-unvalidated.md](medium-ccache-count-unvalidated.md) | Ccache record counts reserve memory from an unvalidated 32-bit count; a 16-byte cache aborts the process on allocator refusal |
| [medium-kadmin-unauthenticated-krb-error-success.md](medium-kadmin-unauthenticated-krb-error-success.md) | An unsigned KRB-ERROR result code 0 is accepted as kpasswd success and replaces the stored password credential |
| [medium-permitted-enctypes-unconsumed.md](medium-permitted-enctypes-unconsumed.md) | `[libdefaults] permitted_enctypes` is parsed but consumed nowhere; requests and reply acceptance ignore the operator allowlist |
| [medium-as-rep-enctype-downgrade.md](medium-as-rep-enctype-downgrade.md) | The initial AS-REP can select a reply/session enctype outside the caller's requested list (RC4 downgrade) |
| [medium-renewal-window-auth-time.md](medium-renewal-window-auth-time.md) | Refresh scheduling measures lifetime from `auth_time`; a renewed TGT is immediately due and auto-renewal runs at round-trip rate |
| [medium-mutual-auth-classification.md](medium-mutual-auth-classification.md) | A requested mutual authentication is not enforced by HTTP completion classification (`Accepted { ap_rep: None }`) |

Cross-plan notes: the two enctype plans both touch `process_as_rep` reply
acceptance; sequence them together. The renewal plans share `src/client.rs`
refresh machinery.

## Low (planned; not implemented)

| Plan | Problem (one line) |
|---|---|
| [low-auto-renewal-busy-loop.md](low-auto-renewal-busy-loop.md) | Cache-only nonrenewable TGTs inside the refresh band make `spawn_auto_renewal` busy-loop at zero delay |
| [low-renewal-eligibility-expired-tgt.md](low-renewal-eligibility-expired-tgt.md) | An expired-but-"renewable" cached TGT keeps the automatic paths on TGS RENEW, so stored credentials never trigger a re-login |
| [low-host-case-service-principal.md](low-host-case-service-principal.md) | Host-based constructors preserve DNS host case; one DNS peer yields two Kerberos identities |
| [low-clockskew-not-consumed.md](low-clockskew-not-consumed.md) | `[libdefaults] clockskew` never reaches the acceptor window, which stays at the hardcoded 300 s |
| [low-domain-realm-case-normalization.md](low-domain-realm-case-normalization.md) | Mixed-case DNS text misses the lower-cased `[domain_realm]` mapping and moves the SPN into the client realm |
| [low-bare-domain-tag-subdomain.md](low-bare-domain-tag-subdomain.md) | A bare `[domain_realm]` tag is not applied to its subdomains |

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
