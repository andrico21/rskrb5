# rskrb5-patched: master checklist

Single source of truth for planned vs implemented work. State as of
2026-10-25, after the plan `rskrb5-review-fixes-lint-alignment` (todos 1-34)
brought the review corrections onto the fix branches, integrated them on
`release/0.3.0` and adopted the strictest lint profile there. The earlier
state (2026-10-23) was re-verified independently from the omp session
`01a112a7` ("Deepseek_code_review_fixes", worker: DeepSeek v4.1 flash).

`[x]` done · `[~]` done, follow-up open · `[ ]` open

**Verification on the fix branches (2026-10-23, then again after todos 1-7):**
every branch was run at its pushed tip with
`cargo test --all-features --no-fail-fast` (33/33 test targets), `cargo fmt
--check`, and upstream-shaped clippy (`--all-targets --all-features -D warnings
-A clippy::chunks_exact_to_as_chunks`), which reports only the three
pre-existing `byte_char_slices` spans in `tests/kadmin.rs` (fixed upstream by
PR [#15](https://github.com/clelange/rskrb5/pull/15)).

**Fail-before on the release line (todo 30, 2026-10-25):** on `release/0.3.0`
at `f18676f`, after the lint rewrite, each of the 14 fixes (plus the include
expansion check) was neutralised by a recorded mutation. All 15 mutation rows
compiled and failed at least one test; every baseline run passed.

## 0. Releases and branch hygiene

- [x] `rskrb5-patched` 0.2.1 published (2026-10-06).
- [x] `rskrb5-patched` 0.2.2 published (tag `v0.2.2` @ `58b27bb`, 2026-10-23). It contains HIGH H1, HIGH H2, the TCP transport fix and the seven earlier fork patches listed in `FORK-NOTES.md`.
- [x] `release/0.2.2` docs commits are pushed (`7c5e834`, `fc76838`, `fa70325`, `ca1ee89`), and CI is green on `ca1ee89`.
- [x] `chore/deps-refresh` @ `4142dce`: lockfile-only refresh on top of `58b27bb`. It bumps `crossbeam-epoch` 0.9.18→0.9.21 (the RUSTSEC-2026-0204 package).
- [x] **Integration branch `release/0.3.0`** (todo 8), cut from `release/0.2.2` (`ca1ee89`). Nine `--no-ff` merges in order: `chore/deps-refresh` (`1cda96c`), `fix/ccache-count-bounds` (`8f2f349`), `fix/kadmin-unsigned-success` (`f672e0f`), `fix/config-clockskew-handoff` (`9100631`), `fix/host-case-spn` (`ac63244`), `fix/domain-realm-normalization` (`deb553e`), `fix/enctype-policy` (`be6e156`), `fix/client-renewal-series` (`4745962`), `fix/mutual-auth-classification` (`082778d`). The replay correction `b7fb459` is cherry-picked as `a1ace38`. `07f1eb3` validates enctype explicitness across `include`/`includedir` files, with its two tests.
- [x] **Version 0.3.0** (todo 9, `cebf1a7`). `cargo semver-checks` against 0.2.2 reported the major changes before the bump and passes after it. The new variants and fields:
  - `LibDefaults.permitted_enctypes_explicit`
  - `InitiatorContext.context_flags`
  - `rskrb5_ng::error::Client::{EnctypeNotRequested, EnctypeNotPermitted}`
  - `rskrb5_ng::error::Kadmin::UnauthenticatedSuccess`
  - `rskrb5_ng::error::Config::EnctypeNotPermitted`
  - `NegotiateHttpError::MutualAuthenticationNotProven` and the new body type parameter
- [x] CHANGELOG `[0.3.0]`, FORK-NOTES (table rows, "Upgrading from 0.2", Retirement) and `docs/gokrb5-parity.md` divergence entries for the behaviour changes (todos 9 and 24):
  - kpasswd rejects an unsigned success;
  - out-of-list enctypes are rejected (a gokrb5 divergence), and an explicit request list outside an explicit `permitted_enctypes` is a parse error;
  - host-based SPN hosts are lower-cased;
  - mutual-auth completion fails closed, in the classifier and in the send wrappers.
- [x] Fork tooling (todo 10, `dd5e57d`): the fuzz crate depends on the renamed package, and `release.yml` publishes with `--locked`. The `--locked` change also landed on `origin/main` (todo 31, `79a28d3`), where GitHub reads the `workflow_run` release workflow.
- [x] `rust-version = "1.99"`, the latest compatible lockfile and the `proptest` dev-dependency (todo 32, `7c95579`). Held-back majors are listed in FORK-NOTES "Dependencies held back".
- [x] Property tests and a ccache fuzz target (todo 33, merged as `85377a7`).
- [x] Rust guidelines vendored at `8b52023` with checksums (todo 34, `7e21b25`).
- [x] Local worktree leftovers in the main checkout (todo 25):
  - `.gitignore` now ignores `CODE_REVIEW*.md`, `/report.json`, `/.omo/` and `__pycache__/` on the release line; the main checkout's uncommitted `.gitignore` edit is restored;
  - `report.json` (audit coverage dump, Oct 6) moved to the run-2 audit directory;
  - `.omo/` (opencode scratch) stays untracked and ignored;
  - this checklist moved from the main checkout into the release line.
- [x] Plan worktrees: the seven fix worktrees, the `lint/*` group worktrees and branches (local only, merged into `release/0.3.0`), the `reproof` worktree and the `main-publisher` worktree are removed. Only the main checkout and `release-0.3.0` remain.
- [ ] Push `release/0.3.0` and watch CI (todo 29). The tag `v0.3.0` and `cargo publish` are the maintainer's step (FORK-NOTES "Releases").
- [ ] Record the delivered facts in the reference repo's `overlays/projects/rskrb5-ng.md` (renamed from `rskrb5.md`) and re-vendor (todo 26).
- [ ] Fork-branch CI on GitHub stays red on the `fix/*` branches: they sit on upstream `6f4abc9`, and the three `byte_char_slices` diagnostics remain until upstream PR #15 lands. The release line is not affected.

## 1. HIGH (run-2 confirmed)

- [x] **H1: AP-REQ replay identity ignores the advisory name-type.** Branch `fix/service-replay-name-type` @ `b7fb459`, PR [clelange#20](https://github.com/clelange/rskrb5/pull/20) (open, body updated). Shipped in 0.2.2 (`1f85793`).
  - [x] Review follow-up, done in todo 2 (`b7fb459`, on the release line as `a1ace38`): the replay cache also indexes a SHA-256 digest of the authenticator ciphertext, so an authenticator re-presented under a rewritten ticket `sname` (a keytab alias sharing the service key) is rejected. Both alias tests fail before the change.
- [x] **H2: authenticator client realm bound to the ticket realm.** Branch `fix/service-authenticator-realm` @ `920f9b0`, PR [clelange#21](https://github.com/clelange/rskrb5/pull/21) (open). Shipped in 0.2.2 (`d23b26d`).
- [x] **Transport: Nagle stall fix plus pinned preauth stream.** Imported from upstream PR #19, with an `Auto`-fallback pinning extension. Branch `fix/tcp-preauth-pinning` @ `b1153c7`, stacked PR [Gittingc0dez/rskrb5#1](https://github.com/Gittingc0dez/rskrb5/pull/1) (open). Shipped in 0.2.2 (`88b1c91`).

## 2. Medium (run-2 confirmed): plans in this directory

| # | Item | Branch @ tip | Tests | Fail-before | Upstream PR |
|---|---|---|---|---|---|
| M1 | Ccache counts bounded before reserving (`medium-ccache-count-unvalidated.md`) | `fix/ccache-count-bounds` @ `fdf641a` | [x] | [x] exact `Truncated` bound: 3/3 fail on `vm.overcommit_memory=1` | [x] [#22](https://github.com/clelange/rskrb5/pull/22) |
| M2 | kpasswd rejects unauthenticated KRB-ERROR success (`medium-kadmin-unauthenticated-krb-error-success.md`) | `fix/kadmin-unsigned-success` @ `a089831` | [x] | [x] mutation: 3/3 tests fail | [x] [#23](https://github.com/clelange/rskrb5/pull/23) |
| M3 | `permitted_enctypes` consumed, only when set explicitly (`medium-permitted-enctypes-unconsumed.md`) | `fix/enctype-policy` @ `7c2c297` | [x] | [x] mutations: serde flag, parse-time rejection, final-only validation | [x] [#27](https://github.com/clelange/rskrb5/pull/27) |
| M4 | AS/TGS reply and session enctype bound to the request list (`medium-as-rep-enctype-downgrade.md`) | same branch | [x] | [x] | [x] [#27](https://github.com/clelange/rskrb5/pull/27), references upstream issue **#5** |
| M5 | Refresh band measured from `start_time` (`medium-renewal-window-auth-time.md`) | `fix/client-renewal-series` @ `fbf4320` | [x] | [x] | [x] [#28](https://github.com/clelange/rskrb5/pull/28) |
| M6 | Mutual-auth completion fails closed (`medium-mutual-auth-classification.md`) | `fix/mutual-auth-classification` @ `71cc63b` | [x] | [x] classifier: 2 tests fail; wrappers: 5 tests fail (4 new rejections plus the updated classifier test) | [x] [#29](https://github.com/clelange/rskrb5/pull/29) |

Follow-ups found in review, all done:

- [x] **M1 tests did not prove the fix on hosts with `vm.overcommit_memory=1`.** Todo 1 (`fdf641a`) pins the exact up-front bound (`Truncated { offset, needed, remaining }` on 64-bit, `LengthOverflow` on 32-bit) and adds the negative-count controls to `rejects_invalid_ccache_inputs`. Against the unfixed `src/ccache.rs`, all three tests now fail on this host (`vm.overcommit_memory=1`).
- [x] M3: `permitted_enctypes_explicit` survives serde (todo 3, `31e5910`: `serde(default)`; JSON without the field deserializes as implicit). The doc comment tells programmatic builders to set the flag. `7c2c297` makes an explicit request list outside an explicit `permitted_enctypes` a parse error instead of a silent narrowing (Kerberos overlay), and the intersection tests now assert on the encoded AS-REQ/TGS-REQ.
- [x] M6: the send wrappers fail closed too (todo 4, `71cc63b`): with mutual authentication requested, any result other than a verified AP-REP returns `NegotiateHttpError::MutualAuthenticationNotProven`, which keeps the response. Default-option wrappers are unchanged.
- [x] M3/M4: the ticket `enc_part` etype is deliberately not checked. The client never uses the service key; the session key is the only enctype it uses, and that one is already bound. Recorded in `medium-permitted-enctypes-unconsumed.md` (Risks).

## 3. Low (run-2 confirmed)

| # | Item | Branch @ tip | Tests | Fail-before | Upstream PR |
|---|---|---|---|---|---|
| L1 | Auto-renewal paces a no-progress refresh (`low-auto-renewal-busy-loop.md`) | `fix/client-renewal-series` @ `fbf4320` | [x] | [x] | [x] [#28](https://github.com/clelange/rskrb5/pull/28) |
| L2 | Expired renewable TGT falls back to AS when credentials exist (`low-renewal-eligibility-expired-tgt.md`) | same | [x] | [x] 2 tests fail | [x] [#28](https://github.com/clelange/rskrb5/pull/28) |
| L3 | Host-based SPN host is lower-cased (`low-host-case-service-principal.md`) | `fix/host-case-spn` @ `5dd96f2` | [x] | [x] | [x] [#25](https://github.com/clelange/rskrb5/pull/25) |
| L4 | `clockskew` reaches the Config-driven acceptors (`low-clockskew-not-consumed.md`) | `fix/config-clockskew-handoff` @ `3e4c6c5` | [x] | [x] 2 tests fail | [x] [#24](https://github.com/clelange/rskrb5/pull/24) |
| L5 | `resolve_realm` folds DNS case (`low-domain-realm-case-normalization.md`) | `fix/domain-realm-normalization` @ `20e48ab` | [x] | [x] | [x] [#26](https://github.com/clelange/rskrb5/pull/26) |
| L6 | Bare `[domain_realm]` tag covers subdomains (`low-bare-domain-tag-subdomain.md`) | same | [x] | [x] | [x] [#26](https://github.com/clelange/rskrb5/pull/26) |

Plan tests that were missing, all written in todos 1, 5, 6 and 7:

- [x] L3: `cached_service_ticket_identity_is_case_folded` (`5dd96f2`).
- [x] L5/L6: `resolve_realm_rejects_bare_prefix_extension` (`notmit.edu`) and the client-path test `service_realm_resolution_folds_dns_case` (`20e48ab`).
- [x] M5/L1/L2 (`fbf4320`):
  - `tokio_client_auto_renewal_paces_after_renewal`;
  - `tokio_client_auto_renewal_uses_as_when_renewal_refused`;
  - `tokio_client_get_service_ticket_falls_back_to_as_for_expired_renewable_tgt`.
- [x] M1: `rejects_invalid_ccache_inputs` gains the negative-count controls (`fdf641a`).

## 4. Lint profile and tooling on `release/0.3.0`

Details in `docs/lint-baseline.md` at `856da18` (the current policy is [`../lint-policy.md`](../../lint-policy.md)); summary in FORK-NOTES "Lint profile".

- [x] Nightly rustfmt profile from rmcp-server-kit, `nightly-2026-10-03` (todo 11, `8eb3977`).
- [x] Environment test helper: child-process re-exec instead of `unsafe` `set_var`, shared helpers split into `tests/support/` (todo 12, `b61c3f2`).
- [x] Baseline generator and gate scripts, stdlib Python only (todos 13 and 15, `d8731d7`, `b572dd1`): allow, profile equality, completeness, baseline ratchet, fork-lines and prose gates, each with `--self-test`.
- [x] Strictest-union profile with the item-level `lint-migration:` baseline (todo 14, `473ca10`): 7,396 entries at adoption, 6,520 after the fork-code pass.
- [x] Supply chain (todo 16, `62191fe`): `cargo deny`, `cargo audit`, `cargo vet`, `machete`, `taplo`, and the duplicate-crate list.
- [x] Fork-code compliance (todos 17-20 on `lint/*` branches, merged as `f2a959a`, `3529ae9`, `51c5e6d`, `c4d8674`) and the converged manifest refresh (todo 21, `f18676f`). FULL-TEST counts 32 `test result: ok` lines, because the report binary is `test = false`.
- [x] CI: core Section 12 jobs plus rmcp-server-kit's stricter jobs, all gates blocking (todo 22, `7e05965`). prek hooks mirror them (todo 23, `801a56c`).
- [x] Docs: `docs/lint-baseline.md`, CHANGELOG lint bullets, FORK-NOTES "Lint profile" and "Upgrading from 0.2" (todo 24, `5b87f39`). The two review advisories, O-2 (the crate-root `public facade` expect masks `pub_use` crate-wide) and O-7 (baseline predicates are exact feature sets, so only K1-K7 are supported), are documented there.
- [x] Tooling fixes found during adoption, each its own commit: `89e4427`, `dfd9798`, `5b02767`, `eba155b`, `319187e`, `dc86a2e`, `b9e1b3a`, `464f163`, `df2afc5`, `6fe2b87`, `b663fe5`, `7deb9ae`, `d77318d`, `f24901b`, `7a38abf` (generator rustdoc caps, shared target directory, crate ownership, rustdoc ordering, reference-tree compensation, module-wrap re-keying, MSRV parity, rewrite and moved-helper provenance, credit transfers, test-`Result` rules, similarity proof).

Gate and exception history, briefly: the plan allowed edits to upstream-origin
lines only under exceptions (a)-(g). Execution hit cases where Clippy cannot
place an expectation on the item, so the user or the orchestrator authorized
(h) `std` to `core`/`alloc` imports and the `public facade` reason, (i) the
single `deliberate:` expect without a PR number on
`client::build_tgs_req_for_realm_with_confounder_and_subkey`, (j)/(k) minimal
behaviour-preserving rewrites of derived types, lifetimes and `Result`
aliases, (l) the crate-level `dead_code_pub_in_binary` expectation,
(m) module-wrap re-keying counted as a move by the ratchet, and (n)/(o) `?`
rewrites in the listed fork-touched upstream tests plus one shadowing rename.
Each one is listed, with its commits, in
`docs/lint-baseline.md` at `856da18` ("Authorized upstream-line
rewrites and exceptions").

## 5. Upstream (clelange/rskrb5) bookkeeping

- [ ] PRs [#15](https://github.com/clelange/rskrb5/pull/15) (clippy 1.98), [#16](https://github.com/clelange/rskrb5/pull/16) (hex dev-dep, fixes #12), [#17](https://github.com/clelange/rskrb5/pull/17) (export padata constants, fixes #14) and [#18](https://github.com/clelange/rskrb5/pull/18) (kpasswd `text_raw`, fixes #2) are open and carried by the fork.
- [ ] PR [#19](https://github.com/clelange/rskrb5/pull/19) (third-party Nagle fix), [#20](https://github.com/clelange/rskrb5/pull/20) (H1, updated with `b7fb459`) and [#21](https://github.com/clelange/rskrb5/pull/21) (H2) are open; [Gittingc0dez/rskrb5#1](https://github.com/Gittingc0dez/rskrb5/pull/1) is open.
- [x] Upstream PRs for the 8 medium/low branches are open (todo 28), bodies in [`pr-bodies/`](pr-bodies/):

  | Branch | PR | Body |
  |---|---|---|
  | `fix/ccache-count-bounds` | [#22](https://github.com/clelange/rskrb5/pull/22) | [`medium-ccache-count-bounds.md`](pr-bodies/medium-ccache-count-bounds.md) |
  | `fix/kadmin-unsigned-success` | [#23](https://github.com/clelange/rskrb5/pull/23) | [`medium-kadmin-unsigned-success.md`](pr-bodies/medium-kadmin-unsigned-success.md) |
  | `fix/config-clockskew-handoff` | [#24](https://github.com/clelange/rskrb5/pull/24) | [`low-config-clockskew-handoff.md`](pr-bodies/low-config-clockskew-handoff.md) |
  | `fix/host-case-spn` | [#25](https://github.com/clelange/rskrb5/pull/25) | [`low-host-case-spn.md`](pr-bodies/low-host-case-spn.md) |
  | `fix/domain-realm-normalization` | [#26](https://github.com/clelange/rskrb5/pull/26) | [`low-domain-realm-normalization.md`](pr-bodies/low-domain-realm-normalization.md) |
  | `fix/enctype-policy` | [#27](https://github.com/clelange/rskrb5/pull/27) | [`medium-enctype-policy.md`](pr-bodies/medium-enctype-policy.md) |
  | `fix/client-renewal-series` | [#28](https://github.com/clelange/rskrb5/pull/28) | [`medium-client-renewal-series.md`](pr-bodies/medium-client-renewal-series.md) |
  | `fix/mutual-auth-classification` | [#29](https://github.com/clelange/rskrb5/pull/29) | [`medium-mutual-auth-classification.md`](pr-bodies/medium-mutual-auth-classification.md) |

  M3/M4 (#27) closes issue **#5**. It touches the area of issue **#4** but does not fix it.
- [ ] Fork patches without an upstream PR ("PR to follow" in FORK-NOTES):
  - issue #10, env-free constructors (`1450607`);
  - issue #11, include/includedir (`7a61eb2`);
  - issue #13, TGS subkey (`782dcb8`). Its public builder carries the only `deliberate:` expect without a PR number.
- [ ] Upstream issues with no fork fix: #1, #3, #4, #6, #7, #8, #9 (mapped in §7).

### Open follow-ups outside this plan

- [x] **`fix/enctype-policy` fails open when `permitted_enctypes` resolves to zero supported ids.** An explicit `permitted_enctypes` that names only enctypes the crate does not implement left `permitted_enctype_ids` empty, and the empty set meant "no policy". Fixed in `cc8060c` (PR #27): parsing fails with `rskrb5_ng::error::Config::NoPermittedEnctypes`, and a hand-built `LibDefaults` with the flag set and no ids fails closed (`EmptyEtypes` / `EnctypeNotPermitted`).
- [x] **MIT name `des3-cbc-sha1` is not recognized** by the enctype name parser, so a `krb5.conf` using that spelling dropped DES3 from the list. Fixed in `752832b` (PR #27): `des3-cbc-sha1` and `des3-hmac-sha1` resolve to enctype 16; gokrb5 divergence recorded in `docs/gokrb5-parity.md`.

## 6. Run-2 needs-validation leads (18): not planned, no owner

Source: `NEEDS-VALIDATION.md` in the run-2 audit directory (`security-audit-skill/rskrb5-fork/run-2/`, outside this repository). Astra cross-reference in brackets.

- [ ] PAC AD-IF-RELEVANT unbounded recursion [RSK-6DF06BE8]
- [ ] PAC claims decompression capped by producer size [RSK-B5912AE2]
- [ ] PAC NDR supplemental-credentials uncapped allocation [RSK-A9B8B032]
- [ ] Release publish authority = tag creation (Astra rejected a similar claim)
- [ ] Credential save / DIR init follows planted symlink [RSK-58A6D5DD]
- [ ] Credential saves inherit permissions [RSK-DF3180A2]
- [ ] `%{uid}`/`%{euid}` tokens from environment [RSK-DC80DC52]
- [ ] n-fold LCM 32-bit overflow (DES3) [RSK-B51C2C85]
- [ ] Unbounded PBKDF2 iterations from ETYPE-INFO2 [RSK-F240C18F]
- [ ] S4U delegated client unbound to ticket payload
- [ ] kpasswd re-sent after possible commit [RSK-4DB854C8, upstream #7]
- [ ] Default config advertises RC4 [RSK-5ECE9681; related upstream #3]
- [ ] Repeated `[realms]` sections erase realms → DNS fallback [RSK-40161D92]
- [ ] NegotiateLayer replay scope not bound to the HTTP request
- [ ] Replay cache retains entries indefinitely [RSK-7D80FA41]
- [ ] Mandatory non-PAC authorization data discarded [RSK-D1D6BDC3]
- [ ] Cross-realm transit unchecked [RSK-3E3C2278]
- [ ] SPNEGO/GSS ignores the mandatory authenticator checksum and sequence number [RSK-FAF64A85]

## 7. Astra full review (86 items, `CODE_REVIEW-Astra.md`, rev `f441b11`): coverage

Sections A and B are covered above: the 5 A items map to H1, H2, M2, M6 and M4, and all 12 B items are run-2 leads in §6. Of the 69 C items:

- **Fixed on a branch (6):**
  - RSK-23EF3999 → M1;
  - RSK-BD020741 → L5;
  - RSK-EAB257B2 → L3;
  - RSK-28F38FD2 → L2;
  - RSK-B073D0EF → M5;
  - RSK-EB15E20D → L1.
- **Tracked as run-2 leads (3):** RSK-DC80DC52, RSK-5ECE9681, RSK-FAF64A85.
- **Fork tooling, fixed on `release/0.3.0` (4):**
  - [x] RSK-9F0AA293: the fuzz crate depends on `rskrb5-patched` (todo 10);
  - [x] RSK-79738020: `release.yml` publishes with `--locked` (todos 10 and 31);
  - [x] RSK-A9CD2563: CI has an `msrv` job, now for `rust-version = "1.99"` (todos 22 and 32);
  - [x] RSK-E17B794B: `deny` and `audit` jobs gate CI (todos 16 and 22).

  Not re-checked: RSK-E0AFE152 and RSK-A8D595D8.
- **Unplanned backlog (56):**
  - [ ] **P1, unplanned:** RSK-C4BE57A0: SPNEGO acceptance does not enforce mechanism selection or mechanism-list integrity.
  - [ ] Client: RSK-AFE184E0, RSK-34601373, RSK-072A268D, RSK-2099CE19, RSK-BC016031, RSK-F526D18D, RSK-E48DA39B, RSK-1922A31B, RSK-45397760.
  - [ ] kpasswd/messages wire: RSK-A5F7D975, RSK-3B6BA222, RSK-789A6FBB, RSK-0C0007B7, RSK-6A673A85.
  - [ ] Secrets and async contracts: RSK-471362A3 (#1), RSK-14E2755A (#8), RSK-8BBFC1EE (#8), RSK-361F35CC, RSK-DEF6C438 (#6), RSK-5E15962F.
  - [ ] Transport/DNS/IPv6: RSK-DBD57F3E, RSK-03EDCC7E, RSK-3F13B5FE, RSK-0D8D7D97, RSK-484961E9, RSK-4AD555A5, RSK-DF8D47BE, RSK-521F824C, RSK-351DC798.
  - [ ] Config enctype names: RSK-77250646 (#4), RSK-45AC5D3A.
  - [ ] Files: RSK-98FEE876, RSK-01B7A90E, RSK-7F30E854.
  - [ ] Service/GSS/SPNEGO: RSK-39F18D3B, RSK-985742B6, RSK-B161A328, RSK-84FA90AE, RSK-2A906A3A, RSK-622F4664 (C4BE57A0 above).
  - [ ] DER/OID: RSK-2A2C1928, RSK-7487E947.
  - [ ] Crypto: RSK-11BF294C, RSK-CE4ACA12, RSK-8F3B02EE, RSK-FA2BF25E, RSK-911A31CB.
  - [ ] PAC/NDR: RSK-DB101DC5, RSK-8BA3D269, RSK-59B45280, RSK-8E17F182, RSK-6A286805, RSK-D33671B2.

## 8. Other plan sources

- The Opus-authored `~/rskrb5/.omo/plans/rskrb5-review-findings.md` (opencode `ses_f9916e436ffekD7DaaRqFUHeCO`, 2026-09-03) no longer exists on disk. Its drafts fed upstream issues #1-#9 (all filed 2026-09-03); for example, its E4 is #4 and its E13 is #5. Those issues are tracked in §5/§7.
- The plan that produced 0.3.0, `rskrb5-review-fixes-lint-alignment`, lives in the local opencode scratch (`.omo/plans/`, not committed); its evidence files sit next to it.
