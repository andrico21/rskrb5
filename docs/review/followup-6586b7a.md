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
| FU-TRN-01 | minor | Local request-time errors are labeled authenticated reply-control errors | open | - | - | - |
| FU-TRN-02 | major | Reflected request KRB-PRIV can become password-bearing failure text | open | - | - | - |
| FU-TRN-03 | major | Unsigned rejection is treated as definitive password-change failure | open | - | - | - |
| FU-TRN-04 | minor | Windows oversized UDP reports Io instead of promised size error | open | - | - | - |
| FU-TRN-05 | minor | Final configured-kpasswd mapping branch is unreachable | open | - | - | - |
| FU-TRN-06 | minor | Config Auto path discards pinned TCP conversation | open | - | - | - |
| FU-TRN-07 | minor | Password endpoint errors omit endpoint authority | open | - | - | - |
| FU-TRN-08 | minor | Obsolete Clone bounds constrain password address APIs | open | - | - | - |
| FU-TRN-09 | minor | Password UDP duplicates bounded transport primitives | open | - | - | - |
| FU-TRN-10 | major | Public checked-result helpers omit AP-REP/context verification | open | - | - | - |
| FU-TRN-11 | major | Delivered decrypt/validation failure loses unknown-outcome wrapper | open | - | - | - |
| FU-TRN-12 | minor | UDP kpasswd admin fallback queries nonexistent protocol variant | open | - | - | - |
| FU-TRN-13 | minor | One unresolvable explicit-DNS SRV target aborts all failover | open | - | - | - |
| FU-TRN-14 | info | Password-specific ASN.1 owner retains dependency plaintext | open | - | - | - |
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
| FU-TST-05 | minor | Explicit MIT integration requests can pass with no live assertions | open | - | - | - |
| FU-TST-06 | minor | AD password-reply interoperability is an open question | open | - | - | - |
| FU-TST-07 | minor | Live harness IPv6 authority helpers disagree with production parser | open | - | - | - |
| FU-TST-08 | minor | Transport ambient-read regression is a bypassable substring check | open | - | - | - |
| FU-TST-09 | minor | Auto TCP-first test does not observe an unwanted UDP probe | open | - | - | - |
| FU-TST-10 | minor | Environment-selected live TCP probe is unbounded | open | - | - | - |
| FU-GATE-01 | major | Whole-tree scans omit build scripts/custom Cargo target paths | fixed | `allow_gate`/`exception_gate` self-tests: a root `build.rs` and a `[[bin]] path = "tools/probe.rs"` with forbidden attributes fail `--enforce`, an empty source set fails; `source_set.py --self-test` (outside path, out-of-line `mod`); red on 7ff0c7d recorded; commits `7e8db11`, `e71481e` | The gates scan every Rust source the Cargo manifests compile (build scripts, custom target paths) and fail on a target outside the checkout, an out-of-line `mod` in a file scanned alone, or an empty source set | - |
| FU-GATE-02 | minor | Removed baseline machinery leaves ineffective flags/dead helper work | fixed | `gate_hygiene.py --enforce` (new gate; 10 dead options/helpers on 7ff0c7d, 0 now) and its self-test; `facade_gate`/`allow_gate`/`prose_gate`/`profile_eq` self-tests distinguish report vs `--enforce`, a real level mismatch and an empty `--paths` selection; commit `07ff5f5` | `--report` (allow/exception/facade/prose gates) and `completeness_check.py --enforce` removed; `fuzz_lint.py` without `--enforce` reports and exits 0; facade output names the owner module and statement; `--paths` with an empty selection selects nothing everywhere; dead scanner helpers removed | - |
| FU-GATE-03 | major | Spaced/raw lint paths bypass exception allowlist | fixed | `exception_gate.py --self-test` HIDDEN_LINTS (spaced, raw, spaced raw and unparsed lint paths beside a sanctioned lint each a violation naming `unwrap_used`); compiler-backed fixture (`clippy-driver -D clippy::unwrap_used` exit 0 on the spaced and raw forms); red on 7ff0c7d recorded; commits `878a318`, `e71481e` | Lint paths are canonicalized (`clippy :: r#unwrap_used` = `clippy::unwrap_used`); an argument that is not a lint path is reported as `<unparsed: ..>` | - |
| FU-GATE-04 | minor | Closure matrix guard ignores lint-capping environment/config/shell | fixed | `feature_closures.py --self-test`: 11 new rejected workflows (job/step/workflow env caps, the fuzz-build env pair, `RUSTC_WRAPPER`, workflow/job defaults shell, step shell, container, working-directory, foreign action) and 6 rejected `.cargo/config.toml` variants; red on 7ff0c7d recorded; commit `3ce5b9c` | `check-ci` also rejects lint-capping or failure-swallowing settings in or above the closures job and checks `.cargo/config.toml` (`build.warnings = "deny"`, no rustflags, wrapper, rustc or Cargo/rustc `[env]`) | - |
| FU-GATE-05 | minor | Fuzz coverage passes empty inventory and CI omits inventory enforcement | fixed | `fuzz_coverage.py --self-test` (missing/empty table fails both `--inventory` and `--coverage`; targets from `fuzz/Cargo.toml`); `fuzz_coverage.py --enforce` in CI `lint-gates` and prek, held there by `workflow_gate.py`; red probe on 7ff0c7d recorded; commit `8d0233e` | `fuzz_coverage.py --enforce` (= `--inventory`) is a blocking gate; targets come from the fuzz manifest, so no cargo-fuzz is needed | - |
| FU-GATE-06 | minor | Inventory validator never checks rows still name defined symbols | fixed | `fuzz_coverage.py --self-test`: stale target row, stale reason-only row and wrong-impl row rejected; helper and trait-impl rows stay valid; on the real tree it named exactly the stale `parse_explicit_enctypes` row; commit `8d0233e` | The inventory check rejects a row whose function is no longer defined in its source file | - |
| FU-GATE-07 | major | Prose checks miss macro-generated items and non-src production | fixed | `prose_gate.py --self-test` GENERATED (macro_rules async fn, metavariable name, test, Drop; foreign macro body; documented generated fn and proptest pass) and the examples-are-production fixture; red on 7ff0c7d recorded; commit `8d83f5c` | Prose rules apply to every non-test file (examples, fuzz targets, build scripts) and to items generated by macro definitions or invocations; `proptest!` cases are exempt only from test-docs/test-result | - |
| FU-GATE-08 | minor | Nearby unrelated/empty cancellation prose satisfies another function | fixed | `prose_gate.py --self-test` ATTACHED (note above an earlier item, blank line, empty note, heading only, heading followed by another heading rejected; attached, wrapped and doc-section contracts pass); red on 7ff0c7d recorded; commit `8d83f5c` | A cancellation contract must be attached directly above its function and contain text | - |
| FU-GATE-09 | nit | SemVer helper orders prerelease numbers lexically | fixed | `semver_baseline.py --self-test` orders `alpha < alpha.1 < rc.2 < rc.10 < rc.a < release`; red probe on 7ff0c7d (`rc.10 < rc.2`) recorded; commit `8eb33fe` | none (helper contract) | - |
| FU-GATE-10 | minor | Semver baseline tag need not match manifest version | fixed | `semver_baseline.py --self-test`: tag `0.3.9` on a `0.3.0` manifest is reported and cannot select a baseline (published `0.3.1` is chosen for 0.4.0); red probe on 7ff0c7d (selected `v0.3.9`) recorded; commit `8eb33fe` | Baselines come from the crates.io version list; a release tag (`N.N.N` or historical `vN.N.N`) whose manifest names rskrb5-ng with another version fails the job | - |
| FU-GATE-11 | major | Published equal-version baseline is skipped as first release | fixed | `semver_baseline.py --self-test` (equal published version: same sha256 = the release, other bytes fail with "version already published; bump the version"; below every published version fails; only no publication is a first release); end-to-end probe with real `cargo package` recorded; red probe on 7ff0c7d (notice) recorded; commit `8eb33fe` | semver-checks compares with the highest published version <= the candidate via `--baseline-version`; a commit keeping a published version fails until the version is bumped (old self-test assertion rewritten, old -> new in the evidence) | - |
| FU-GATE-12 | major | Fixture env writer turns operator values into shell code | fixed | `scripts/run-gated-integration.sh self-test` (run by `fixture_runner_env_file_is_private_and_redacted` and CI lint-gates): spaces, quotes, `$(..)`, backquotes, `;` and newlines round-trip byte for byte and no marker command runs; red on 7ff0c7d recorded (marker executed, spaced path cut); commit `286d5af` | The runner writes `export NAME=<printf %q value>` for a fixed variable list; operator values are data | - |
| FU-GATE-13 | major | Multiline keytab values bypass line-based secret redaction | fixed | same self-test: no line of multiline base64/hex dummy secrets appears in `env` output, both are `<redacted>`, and the stubbed test command receives the complete multiline value; red on 7ff0c7d recorded; commit `286d5af` | `env` re-reads the values by name and prints keytab HEX/BASE64 secrets as `<redacted>`, never line by line | - |
| FU-CI-01 | minor | docs.rs default build omits advertised HTTP/Tower APIs | fixed | `docsrs_check.py --self-test`; red: default-feature docs.rs-style build lacks `http/struct.NegotiateLayer.html`; green: `cargo +nightly-2026-10-03 doc --features http,tower` with `--cfg docsrs` documents it (`--verify`); new `docs` job step; commit `73176ec` | `[package.metadata.docs.rs] features = ["http", "tower"]`: docs.rs documents the HTTP helpers and the Tower middleware | - |
| FU-CI-02 | minor | AD helper regression suites are not automated | fixed | `workflow_gate.py --self-test` and `--enforce` (lint-gates job and prek hook must run `check-github-ad-gate.py --self-test` and `check-ad-integration-env-smoke.py`, plus the runner and release self-tests; red on 7ff0c7d recorded); scratch copies with the dispatch refusal or `require_value` disabled fail those commands; commit `9e679d8` | CI `lint-gates` and the prek hook run the AD helper suites | - |
| FU-CI-03 | minor | Advisory geiger fails scanning rather than reporting complete unsafe inventory | fixed | red: `cargo geiger --all-features` on the current lockfile exits 1 with "Found 336 warnings"; green: the JSON scan exits 0 and `geiger_report.py` classifies all 336 unscanned files (3 build-script outputs, 333 non-Rust files), root unsafe 0, 92 of 156 dependencies with unsafe, scan complete; `geiger_report.py --self-test`; commit `94c6486` | The advisory geiger job writes and uploads a JSON report and summary; the step fails only on a fatal scan error or an unscanned Rust source | - |
| FU-CI-04 | minor | Mutation timeout has no kill deadline/completeness aggregation | fixed | `mutants_report.py --self-test` (one shard missing and one missed mutant unrecorded both reported, exit 1; unfinished shards; open/hang rules; escaped `\|` names); on the 7953988 artifacts it reports shard 7 missing and shards 2, 5 unfinished; TERM-ignoring dummy: `timeout 3s` ran 15 s, `timeout -k 2s 3s` 5 s; commit `9d2bd53` | CI `mutants` runs 16 shards under `timeout -k 5m 170m` (job budget 200 min), and the advisory `mutants-report` job aggregates them (`--expect-shards 16`, register when present) | - |
| FU-CI-05 | minor | Release toolchain action pin is not exercised by CI | fixed | `workflow_gate.py` pin check (each `dtolnay/rust-toolchain` channel one SHA; release workflows only the `# stable` revision; every action SHA-pinned); red on 7ff0c7d (`release.yml` on the `# master` revision) recorded; commit `9e679d8` | `publish.yml` sets up the toolchain with CI's stable revision `b725eda` | - |
| FU-CI-06 | minor | Verify-build and later registry token share one runner | fixed | `registry_token_reaches_only_a_publish_job_that_builds_nothing`, `publish_runs_at_a_tag_after_a_token_free_verify_job`, `release_coordinator_holds_no_secret_and_dispatches_publish_at_the_tag` (`tests/gokrb5_parity_manifest.rs`, red on the 7ff0c7d workflows recorded); `release-publish.sh self-test` (check-ref, find-tag); commits `7e58d90`, `ee04c87`; the dispatch checks after the push are todo 8's | `release.yml` is a secret-free coordinator that dispatches `publish.yml` at `refs/tags/N.N.N` (tags without `v`, D14); `publish.yml` (workflow_dispatch only) verify-builds in a token-free `verify` job and uploads with `--no-verify` from a `publish` job that builds nothing and requires the verified sha256 (old release tests rewritten, old -> new in the evidence) | - |
| FU-CI-07 | major | Upload-success/release-failure cannot recover by rerun | fixed | `release_recovery_verifies_the_published_crate_and_creates_one_release` runs `release-publish.sh self-test`: upload ok then one `gh` failure; the re-dispatch downloads the published `.crate`, matches its sha256 and creates exactly one release; another re-dispatch creates none; different published bytes are refused; red: the 7ff0c7d publish step records `published=false` on the retry; commits `7e58d90`, `ee04c87` | Re-dispatching `publish.yml` at the tag is the recovery path (docs/RELEASING.md); an already-published version is certified only by equal sha256 | - |
| FU-FUZ-01 | major | Mutation campaign is incomplete and missed mutants are untriaged | open | - | - | - |
| FU-FUZ-02 | info | TCP outer record-mark parser lacks fuzz target by current organization | open | - | - | - |
| FU-DOC-01 | minor | Config comments reference nonexistent contributor/editor files | fixed | `rg -n -e 'CONTRIBUTING\.md' -e 'Complements \.gitattributes' .cargo/config.toml rustfmt.toml` printed the CONTRIBUTING line before and nothing after (exit 1); commit `e90e619` | none | - |
| FU-DOC-02 | minor | Packaged Markdown links target excluded files | open | - | - | - |
| FU-DOC-03 | minor | Changelog0.2.2 tag date conflicts with publication date | open | - | - | - |
| FU-DOC-04 | nit | Branch ledger claims observations missing from its own table | open | - | - | - |
| FU-DOC-05 | info | RC4 permission versus request-ID behavior is unclear in worker note | open | - | - | - |
| FU-DOC-06 | info | Brief versus NoPermittedEnctypes wording cannot be independently established | open | - | - | - |
| FU-DOC-07 | info | Migration guide omits TransitValidator method name | open | - | - | - |
| FU-DOC-08 | minor | Migration inventory advertises removed reexports/malformed generic paths | open | - | - | - |
| FU-DOC-09 | minor | Fuzz inventory still maps removed config parser | fixed | `rg -n 'config::parse_explicit_enctypes' docs/review/fuzz.md` printed the row before and nothing after; `fuzz_coverage.py --enforce` passes (330 rows); bounded coverage: `cargo fuzz coverage krb5_conf` + `llvm-cov export` proved all 28 `krb5_conf` rows, incl. `LibDefaults::usable_explicit_enctypes` (count 8) and `validate_explicit_enctypes` (count 34); commit `e322e65` | none | - |
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
| FU-DOC-23 | nit | Bare kpasswd reply profile is omitted from parse contract | open | - | - | - |
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
