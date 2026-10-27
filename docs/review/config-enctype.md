# Configuration and enctype review dispositions

Commands, initial red runs and fix-reversal QA are recorded in
`task-36-rskrb5-ng-own-way.log`.

## Acceptance receipt

Verified implementation tip: `40360cf` on `work/r-config-enctype`.
The item commits are `808ebcd`, `9007c1d`, `d0d38e1`, `71016e2`, and `40360cf`
in table order. Each fixed item has a recorded pre-fix failure and scratch
fix-reversal failure (exit 101).

Final acceptance: STRICT (36 closures, 72 commands), WIN-CLIPPY, FULL-TEST,
DOCTEST, DOCS (stable and nightly), NIGHTLY-FMT, GATES, and exact-once IDs all
exited 0. FULL-TEST: 35 successful result lines, 777 passed tests. Nine tests
were added (six config regressions and three guard tests); the inferred handoff
total is 768, not a separately executed baseline FULL-TEST in this session.
Changed Rust files have clean LSP error diagnostics.

Ownership exceptions are call-site migrations in `tests/client/as_exchange.rs`,
`tests/client/tgs_exchange.rs`, and `tests/client_ad_integration.rs`, the required
public-API migration guide, and config-domain variants in `src/error.rs`.
No merge or push was performed; the branch and worktree are retained.

| ID | Status | Tests / commit | Behaviour change for CHANGELOG | Dismissal evidence |
|---|---|---|---|---|
| RSK-40161D92 / lead `apply_section/realms-replacement-dns-fallback` | fixed | `repeated_realms_preserve_configured_endpoints`, `repeated_realms_compose_across_files`; commit suffix `(RSK-40161D92)` | Repeated realm sections, path-list files and includes compose by case-sensitive realm identity. List relations append in file order with final markers preserved; later scalar values override. Kpasswd administration fallback runs after composition. Configured routes no longer disappear into DNS fallback. | — |
| RSK-77250646 / upstream issue #4 | fixed | `assigned_enctype_names_control_encoded_request`, `permitted_enctypes_survive_a_serde_round_trip`; commit suffix `(RSK-77250646)` | Enctype names are the sole stored policy. Derived-ID methods replace writable fields/builders; request options, reply checks, diagnostics and compatibility JSON derive from current names. Empty request lists fail closed instead of substituting defaults. | — |
| RSK-45AC5D3A | fixed | `unsupported_explicit_enctype_names_are_rejected`; commit suffix `(RSK-45AC5D3A)` | Explicit ticket, TGS and permitted lists reject unsupported entries with `Config::UnsupportedEnctype` naming the key and entry, including mixed supported/unsupported lists. | — |
| RSK-5ECE9681 / lead `DEFAULT_ENCTYPES/deprecated-rc4-default` / upstream issue #3 | fixed | `default_wire_enctypes_are_aes_only`, `deprecated_enctypes_require_explicit_family_opt_in`, `deprecated_family_flags_apply_after_all_sections`; commit suffix `(RSK-5ECE9681)` | Config defaults are AES-SHA2 then AES-SHA1. RC4 and DES3 require independent `allow_rc4` / `allow_des3` flags (both false by default). Explicit disabled entries return `Config::EnctypeDisabled`; weak/export algorithms additionally require `allow_weak_crypto`. Final-section policy governs all lists. | — |
| upstream issue #10 (remainder) / project rule (13) | fixed | `ordinary_defaults_ignore_ambient_environment`, `production_environment_reads_are_explicit`, `guard_rejects_aliases_and_imports`, existing hostile-env constructor probes; commit suffix `(upstream-10)` | New/default/parse are environment-free; client-keytab preserves `%{euid}` and k5login defaults empty. Explicit `LibDefaults::from_env()` reads HOME. Ambient discovery APIs document their inputs; a whole-src guard rejects unapproved reads/import aliases. | — |
