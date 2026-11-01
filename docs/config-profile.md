# Profile composition and name expansion (todo 15, Steps A/B1/B2)

This step changes profile composition, not the set of effective Kerberos
features. B1 adds explicit-context credential-name parameter expansion.
B2 adds bounded reader adapters, dynamic-provider rejection and existing
credential-consumer integration. Additional typed relations and diagnostics
remain subsequent steps.

## Reference and lookup classification

The reference is MIT **krb5-1.22.2-final**, commit
`8570e77819563e036027e1da789d08ec9333ed4d`.
[prof_get.c:215–249](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/util/profile/prof_get.c#L215-L249)
returns only the first value for scalar lookup;
[155–194](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/util/profile/prof_get.c#L155-L194)
collects all values for multi-valued lookup. Boolean and integer getters use
the scalar lookup. A whitespace/comma-separated list inside one value is **not**
a multi-valued profile relation.

| Section | Relations currently decoded | Lookup kind |
| --- | --- | --- |
| libdefaults | allow_rc4, allow_des3, allow_weak_crypto, canonicalize, dns_canonicalize_hostname, dns_lookup_kdc, dns_lookup_realm, forwardable, ignore_acceptor_hostname, k5login_authoritative, noaddresses (alias no_addresses), proxiable, rdns, verify_ap_req_nofail | Boolean; first value |
| libdefaults | ccache_type, clockskew, default_ccache_name, default_client_keytab_name, default_keytab_name, default_realm, k5login_directory, kdc_default_options, kdc_timesync, realm_try_domains, renew_lifetime, safe_checksum_type, ticket_lifetime, udp_preference_limit | Single; first value |
| libdefaults | default_tgs_enctypes, default_tkt_enctypes, permitted_enctypes, extra_addresses, preferred_preauth_types | Delimited list inside a single value; first relation |
| realms / realm | kdc, kpasswd_server, master_kdc, admin_server | Repeated list; accumulate in source order |
| realms / realm | default_domain | Single; first value (legacy parse-only field) |
| domain_realm | each mapping key | Single; first value; existing DNS case folding retained |

`admin_server` is multi-valued for **libkrb5 location and kpasswd fallback**:
[locate_kdc.c:273–296,538–576](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/lib/krb5/os/locate_kdc.c#L273-L296),
[changepw.c:60–89](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/lib/krb5/os/changepw.c#L60-L89).
The separate kadm5 consumer selects a single string; this crate does not yet
implement that consumer.

Future typed decoding must preserve the distinction: `auth_to_local`, capaths
intermediates, plugin `disable`/`enable_only`/`module`, and endpoint
`primary_kdc` are multi-valued. Other libdefaults list syntax (for example
`spake_preauth_groups`) is contained in a scalar relation. Unknown paths are
retained during composition but are not exposed as new effective consumers in
Step A. See the later relation/diagnostic work before claiming completeness.

## Sources, finals and syntax

Files in `KRB5_CONFIG` compose in platform path-list order (colon on Unix).
A directory entry uses the same filter as `includedir`: ASCII alphanumerics,
`-`, `_`, or a non-dot name ending `.conf`. Sorting is bytewise. Includes
execute at their directive site, even inside a subsection, with fresh syntax
state and the shared profile tree; the parent resumes its original state.
See [prof_parse.c:214–256](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/util/profile/prof_parse.c#L214-L256).

`[section]*`, `subsection* = {`, `}*`, and `relation* = value` prevent later
contributions to the marked scope, within the file and across files. Earlier
values remain; a final value does not replace them. The defining block still
contributes its own values. See
[prof_parse.c:92–210](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/util/profile/prof_parse.c#L92-L210)
and [prof_tree.c:208–249](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/util/profile/prof_tree.c#L208-L249).

Comments begin with `#` or `;` after optional leading whitespace. The retained
gokrb5 extension also recognizes them after whitespace outside quotes.
`RULE:[2:$1;$2]` survives unchanged. Quoted values support escaped quotes,
backslashes, newline, tab and backspace. Braces are structural only in a
subsection assignment or closing-brace line, not arbitrary value text.

### Deliberate divergences and bounds

- Missing explicitly named `KRB5_CONFIG` entries are errors; MIT skips them.
- Include paths must be absolute; leading whitespace before a directive is
  accepted. No dynamic module code is loaded.
- The unquoted value-suffix `value*` final form is retained as a gokrb5 extension.
- Total source bytes, including caller text and root files: **4 MiB**.
  Every filesystem read stops at remaining budget plus one byte.
- Total files, including repeated reads and root files: **256**.
- Include depth: **8 edges**, with root depth zero. Subsection nesting is also
  capped at eight to bound path allocations. Excess uses `IncludeTooDeep`.
- Typed limits: `IncludeTooDeep`, `IncludeTooMany`, `IncludeTooLarge`.
  Canonical active-chain cycles use `IncludeCycle`; re-reading a completed
  source is not a cycle. Unknown-section unbalanced braces are errors.
- Existing permanent protocol rejection checks still run before discarded
  relations can hide forbidden protocol selections.

## Independent expected values

`tests/fixtures/profile/mit-sample.conf` copies the sample stanzas from
[krb5_conf.rst:1237–1256](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/doc/admin/conf_files/krb5_conf.rst#L1237-L1256).
`mit_documentation_sample_matches_expected_values` checks `ATHENA.MIT.EDU`,
DNS booleans, three ordered Athena KDCs and two ordered example KDCs against
that sample and the scalar/list getters cited above. Port 88 is the crate's
existing endpoint normalization. This is a source-derived differential fixture,
not a claim that a live MIT process was executed.

The existing `resolve_realm_applies_bare_domain_tags_to_subdomains` fixture is
MIT's three-tag example at
[krb5_conf.rst:585–603](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/doc/admin/conf_files/krb5_conf.rst#L585-L603):
`crash.mit.edu` and hosts below `.dev.mit.edu` map to `TEST.ATHENA.MIT.EDU`,
while `dev.mit.edu` and `mit.edu` map to `ATHENA.MIT.EDU`.

Composition and boundary tests live in `tests/config/profile*.rs`; the original
config tests remain, with deliberately changed expectations recorded in the
follow-up register and task evidence.

## Explicit-context name expansion (B1)

`config::parameters::expand(template, &ExpansionContext)` is pure: it reads no
environment, files or process identity. `DefaultName::{Ccache, Keytab,
ClientKeytab}.expand(&config.libdefaults, &context)` selects the first-wins
template for `default_ccache_name`, `default_keytab_name` or
`default_client_keytab_name`, then applies that same expander. Parsing still
preserves templates and does not discover facts or resolve names implicitly.
Expansion errors are raised when a name is resolved, not by ordinary parsing.

The contract follows MIT's
[parameter table](https://web.mit.edu/kerberos/krb5-1.22/doc/admin/conf_files/krb5_conf.html#parameter-expansion)
and the pinned
[1.22.2 scanner](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/lib/krb5/os/expand_path.c).

| Parameter | Explicit context fact |
| --- | --- |
| `TEMP` | Temporary directory |
| `uid`, `euid` | Real/effective `u32` identities, Linux only |
| `USERID` | Real UID on Linux; supplied SID on Windows |
| `username` | Username of the effective identity, not `USER`/`USERNAME` text |
| `null` | Empty string, without a context field |
| `LIBDIR`, `BINDIR`, `SBINDIR` | Installation directories supplied by the embedding application |
| `USERCONFIGDIR`, `USERCONFIG` | Per-user MIT configuration directory |
| `APPDATA` | Roaming application data directory |

`USERCONFIGDIR` is the plan's spelling, supported as an explicit extension:
MIT documents `USERCONFIG`. The Windows directory facts and username may be
provided explicitly on any host; this is not Windows shell-folder or account
discovery. No installation prefix, SID, username or home-derived directory is
invented. Missing facts return `parameters::Failure::Unavailable`; unrecognized
names return `UnknownToken`, and an unterminated `%{` returns
`UnterminatedToken`. Exact names are required: MIT's incidental prefix matching
is deliberately not copied.

`%%` remains two percent signs; it is not an escape. `%%{TEMP}` produces one
literal percent followed by the replacement. Inserted values, including `%{uid}`,
unknown tokens and bare `%{`, remain literal and are never recursively expanded.
Caller facts retain their path separators, rather than MIT Windows' final slash
conversion. The result is resolved data: use literal-path APIs (`Keytab::load`,
`CCache::load`) after handling any store prefix, not token-expanding name APIs.
At B1, existing name loaders retained their Linux procfs UID/eUID behavior and
the exact-owner guard inventory was unchanged. B2 connects the consumers below.

`tests/config/expansion.rs` covers each token, platform identity policy,
missing facts, exact-name errors, malformed tokens, literal percent signs,
nonrecursive Unicode replacements and resolution of all three profile names.
B1 alone does not close GAP-4/WP-01 or any additional follow-up register row.

## Reader adapters and dynamic providers (B2)

GO-config-1 names gokrb5 `Load`, `NewFromString`, `NewFromReader`,
`NewFromScanner`, `New` and `JSON`. Their Rust equivalents are respectively
`Config::load`/`from_path`, `parse`/`from_string`, `from_reader` (also accepts
`BufRead`), `new`, and `json`. No Go scanner object or redundant Rust scanner
constructor is required. The existing parity manifest has an area-level
`config` row, not a prescribed Rust constructor-name list.

`from_reader` reads at most **4 MiB plus one sentinel byte**, rejects oversize
input with `IncludeTooLarge`, rejects invalid UTF-8 with `Config::Io` carrying
`InvalidData`, and retains reader I/O causes. Successful bytes enter the same
include-aware composition as `parse`. Root and included bytes share the 4 MiB
budget; includes must be absolute, with unchanged depth/file/cycle checks.

`module MODULEPATH:RESIDUAL` and `module = ...` relations are rejected with
`Config::UnsupportedDynamicModule` in Compatible and Strict modes. This also
applies in `[plugins]`, nested or ignored sections, finalized/discarded scopes,
and included sources. No dynamic code is loaded. These cover MIT-config-54/55
refusal behavior, not the future WP-16 registered-provider implementation.

## Effective default-name consumers (B2)

Configured names now pass through `DefaultName::expand` with explicit facts
built by the credential-discovery adapter, outside profile parsing:

- Tokio ccache default load, save and update (both configured-only and
  environment-override variants), including Negotiate/blocking delegates.
- Tokio configured/default client keytab.
- Service validator and HTTP layer/service configured/default server keytab.

The name environment variables retain precedence. Their explicit values keep
the existing UID-token behavior, not new profile-template semantics. Expanded
profile values flow into literal-name/path handling without a second scan;
`DIR:` saves retain primary-file publication. The child-process regression
`ambient_templates_are_expanded_once` loads real credentials from a directory
whose substituted value itself contains `%{uid}`.

The adapter reads only requested facts: Linux real/effective IDs from the
existing procfs reader; `TMPDIR` (fallback `/tmp`) for non-Windows TEMP;
Windows `TEMP` and `APPDATA`, with `USERCONFIG[DIR]` derived as
`APPDATA\\MIT\\Kerberos5`. Invalid Unicode is an error. The Windows environment
mapping is an explicit limitation, not a claim of native shell-folder lookup.
The three new environment reads are pinned by exact path/owner in
`ambient_guard`; transitive public consumers document them and literal-input
alternatives. Configured-name loaders avoid the name-override environment but
are no longer environment-free when their templates request these facts.

For Step E: all three relations have consumers. Ambient effective-username,
Windows SID and installation-directory discovery is unavailable under the
current no-unsafe/no-new-dependency implementation; such tokens fail typed
`Unavailable` instead of silently selecting a wrong credential. Applications
can supply those facts through B1's pure API and use explicit literal paths.
No additional ledger row closes: FU-CFG-09 was already marked fixed by Step A;
B2 completes its separately noted dynamic-module refusal. GAP-4 remains open.

## C1: first 22 libdefaults relations

The typed public `LibDefaults` fields expose all 22 values from `allow_des3`
through `ignore_acceptor_hostname`. `hostname::Canonicalization` preserves
`Never`, `Always`, and `Fallback`; boolean serde representations remain
compatible, with the additional string `"fallback"`. Existing boolean builders
remain available. New fields are `default_rcache_name`, `dns_uri_lookup`,
`enforce_ok_as_delegate`, and `err_fmt`.

`src/config/libdefaults/relations.rs::RELATIONS` is the machine-readable source
for step F. Its 22 literal rows contain six columns: relation, value kind, MIT
default, consumer symbol or `plan 2 WP-xx`, fail-closed rationale, and named test
in `tests/config/relations_c1.rs`. Every relation is a **scalar lookup**; list
tokens are inside that first value. Step F still owns generating and checking
`docs/config-relations.md`; C1 does not claim all 43 relations are complete.

The production classifier reads the same table after complete decoding and
enctype resolution. `Config::diagnostics()` exposes its `NotYetEffective`
diagnostics alongside existing enctype diagnostics. Strict mode rejects every
selected deferred C1 relation. Compatible mode rejects explicit replay-store
names other than `none:` (persistent/cross-process protection is unavailable,
WP-20), and nonempty `extra_addresses` with `noaddresses=false` (address-bound
requests unavailable, WP-04). `none:` does **not** disable current memory replay
protection. With `noaddresses=true`, addresses are typed but only diagnosed.
Absent deferred relations do not generate a diagnostic or activate a feature.

No DNS canonicalization, TXT/URI discovery, GSS credential forwarding, acceptor
name relaxation, error formatting, or cache-format selection is added. Those
requests produce diagnostics: current behavior does not perform the requested
relaxation. GSS context builders already reject credential delegation. AS
canonicalization remains suppressed to preserve authenticated identity; TGS
options still consume the flag. The table records that partial effectiveness
as WP-04, not as completed AS canonicalization.

Existing consumers now apply `forwardable` to AS and TGS request bits; false
clears a conflicting raw KDC-options bit. `Config::realm_for_host` selects a
domain mapping before `default_realm`, and the high-level service-realm lookup
uses it before its existing client-realm fallback. Explicit service realms
retain precedence. Clockskew continues into reply-validation and acceptor
options; enctype expressions and default-name loaders retain WP-02/B2 consumers.

### MIT references and deliberate grammar differences

- [1.22 krb5.conf relation defaults](https://web.mit.edu/kerberos/krb5-1.22/doc/admin/conf_files/krb5_conf.html#libdefaults).
  Build-time `DEFCCNAME`, `DEFCKTNAME`, `DEFKTNAME` are not universal paths.
  This crate retains its B2 defaults. DNS KDC lookup defaults false here rather
  than MIT's true in DNS-enabled builds; URI discovery defaults false here
  because it is unavailable. Replay-name storage is unset here, not a claim
  that MIT's `dfl:` backend exists.
- [prof_get.c](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/util/profile/prof_get.c):
  booleans include `on`, `off`, `nil`; historical `f` remains a gokrb5 extension.
  `ccache_type` is signed decimal i32, not a four-value parsing enum.
- [x-deltat.y:143–171](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/lib/krb5/krb/x-deltat.y#L143-L171):
  C1 clockskew accepts seconds, ordered `d/h/m/s` terms, `h:m[:s]`, and
  `d-h:m:s`. Signed components are accepted when their checked i32 total is
  nonnegative. Colon fields after the first have at most two digits; duplicate
  or reordered units, concatenated whitespace-separated digits, overflow and
  trailing garbage are errors. Negative tolerances fail closed. MIT's context
  initializer actually reads clockskew as integer seconds: time syntax here is
  the requested extension. Unlike MIT's lexer, unknown trailing characters
  are not treated as end-of-input. Other duration relations retain their
  previous parser pending C2; this is not a global duration-parser rewrite.
- [localaddr.c](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/lib/krb5/os/localaddr.c):
  address lists accept commas and ASCII whitespace. This crate deliberately
  rejects malformed address tokens instead of silently narrowing the list.

Parse diagnostics remain excluded from serde, as before. The existing serde
round-trip regression now compares all serialized fields and explicitly pins
that diagnostic exclusion. The malformed-address regression retains the same
bad input but changes partial acceptance to `InvalidAddress`; a valid uppercase
fixture preserves the original case-folding and address-order assertions.

## C2: complete 43-relation libdefaults catalogue

`RELATIONS` now has **43 rows**, with the same six columns and the same
production classifier. `relations_match_todo_15_item_2` compares its ordered
names and count with an independent literal checklist copied from todo 15
item 2. `tests/config/relations_c2.rs` provides one named table-driven test
per additional relation. This completes the libdefaults catalogue, not the
remaining realm/section/provider work or step F's generated documentation.

MIT defaults and relation types are sourced from the pinned
[1.22.2 krb5.conf documentation, lines 274–420](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/doc/admin/conf_files/krb5_conf.rst#L274-L420).
The table records each default explicitly. `k5login_authoritative` now defaults
true, matching MIT. No local-login authorization exists yet, so neither value
grants login; k5login directory/authority remain diagnostic (WP-17).

New typed public fields preserve KCM service/socket names, the inert plugin
directory template, optional shortname suffix, total request duration, SPAKE
group names, and channel-binding-aware signaling. Empty shortname suffix is
distinct from unset. SPAKE words are case-insensitive and canonicalized to
`edwards25519`, `P-256`, `P-384`, `P-521`; empty lists remain empty. Unknown
names fail instead of MIT's trace-and-skip behavior. No SPAKE operation,
KCM connection, DNS qualification, or executable plugin loading occurs.

The remaining fail-closed rules apply in both modes:

- `noaddresses=false` (including `no_addresses`) requires unavailable
  address-bound requests and is rejected, even without extra addresses.
- Any nonzero `request_timeout` requires a total deadline across discovery,
  retries and password delivery; existing per-attempt timeouts do not satisfy
  it. It is rejected rather than wrapped in a cancellation-unsafe timeout.
- `verify_ap_req_nofail=true` requires unavailable initial-credential proof
  orchestration and is rejected (WP-11).
- `client_aware_channel_bindings=true` requires unavailable GSS signaling and
  is rejected (WP-12).

Zero/false values above are diagnostic; all explicitly selected deferred C2
relations are errors in Strict mode. `rdns`, realm-domain probing, clock
correction, shortname qualification, KCM and plugin settings cannot activate
their missing behaviors. SPAKE group and preauth preference lists are not
requirements to use a mechanism. `preferred_preauth_types` remains diagnostic
for ordering; existing todo-14 removal of draft-9 IDs 14/15 and their individual
diagnostics is preserved. `permitted_enctypes` remains an effective WP-02
cryptographic policy, not a deferred relation.

`proxiable` now reaches both AS/TGS option consumers and the encoded AS request;
false clears a conflicting raw option bit, as for C1 forwardable. Existing
ticket/renewable lifetime consumers now receive the bounded MIT interval
parser used by C1 clockskew. Negative totals, overflow, malformed unit order,
and trailing garbage fail closed; zero renewable lifetime remains disabled.

[MIT init_ctx.c:265–270](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/lib/krb5/krb/init_ctx.c#L265-L270)
uses the decimal signed-integer profile getter for `kdc_default_options` and
`kdc_timesync`. Bare option numbers now mean decimal; explicit `0x`/`0X`
bitmasks remain a documented extension. Signed values preserve their 32-bit
bit pattern. `kdc_timesync` accepts signed integers like the implementation
(nonzero means enabled), despite the documentation recommending 0 or 1.
Profile scalar first-wins remains unchanged, rather than claiming the old
documentation's XOR wording describes the current getter.

[sendto_kdc.c:474–494](https://github.com/krb5/krb5/blob/krb5-1.22.2-final/src/lib/krb5/os/sendto_kdc.c#L474-L494)
defines effective Auto transport UDP preference: negative uses default 1465,
large values cap at 32700, and request size equal to the limit uses UDP first.
Explicit TCP/UDP still bypass Auto selection. Table-driven lib tests exercise
this actual consumer, including limit 1 and cap boundaries.

Three old fixture tests used `noaddresses=false`: each now asserts its typed
WP-04 error on the same original input, then checks its existing loading,
realm, and serialization behavior with an explicitly addressless copy. This
is a deliberate policy change, not silently weakening those fixtures. The
register remains unchanged at this substep.
