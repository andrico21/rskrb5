# Profile composition and name expansion (todo 15, Steps A/B1)

This step changes profile composition, not the set of effective Kerberos
features. B1 adds explicit-context credential-name parameter expansion.
Reader adapters, dynamic-provider rejection, additional typed relations and
diagnostics remain subsequent steps.

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
Existing name loaders retain their Linux procfs UID/eUID behavior unchanged;
B1 does not widen their ambient-discovery contract or wire plan-2 consumers.
There are no new ambient readers, so the exact-owner guard inventory is unchanged.

`tests/config/expansion.rs` covers each token, platform identity policy,
missing facts, exact-name errors, malformed tokens, literal percent signs,
nonrecursive Unicode replacements and resolution of all three profile names.
B1 alone does not close GAP-4/WP-01 or any additional follow-up register row.
