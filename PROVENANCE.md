# Provenance

This file records where `rskrb5-ng` comes from, what was published under
earlier names, which upstream contributions were filed along the way, and how
the upstream work is attributed. The facts below were checked against git,
the crates.io API and the GitHub API on 2026-10-27.

## Origin

`rskrb5-ng` starts from [`clelange/rskrb5`](https://github.com/clelange/rskrb5)
`main` at commit `6f4abc9` (2026-07-08), a pure-Rust Kerberos 5 port of
[`gokrb5`](https://github.com/jcmturner/gokrb5) v8 by Clemens Lange. Upstream
is licensed Apache-2.0, and so is this crate. Upstream published `rskrb5`
0.1.0 and 0.2.0 on crates.io; the tags `v0.1.0` (`203f78a`) and `v0.2.0`
(`a17d210`) in this repository are upstream's.

Everything after `6f4abc9` on `main` is this repository's work. It is
developed independently: upstream changes aren't tracked or merged, and the
repository `andrico21/rskrb5-ng` is a standalone repository, no longer in the
fork network of `clelange/rskrb5`.

## Names and releases

| Version | Crate | Commit | Published | Notes |
|---|---|---|---|---|
| 0.2.1 | `rskrb5-patched` | `f441b11` (tag `v0.2.1`) | 2026-10-06 | upstream plus the patches listed under 0.2.1 in `CHANGELOG.md` (PRs #15 to #18, issues #10 to #14) |
| 0.2.2 | `rskrb5-patched` | `58b27bb` (tag `v0.2.2`) | 2026-10-23 | adds the replay, authenticator-realm and TCP transport fixes |
| 0.3.0 | `rskrb5-ng` | not tagged | not published | this crate |

The `rskrb5-patched` crate was a stopgap: it carried fixes that were waiting
for upstream review, under a different package name so consumers could depend
on a registry version. It kept the library name `rskrb5`.

A 0.3.0 of `rskrb5-patched` was prepared on the branch `release/0.3.0` but
never published. That branch was merged into `main` and is kept as the tag
`archive/release/0.3.0`. Its content then became `rskrb5-ng` 0.3.0: the
package was renamed to `rskrb5-ng` and the library to `rskrb5_ng`, the GitHub
repository `andrico21/rskrb5` was renamed to `andrico21/rskrb5-ng` (GitHub
redirects the old URL) and detached from the fork network, and the code went
through the full lint profile, the API pass, the review backlog and the fuzz
work listed in [`CHANGELOG.md`](CHANGELOG.md). Code moving from
`rskrb5-patched` follows
[`docs/migration-from-rskrb5-patched.md`](docs/migration-from-rskrb5-patched.md).

The branch ledger [`docs/maintenance/branches.md`](https://github.com/andrico21/rskrb5-ng/blob/main/docs/maintenance/branches.md)
lists every ref, the `archive/*` tags of the deleted release branches and the
frozen pull-request head branches.

## Upstream contributions (historical)

These pull requests and issues were filed against `clelange/rskrb5` while
`rskrb5-patched` existed. They are a historical record: this project doesn't
maintain them, and their head branches stay frozen in this repository. The
state column is what `gh pr view`/`gh issue list -R clelange/rskrb5` reported
on 2026-10-27.

| Upstream | Head branch here | Subject | State |
|---|---|---|---|
| [PR #15](https://github.com/clelange/rskrb5/pull/15) | `rust-1-98-clippy-drift` | clippy lints reported by Rust 1.98 | open |
| [PR #16](https://github.com/clelange/rskrb5/pull/16) | `hex-dev-dependency` | `hex` as a dev-dependency (issue #12) | open |
| [PR #17](https://github.com/clelange/rskrb5/pull/17) | `export-padata-constants` | export `PA_FX_COOKIE`, `PA_AS_FRESHNESS`, `random_nonce` (issue #14) | open |
| [PR #18](https://github.com/clelange/rskrb5/pull/18) | `kpasswd-verbatim-result-bytes` | kpasswd result bytes kept as received (issue #2) | open |
| [PR #20](https://github.com/clelange/rskrb5/pull/20) | `fix/service-replay-name-type` | AP-REQ replay identity over the advisory name-type | open |
| [PR #21](https://github.com/clelange/rskrb5/pull/21) | `fix/service-authenticator-realm` | authenticator client realm bound to the ticket realm | open |
| [PR #22](https://github.com/clelange/rskrb5/pull/22) | `fix/ccache-count-bounds` | ccache record counts bounded by the input | open |
| [PR #23](https://github.com/clelange/rskrb5/pull/23) | `fix/kadmin-unsigned-success` | kpasswd success needs authenticated provenance | open |
| [PR #24](https://github.com/clelange/rskrb5/pull/24) | `fix/config-clockskew-handoff` | `[libdefaults] clockskew` on the config-driven acceptors | open |
| [PR #25](https://github.com/clelange/rskrb5/pull/25) | `fix/host-case-spn` | host-based SPNs fold the host to lower case | open |
| [PR #26](https://github.com/clelange/rskrb5/pull/26) | `fix/domain-realm-normalization` | `[domain_realm]` case folding and bare tags | open |
| [PR #27](https://github.com/clelange/rskrb5/pull/27) | `fix/enctype-policy` | reply enctypes bound to the request; `permitted_enctypes` enforced | open |
| [PR #28](https://github.com/clelange/rskrb5/pull/28) | `fix/client-renewal-series` | TGT refresh band, renewal pacing and AS recovery | open |
| [PR #29](https://github.com/clelange/rskrb5/pull/29) | `fix/mutual-auth-classification` | requested mutual authentication fails closed | open |
| [Gittingc0dez/rskrb5#1](https://github.com/Gittingc0dez/rskrb5/pull/1) | `fix/tcp-preauth-pinning` | `Auto`-fallback pinning, stacked on third-party PR [#19](https://github.com/clelange/rskrb5/pull/19) | open |

Issues filed: [#1](https://github.com/clelange/rskrb5/issues/1) to
[#14](https://github.com/clelange/rskrb5/issues/14), all open on 2026-10-27.
Their resolution in this crate is indexed in
[`docs/review/README.md`](https://github.com/andrico21/rskrb5-ng/blob/main/docs/review/README.md) (keys `upstream issue #N`).

The TCP transport change of 0.2.2 imported the two commits of the third-party
upstream PR #19, opened by Gittingc0dez, with their authorship preserved
(`c0b79fe` and `c339e07`, author MynameizEchelon).

## Attribution and licensing

`rskrb5-ng` is a derivative work of `rskrb5` under the Apache License 2.0.
Following its section 4:

- [`LICENSE`](LICENSE) is the Apache License 2.0 text, as upstream ships it
  (section 4(a)).
- Files changed here carry no per-file notices; the modifications are the
  commits on `main` after `6f4abc9`, summarized in
  [`CHANGELOG.md`](CHANGELOG.md) and in this file (section 4(b)).
- Upstream's copyright and attribution notices are kept (section 4(c)).
- [`NOTICE`](NOTICE) keeps upstream's text unchanged and adds one line for
  the rskrb5-ng modifications (section 4(d)).

`rskrb5` credits gokrb5 (Copyright its contributors, Apache-2.0) in its
`NOTICE`; that credit is kept as written.
