# Changelog

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
