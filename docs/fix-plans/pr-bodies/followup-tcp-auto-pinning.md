# Stacked suggestion for clelange/rskrb5#19: pin the Auto fallback TCP stream for the preauth retry

- Base: this fork's `main` (which is PR #19's head branch). Merge here to fold the change
  into #19, or close it and we will file the same commit against `clelange/rskrb5` after
  #19 lands.
- Branch: `fix/tcp-preauth-pinning` (`andrico21/rskrb5`), commit `b1153c7`, stacked on the
  two commits imported from PR #19's branch (`b31b5d1`, `9403abe`).
- Not a duplicate: PR #19 covers the Tcp path, single-segment framing, `nodelay` and the
  pinned `Tcp` stream; this adds the missing `KdcProtocol::Auto` arm.

## Summary

`send_pinned` sends `KdcProtocol::Udp | KdcProtocol::Auto` through the unpinned path.
For an Auto login whose UDP leg fails (no UDP answer, or `KRB_ERR_RESPONSE_TOO_BIG`),
the first AS request correctly falls back to TCP — but the preauth retry then re-probes
UDP, fails again, and opens a **second** TCP connection, which is the exact cost PR #19
removes for `KdcProtocol::Tcp` (their capture: second handshake 200.18 ms vs 83.95 ms).

## Change

- `src/client/transport.rs`: `send_pinned`'s Auto arm mirrors `send`'s fallback logic and
  carries the stream whenever the TCP leg answers; `Udp` remains streamless.

## Test

- `tests/client_transport.rs::auto_login_reuses_the_stream_after_the_udp_fall_back_to_tcp`
  — TCP stub that answers the bare AS-REQ with `KDC_ERR_PREAUTH_REQUIRED`, reads the retry
  on the same connection, and asserts no second accept within 250 ms. Fails before the
  change (second connection), passes after.

## Verification

- `cargo fmt --all -- --check` clean; `cargo clippy --all-targets --all-features -- -D
  warnings` clean on the branch; `cargo test --all-features --test client_transport`
  19/19.

## Compatibility

- Wire-compatible; only Auto-path connection reuse changes. No public API change.
