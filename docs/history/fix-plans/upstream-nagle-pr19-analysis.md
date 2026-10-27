# Upstream analysis: Gittingc0dez/rskrb5 Oct-5 commits vs the fork's TCP fix

- Subject: `Gittingc0dez/rskrb5@9403abe` (`main`) = `6f4abc9` (upstream `clelange/rskrb5`
  `main`, the fork base) + `b31b5d1` "Refactor TCP stream to fix Nagles stall." +
  `9403abe` "Add tests for Nagles stall fix".
- Upstream PR: `clelange/rskrb5#19` (open, 2026-10-06, author @Gittingc0dez).
- Fork before this analysis: `release/0.2.1` carried only the socket-option half
  (`7f90339` "Set TCP_NODELAY on the KDC TCP connect"; measured 40.95 ms vs 20.64 ms
  at 10 ms emulated one-way latency; unit test asserts `nodelay`).

## What their pair does

Three mechanisms, one goal (AS-login latency against a Windows DC: 768.6 ms → 313.2 ms,
−59.3 %; two connections → one):

1. **Single-segment framing.** `exchange_tcp` assembles the 4-byte RFC 4120 record mark
   and the body into one pre-sized buffer and issues a single `write_all`, so the body
   can never wait on the peer's delayed-ACK timer for the record mark.
2. **`set_nodelay(true)`** on the KDC connect, as a guard against reintroducing the
   split write.
3. **Stream pinning.** `send_tcp_pinned` / `send_pinned` / `send_follow_up` keep the TCP
   stream that answered the first AS phase and send the preauth retry on it (RFC 4120
   section 7.2.2 permits reuse; a KDC close falls back to a fresh connection on an
   `Io` error). Their capture: second handshake 200.18 ms vs 83.95 ms on a pinned RTT.
4. Three deterministic stub-KDC tests plus a gated live probe (`TEST_KDC_REUSE=1`).

## Same or better — decision

- Mechanism 1 is the root-cause fix and is worth adopting even where 2 already masks
  the symptom: coalescing keeps Nagle enabled and removes the stall structurally.
- Mechanism 3 is the larger win against a Windows DC and is orthogonal to framing.
- Mechanism 2 is kept (also part of their change and of the fork).
- **Gap found in PR #19 (the fork's "different, better" delta):** `send_pinned` maps
  `KdcProtocol::Auto` to the unpinned path. An Auto login that falls back to TCP (no
  UDP answer, or `KRB_ERR_RESPONSE_TOO_BIG`) therefore pins nothing, so the preauth
  retry re-probes UDP, fails again and opens a second TCP connection — exactly the cost
  defect 2 removes for `Tcp`. Fixed in the fork: `send_pinned`'s Auto arm now carries
  the TCP-fallback stream (commit `b1153c7`), with
  `auto_login_reuses_the_stream_after_the_udp_fall_back_to_tcp` (fails before, passes
  after).

## What the fork did (branch `release/0.2.2`)

- Reverted the nodelay-only commit, imported both upstream commits with authorship
  preserved (`c0b79fe`, `c339e07`), added the Auto extension (`88b1c91`), stacked the
  two service-validation fixes (`1f85793`, `d23b26d`).
- Verified on the branch: `cargo fmt --all -- --check` clean, `cargo clippy
  --all-targets --all-features -- -D warnings` clean, `cargo test --all-features
  --no-fail-fast` green (service 23/23, client_transport 19/19).
- Fork release: version bumped to `0.2.2` on `release/0.2.2`; pushing the
  `v0.2.2` tag at that tip publishes through the release workflow.

## Upstream routing

- No duplicate PR for the core fix: PR #19 is open and covers mechanisms 1-3. When it
  merges, drop the imported commits at rebase and keep only the Auto extension.
- The Auto extension is open as a stacked PR into PR #19's head branch:
  <https://github.com/Gittingc0dez/rskrb5/pull/1>. If it is folded in, nothing else is
  needed; if it is declined, file the same commit against `clelange/rskrb5` after #19
  lands (body: `pr-bodies/followup-tcp-auto-pinning.md`).
- The draft comment below remains the alternative if a PR into the contributor's fork is
  not wanted.

## Draft comment for clelange/rskrb5#19

> Reviewed the framing and pinning changes; the three stub-KDC tests pass against
> this tree (`cargo test --all-features --test client_transport`, 18/18), and the
> single-segment write plus `nodelay` match what the capture shows.
>
> One gap: `send_pinned` maps `KdcProtocol::Auto` to the unpinned `send()`, so an
> Auto login that falls back to TCP (no UDP answer, or `KRB_ERR_RESPONSE_TOO_BIG`)
> pins nothing — the preauth retry re-probes UDP, fails again, and opens a second
> TCP connection, which is the exact cost defect 2 removes for `KdcProtocol::Tcp`.
>
> The fix mirrors `send`'s Auto arm and returns the stream whenever the TCP leg
> answers:
>
> ```rust
> KdcProtocol::Auto => match self.send_udp(addr.clone(), request).await {
>     Ok(response) if kdc_error_code(&response) == Some(KRB_ERR_RESPONSE_TOO_BIG) => self
>         .send_tcp_pinned(addr, request)
>         .await
>         .map(|(response, stream)| (response, Some(stream))),
>     Ok(response) => Ok((response, None)),
>     Err(_) => self
>         .send_tcp_pinned(addr, request)
>         .await
>         .map(|(response, stream)| (response, Some(stream))),
> },
> ```
>
> Test: `auto_login_reuses_the_stream_after_the_udp_fall_back_to_tcp` (TCP stub,
> no UDP answer; asserts the retry rides the first connection). Reference
> implementation: `andrico21/rskrb5` branch `fix/tcp-preauth-pinning`, commit
> `b1153c7`. Happy to fold this in here or file it as a follow-up — your call.
