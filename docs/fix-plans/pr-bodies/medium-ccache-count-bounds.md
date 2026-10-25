# ccache: bound record counts against the remaining input before reserving

- Target: `clelange/rskrb5` `main` (`6f4abc9`), branch `fix/ccache-count-bounds`.
- Commits:
  - `9701864` ccache: bound record counts against the remaining input before reserving
  - `a37a4d1` ccache: drop the redundant component-count cast
  - `fdf641a` ccache: pin the up-front count bound in the impossible-count tests

## Problem

`CCache::parse` sized three `Vec::with_capacity` reservations straight from counts stored in the credential-cache bytes: each principal's component count, and each credential's address and authorization-data counts. `read_count` only rejected negative values and never compared a count with the bytes that remain. The principal component count didn't go through `read_count` at all; it was a raw `read_i32` with a negative check.

So a 16-byte input asked the allocator for 51,539,607,528 bytes (component count `i32::MAX` times 24), and 71- and 75-byte inputs asked for 68,719,476,704 bytes (address or auth-data count times 32). When the allocator refuses a reservation, Rust aborts the process instead of returning an error. A malformed cache that every other path reports as an ordinary truncation therefore killed the caller. Under permissive overcommit the same input held tens of GiB of address space instead.

There's no RFC rule at stake here. The MIT ccache format encodes these counts as 32-bit integers, and the parser has to treat them as untrusted input. `read_data` already bounds its byte copies against the remaining input. The three reservations didn't.

## Change

- `read_count` takes a `min_item_len` and rejects any count whose minimum encoding can't fit in the remaining input. It uses the existing `Error::Truncated { offset, needed, remaining }`, plus `Error::LengthOverflow` when `count * min_item_len` overflows `usize`.
- The principal component count goes through the same helper with a 4-byte minimum per component. The v1 `-1` adjustment happens after the bound check.
- The credential address and auth-data counts use a 6-byte minimum (`HostAddress` and `AuthorizationDataEntry` are at least 6 bytes each).
- `read_data` keeps its byte-length behaviour with `min_item_len = 1`.
- `Vec::with_capacity` runs only after the count is proven feasible.
- `a37a4d1` drops a cast that became a no-op (`clippy::unnecessary_cast`). No behaviour change.

## Tests

In `tests/ccache.rs`:

- `rejects_impossible_component_count` (16-byte payload, component count `i32::MAX`), `rejects_impossible_address_count` (71 bytes, address count `i32::MAX`) and `rejects_impossible_auth_data_count` (75 bytes, auth-data count `i32::MAX`). Each asserts the exact up-front bound:
  - 64-bit: `Truncated { offset: 12, needed: 8_589_934_588, remaining: 4 }`, `Truncated { offset: 71, needed: 12_884_901_882, remaining: 0 }` and `Truncated { offset: 75, needed: 12_884_901_882, remaining: 0 }`;
  - 32-bit: `LengthOverflow`.
- `rejects_invalid_ccache_inputs` gains two negative-count controls (component count `-1` and address count `-1`, both `Error::NegativeLength(-1)`).

Fail-before evidence, on a host with `vm.overcommit_memory = 1`:

- With `src/ccache.rs` restored to `6f4abc9`, all three `rejects_impossible_*` tests fail. Each assertion on the exact `Truncated { offset, needed, remaining }` value fails, so the tests prove the up-front bound even where the allocator wouldn't abort. With the fix restored, the same 3 tests pass.
- The negative-count controls pass before and after the fix by design. With the `count < 0` guard removed from `read_count`, `rejects_invalid_ccache_inputs` fails: the component count `-1` no longer yields `NegativeLength(-1)`.

## Verification

All runs used stable Rust 1.99.1 on the branch tip.

- `cargo test --all-features --test ccache`: 23 passed.
- `cargo test --all-features --no-fail-fast`: 33 test targets ok, 0 failed.
- `cargo fmt --all -- --check`: clean.
- `cargo clippy --all-targets --all-features -- -D warnings -A clippy::chunks_exact_to_as_chunks`: the only diagnostics are the 3 `clippy::byte_char_slices` errors in `tests/kadmin.rs` that already fail on `main`. CI on `main` stays red on `clippy::chunks_exact_to_as_chunks` and `clippy::byte_char_slices` until PR #15 lands. This change adds no diagnostic.

## Compatibility

- No public API change and no serialization change.
- Inputs that used to abort the process (or hold a multi-GiB reservation) now return `Error::Truncated`, or `Error::LengthOverflow` on 32-bit targets. Every valid cache parses as before.

## Series and merge order

- No other open PR touches `src/ccache.rs` or `tests/ccache.rs`. This PR merges in any order.

## Notes

- `min_item_len` is a lower bound, not an exact encoding length. A count just under the bound still fails later through the existing `read_bytes`/`read_counted_string` truncation checks.
- The keytab parser reads the same component count as `i16`, which caps it at 32,767, so it doesn't have this problem.
