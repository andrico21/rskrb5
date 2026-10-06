# Ccache: bound record counts against remaining input before reserving

- Severity: medium (likelihood medium / impact medium / confidence high) — fingerprint `rskrb5/ccache/parse/count-before-input-bound`
- Audit: run-2 findings.json record (`verdict: confirmed`) + `agents/vfy-rskrb5-ccache-parse-count-/artifacts/ccache-parse-count-verify5:50-73`
- Status: planned; not implemented in the fork; no upstream PR yet

## Problem

`CCache::parse` sizes three `Vec::with_capacity` reservations directly from
counts embedded in the credential-cache bytes, and `read_count` never relates a
count to the bytes that remain. A 16-byte input therefore asks the allocator for
51,539,607,528 bytes (component count × 24) and 71-/75-byte inputs ask for
68,719,476,704 bytes (address / authorization-data count × 32); when the
allocator refuses, the reservation becomes an unrecoverable SIGABRT instead of a
typed parse error. A malformed cache that every other path reports as an
ordinary truncation terminates the caller's process, with a ~3-billion-fold
input-to-cost amplification on 16–75 bytes.

## Root cause (verified against upstream 6f4abc9)

- `src/ccache.rs:1049` — `fn read_count(bytes: &[u8], offset: &mut usize, endian: Endian) -> Result<usize, Error>` — rejects only negative `i32` and returns up to `i32::MAX` as `usize`; it takes no minimum-element size and never compares the count with `bytes.len() - *offset`.
- `src/ccache.rs:582` — `let mut component_count = read_i32(bytes, offset, endian)?;` — the principal component count bypasses `read_count` entirely (raw `read_i32`; only a negative check at `:589`) and is consumed by `src/ccache.rs:593` — `let mut components = Vec::with_capacity(component_count as usize);`. The realm string is read before it (`:592`), so a 16-byte input reaches the reservation.
- `src/ccache.rs:709-710` — `let address_count = read_count(bytes, offset, endian)?;` then `let mut addresses = Vec::with_capacity(address_count);`.
- `src/ccache.rs:715-716` — `let auth_data_count = read_count(...)?;` then `let mut auth_data = Vec::with_capacity(auth_data_count);`.
- `src/ccache.rs:1057` — `fn read_data(...)` calls `read_count` but then bounds the copy with `read_bytes`/`checked_end` (`:995-997`): the module already implements the discipline the three reservations lack.
- `src/keytab.rs:451,462` — the sibling parser reads the identical component count with `read_i16` (max 32 767) before `Vec::with_capacity`; the ccache copy widened the field to `i32` without adding a bound.
- Minimum per-element encodings are 4 bytes (component string) and 6 bytes (`HostAddress` / `AuthorizationDataEntry`), so any count above `remaining/4` or `remaining/6` is impossible yet still reserved.

Base and fork `src/ccache.rs` are byte-identical, so all line numbers above hold
in both trees.

## Evidence (from the audit)

- `agents/vfy-rskrb5-ccache-parse-count-/artifacts/ccache-parse-count-verify5:57-61` — 16-byte `components` input: `memory allocation of 51539607528 bytes failed`, exit 134.
- `.../ccache-parse-count-verify5:63-67` — 71-byte `addresses` input: `memory allocation of 68719476704 bytes failed`, exit 134.
- `.../ccache-parse-count-verify5:69-73` — 75-byte `authdata` input: same 68,719,476,704-byte request, exit 134.
- `.../ccache-parse-count-verify5:50` — control `data_bound` (component length `i32::MAX` on 20 bytes): `err credential cache data is truncated at offset 20; need 2147483647 bytes, have 0`, exit 0, no large allocation.
- `.../ccache-parse-count-verify5` — control `negcount` (count `-1`) returns `Error::NegativeLength`; a valid `CCache::new(..).to_bytes()` control parses `ok`.
- Payloads: `components` = `05 04 00 00 00 00 00 00 7f ff ff ff 00 00 00 00`; `addresses`/`authdata` are the 71-/75-byte prefixes ending in a `7f ff ff ff` count. Runner sandbox enforced `RLIMIT_AS = 3 GiB` per process.

## Proposed fix

1. Give `read_count` a `min_item_len` parameter and validate the claimed count
   against the remaining input with the existing `Error::Truncated` /
   `Error::NegativeLength` / `Error::LengthOverflow` variants; reserve only
   after the count is proven feasible.
2. Route the `Principal::parse` component count (`src/ccache.rs:582`) through the
   same helper (min 4 bytes, adjusted for the v1 `-1` case) so it no longer uses
   a raw `read_i32`.
3. Update the two `Credential::parse` sites to pass the 6-byte minimum.
4. Keep `Vec::with_capacity` (optionally `try_reserve`) only after the bound
   check; the three call sites of `read_count` in the crate are
   `src/ccache.rs:709`, `:715`, and the `read_data` length at `:1058`.

```rust
/// Read a non-negative i32 element count and require the input to still be able to
/// contain that many elements of at least `min_item_len` bytes each.
fn read_count(
    bytes: &[u8],
    offset: &mut usize,
    endian: Endian,
    min_item_len: usize,
) -> Result<usize, Error> {
    let count = read_i32(bytes, offset, endian)?;
    if count < 0 {
        return Err(Error::NegativeLength(count));
    }
    let count: usize = count.try_into().map_err(|_| Error::LengthOverflow)?;
    let remaining = bytes.len().saturating_sub(*offset);
    let needed = count.checked_mul(min_item_len).ok_or(Error::LengthOverflow)?;
    if needed > remaining {
        return Err(Error::Truncated { offset: *offset, needed, remaining });
    }
    Ok(count)
}
```

```rust
// Principal::parse: bound the component count before reserving capacity.
let mut component_count = read_count(bytes, offset, endian, 4)?;
if version == 1 {
    component_count = component_count.checked_sub(1).ok_or(Error::LengthOverflow)?;
}
let realm = read_counted_string(bytes, offset, endian)?;
let mut components = Vec::with_capacity(component_count);
```

```rust
// Credential::parse: each address/auth-data entry needs at least 6 bytes.
let address_count = read_count(bytes, offset, endian, 6)?;
let mut addresses = Vec::with_capacity(address_count);
// ...
let auth_data_count = read_count(bytes, offset, endian, 6)?;
let mut auth_data = Vec::with_capacity(auth_data_count);
```

Update the one existing `read_count` caller shape in `read_data` (`:1058`) to
pass `min_item_len = 1`, preserving its current byte-bound behaviour.

## Regression tests

- `tests/ccache.rs::rejects_impossible_component_count` — 16-byte payload with component count `i32::MAX` returns `Error::Truncated` (never aborts).
- `tests/ccache.rs::rejects_impossible_address_count` — 71-byte payload with address count `i32::MAX` returns `Error::Truncated`.
- `tests/ccache.rs::rejects_impossible_auth_data_count` — 75-byte payload with auth-data count `i32::MAX` returns `Error::Truncated`.
- Extend `tests/ccache.rs::rejects_invalid_ccache_inputs` (`tests/ccache.rs:491`) with the negative-count and oversized-length controls so the typed-error behaviour stays asserted next to the new cases.
- Fixtures: reuse the file's `decode_hex` helper and build the payloads from the v4 big-endian layout documented in the finding; no KDC or key material needed.

## Verification

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --test ccache
```

## Compatibility / notes

- Wire-compatible: no serialization changes. Only inputs that previously
  aborted (or held a multi-GiB reservation under permissive overcommit) now
  return the typed truncation error they would have returned had the length
  field been bounded like every other field.
- Fork `tests/ccache.rs` differs from upstream only in the `chunks_exact` →
  `as_chunks` clippy fix (`tests/ccache.rs:514`); no test in it exercises the
  count reservations, so the new cases are additive.
- Neither in-flight HIGH fix touches `src/ccache.rs` (both are in
  `src/service.rs`), so this change is independent of them.

## Upstream route

- Fork-only commit first; a PR against `clelange/rskrb5` (`6f4abc9` target) carries the same patch. No dependencies on other fix plans.

## Risks / open questions

- The fatal effect depends on the allocator refusing the reservation (`RLIMIT_AS`, non-overcommit, or RAM+swap below the request); with permissive overcommit the pre-fix code holds 48–64 GiB of address space instead. The bound check removes both outcomes, so the risk is not a blocker for the fix.
- `min_item_len` is a conservative lower bound, not an exact encoding length: values just below the bound still fail later through the existing `read_bytes`/`read_counted_string` truncation checks. Confirm the chosen minimums (4 and 6) against `HostAddress`/`AuthorizationDataEntry` parsing in `src/ccache.rs` during review.
- The v1 principal path subtracts 1 from the count before parsing; the ordering of the bound check versus the `-1` adjustment must keep `Truncated` reachable for `i32::MAX` (asserted by the regression test).