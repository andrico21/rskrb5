# Review disposition index

This directory records how every open item of the code review backlog was
resolved for `rskrb5-ng` 0.3.0. Each area document lists its items with a
status (`fixed` or `dismissed`), the tests and commit, the behaviour change
and, for a dismissal, the evidence. A `fixed` item has a regression test that
failed on the pre-fix code. A dismissal carries a probe, a measurement or a
citation that shows why the item does not apply.

## Source documents

The inputs are not committed to this repository:

- `CODE_REVIEW-Astra.md`, the full code review at `f441b11`. Items are keyed
  `RSK-XXXXXXXX`; each has a fingerprint, locations, a fix direction and
  conditions.
- `NEEDS-VALIDATION.md` of the second security-audit run (`run-2`): 18 leads,
  keyed by lead name.
- The upstream issues filed against `clelange/rskrb5` (`upstream issue #N`).
- The Rust guidelines (`andrico21/rust-guidelines`): deviation 8 of the former
  project overlay `overlays/projects/rskrb5.md` at `1606688`, which applies the
  `http-services.md` overlay to the Negotiate layer and the Axum example
  (`overlay deviation 8`), and rule 13, ambient inputs, of the project overlay
  vendored in [`../rust-guidelines/`](../rust-guidelines/) (`project rule (13)`).
- The ambient-input inventory of the plan (`ambient input RSKRB5_DNS_SERVER`).

## Areas

| Document | Todo | Area | Fixed rows | Dismissed rows |
| --- | --- | --- | --- | --- |
| [`spnego-gss.md`](spnego-gss.md) | 29 | SPNEGO, GSS tokens, DER and OIDs | 8 | 0 |
| [`service-http.md`](service-http.md) | 30 | Service acceptor and HTTP layer | 7 | 1 |
| [`crypto.md`](crypto.md) | 31 | Cryptography and key derivation | 7 | 1 |
| [`pac.md`](pac.md) | 32 | PAC and NDR | 10 | 0 |
| [`client.md`](client.md) | 33 | Client AS/TGS exchanges, renewal and caches | 10 | 0 |
| [`kpasswd-messages.md`](kpasswd-messages.md) | 34 | kpasswd, KRB-PRIV/KRB-SAFE messages, secrets and cancellation contracts | 7 | 1 |
| [`transport.md`](transport.md) | 35 | Transport, DNS, IPv6, SRV and kpasswd retry | 11 | 0 |
| [`config-enctype.md`](config-enctype.md) | 36 | Config and enctype policy | 5 | 0 |
| [`files.md`](files.md) | 37 | Ccache, keytab and credential file handling | 7 | 0 |
| [`release-ci.md`](release-ci.md) | 38 | Release authority, CI docs and fixture secrets | 3 | 0 |

## Totals

- 78 rows covering 100 keys. A row can carry several keys, for example a
  review item and the run-2 lead or upstream issue it shares a defect with.
- Rows: 75 fixed, 3 dismissed.
- Keys: 97 fixed, 3 dismissed. The keys are 71 review items, 18 run-2 leads,
  8 upstream issues, overlay deviation 8, project rule (13) and the
  `RSKRB5_DNS_SERVER` ambient input.
- Dismissed: RSK-911A31CB (cipher setup already runs once per operation;
  measured), the run-2 lead `src/http.rs:NegotiateLayer:replay-scope-unbound-http-request`
  (clones share one replay cache; independent layers share one explicitly;
  the limits are documented) and RSK-8BBFC1EE (every wrapper already carries
  its cancellation contract; the gate enforces it).

## Items

| ID | Status | Area | Todo |
| --- | --- | --- | --- |
| RSK-7487E947 | fixed | [`spnego-gss.md`](spnego-gss.md) | 29 |
| RSK-2A2C1928 | fixed | [`spnego-gss.md`](spnego-gss.md) | 29 |
| RSK-622F4664 | fixed | [`spnego-gss.md`](spnego-gss.md) | 29 |
| RSK-2A906A3A | fixed | [`spnego-gss.md`](spnego-gss.md) | 29 |
| RSK-84FA90AE | fixed | [`spnego-gss.md`](spnego-gss.md) | 29 |
| RSK-C4BE57A0 | fixed | [`spnego-gss.md`](spnego-gss.md) | 29 |
| RSK-FAF64A85 / run-2 lead `src/spnego.rs:accept_sec_context_header:mandatory-gss-authenticator-fields` | fixed | [`spnego-gss.md`](spnego-gss.md) | 29 |
| upstream issue #9 | fixed | [`spnego-gss.md`](spnego-gss.md) | 29 |
| overlay deviation 8 (`http-services.md`) | fixed | [`service-http.md`](service-http.md) | 30 |
| run-2 lead `src/http.rs:NegotiateLayer:replay-scope-unbound-http-request` | dismissed | [`service-http.md`](service-http.md) | 30 |
| RSK-B161A328 | fixed | [`service-http.md`](service-http.md) | 30 |
| RSK-985742B6 | fixed | [`service-http.md`](service-http.md) | 30 |
| RSK-7D80FA41 / lead `ReplayCache:indefinite-entry-retention` | fixed | [`service-http.md`](service-http.md) | 30 |
| RSK-D1D6BDC3 / lead `mandatory-authorization-data-discarded` | fixed | [`service-http.md`](service-http.md) | 30 |
| RSK-3E3C2278 / lead `unchecked-cross-realm-transit` | fixed | [`service-http.md`](service-http.md) | 30 |
| RSK-39F18D3B | fixed | [`service-http.md`](service-http.md) | 30 |
| RSK-11BF294C | fixed | [`crypto.md`](crypto.md) | 31 |
| RSK-FA2BF25E | fixed | [`crypto.md`](crypto.md) | 31 |
| RSK-F240C18F / lead `s2kparams_to_iterations:unauthenticated-pbkdf2-work` | fixed | [`crypto.md`](crypto.md) | 31 |
| RSK-B51C2C85 / lead `nfold:lcm-usize-overflow` | fixed | [`crypto.md`](crypto.md) | 31 |
| RSK-CE4ACA12 | fixed | [`crypto.md`](crypto.md) | 31 |
| RSK-8F3B02EE | fixed | [`crypto.md`](crypto.md) | 31 |
| RSK-911A31CB | dismissed | [`crypto.md`](crypto.md) | 31 |
| RSK-DEF6C438 / upstream issue #6 | fixed | [`crypto.md`](crypto.md) | 31 |
| RSK-6DF06BE8 / lead `pac.authorization-data.unbounded-if-relevant-recursion` | fixed | [`pac.md`](pac.md) | 32 |
| RSK-B5912AE2 / lead `pac.claims-decompression.peer-controlled-cap` | fixed | [`pac.md`](pac.md) | 32 |
| RSK-A9B8B032 / lead `pac.ndr.supplemental-credentials-unbounded-capacity` | fixed | [`pac.md`](pac.md) | 32 |
| RSK-DB101DC5 | fixed | [`pac.md`](pac.md) | 32 |
| RSK-8BA3D269 | fixed | [`pac.md`](pac.md) | 32 |
| RSK-59B45280 | fixed | [`pac.md`](pac.md) | 32 |
| RSK-8E17F182 | fixed | [`pac.md`](pac.md) | 32 |
| RSK-5E15962F | fixed | [`pac.md`](pac.md) | 32 |
| RSK-6A286805 | fixed | [`pac.md`](pac.md) | 32 |
| RSK-D33671B2 | fixed | [`pac.md`](pac.md) | 32 |
| RSK-AFE184E0 | fixed | [`client.md`](client.md) | 33 |
| RSK-34601373 | fixed | [`client.md`](client.md) | 33 |
| RSK-072A268D | fixed | [`client.md`](client.md) | 33 |
| RSK-2099CE19 | fixed | [`client.md`](client.md) | 33 |
| RSK-BC016031 | fixed | [`client.md`](client.md) | 33 |
| RSK-F526D18D | fixed | [`client.md`](client.md) | 33 |
| RSK-E48DA39B | fixed | [`client.md`](client.md) | 33 |
| RSK-1922A31B | fixed | [`client.md`](client.md) | 33 |
| RSK-45397760 | fixed | [`client.md`](client.md) | 33 |
| run-2 lead `src/client.rs:s4u-delegation:delegated-client-unbound-to-ticket-payload` | fixed | [`client.md`](client.md) | 33 |
| RSK-A5F7D975 | fixed | [`kpasswd-messages.md`](kpasswd-messages.md) | 34 |
| RSK-3B6BA222 | fixed | [`kpasswd-messages.md`](kpasswd-messages.md) | 34 |
| RSK-789A6FBB | fixed | [`kpasswd-messages.md`](kpasswd-messages.md) | 34 |
| RSK-0C0007B7 | fixed | [`kpasswd-messages.md`](kpasswd-messages.md) | 34 |
| RSK-6A673A85 | fixed | [`kpasswd-messages.md`](kpasswd-messages.md) | 34 |
| RSK-471362A3 / upstream issue #1 | fixed | [`kpasswd-messages.md`](kpasswd-messages.md) | 34 |
| RSK-14E2755A / upstream issue #8 | fixed | [`kpasswd-messages.md`](kpasswd-messages.md) | 34 |
| RSK-8BBFC1EE | dismissed | [`kpasswd-messages.md`](kpasswd-messages.md) | 34 |
| RSK-03EDCC7E | fixed | [`transport.md`](transport.md) | 35 |
| RSK-3F13B5FE | fixed | [`transport.md`](transport.md) | 35 |
| RSK-0D8D7D97 | fixed | [`transport.md`](transport.md) | 35 |
| RSK-484961E9 | fixed | [`transport.md`](transport.md) | 35 |
| ambient input `RSKRB5_DNS_SERVER` | fixed | [`transport.md`](transport.md) | 35 |
| RSK-4AD555A5 | fixed | [`transport.md`](transport.md) | 35 |
| RSK-DF8D47BE | fixed | [`transport.md`](transport.md) | 35 |
| RSK-521F824C | fixed | [`transport.md`](transport.md) | 35 |
| RSK-DBD57F3E | fixed | [`transport.md`](transport.md) | 35 |
| RSK-351DC798 | fixed | [`transport.md`](transport.md) | 35 |
| RSK-4DB854C8 / upstream issue #7 / run-2 lead `send_to_endpoints/post-send-mutation-retry` | fixed | [`transport.md`](transport.md) | 35 |
| RSK-40161D92 / lead `apply_section/realms-replacement-dns-fallback` | fixed | [`config-enctype.md`](config-enctype.md) | 36 |
| RSK-77250646 / upstream issue #4 | fixed | [`config-enctype.md`](config-enctype.md) | 36 |
| RSK-45AC5D3A | fixed | [`config-enctype.md`](config-enctype.md) | 36 |
| RSK-5ECE9681 / lead `DEFAULT_ENCTYPES/deprecated-rc4-default` / upstream issue #3 | fixed | [`config-enctype.md`](config-enctype.md) | 36 |
| upstream issue #10 (remainder) / project rule (13) | fixed | [`config-enctype.md`](config-enctype.md) | 36 |
| RSK-7F30E854 | fixed | [`files.md`](files.md) | 37 |
| RSK-01B7A90E | fixed | [`files.md`](files.md) | 37 |
| RSK-98FEE876 | fixed | [`files.md`](files.md) | 37 |
| RSK-DC80DC52 / lead `file-name/uid-token-environment-substitution` | fixed | [`files.md`](files.md) | 37 |
| RSK-DF3180A2 / lead `credential-file/save/inherited-permissions` | fixed | [`files.md`](files.md) | 37 |
| RSK-58A6D5DD / lead `credential-file/path-write/followed-symlink` | fixed | [`files.md`](files.md) | 37 |
| RSK-361F35CC | fixed | [`files.md`](files.md) | 37 |
| run-2 lead `release.publish.crates-io-token.unprotected-tag-authorization` | fixed (the registry token is a `release` environment secret only since the owner's move on 2026-10-29, follow-up row FU-OPS-01) | [`release-ci.md`](release-ci.md) | 38 |
| RSK-E0AFE152 | fixed | [`release-ci.md`](release-ci.md) | 38 |
| RSK-A8D595D8 | fixed | [`release-ci.md`](release-ci.md) | 38 |

## Closed before the review backlog

These items were closed before this backlog was planned, on the 0.2.x and
0.3.0 fix branches. Each commit is on `main`; for a merged branch the merge
commit is given as well.

| Item | Closed by | Change |
| --- | --- | --- |
| RSK-3D4936DE | `d23b26d` | The accepted client identity is bound to the ticket realm (shipped in 0.2.2). |
| RSK-88753BCE | `1f85793`, follow-up `a1ace38` | The AP-REQ replay identity ignores the advisory name type (0.2.2); the replay cache also indexes the authenticator ciphertext digest. |
| RSK-024DCC11 | `a089831` (merge `f672e0f`) | A kpasswd success without authenticated provenance is rejected. |
| RSK-53F70E88 | `8b75cda`, `71cc63b` (merge `082778d`) | Requested mutual authentication fails closed in the classifier and in the send wrappers. |
| RSK-8EC67CA1 | `236c4ce` (merge `be6e156`) | AS/TGS reply and session enctypes are bound to the requested list. |
| RSK-23EF3999 | `9701864` (merge `8f2f349`) | Ccache record counts are bounded by the remaining input before reserving. |
| RSK-BD020741 | `9ede05a` (merge `deb553e`) | `[domain_realm]` lookups fold the DNS name case. |
| RSK-EAB257B2 | `50e5284` (merge `ac63244`) | Host-based service principals lower-case the DNS host. |
| RSK-28F38FD2 | `9db3c87` (merge `4745962`) | Automatic logins recover through an AS exchange when an expired TGT cannot be renewed. |
| RSK-B073D0EF | `29b6a51` (merge `4745962`) | The refresh band is measured from the current ticket life, not `auth_time`. |
| RSK-EB15E20D | `0a2cf65` (merge `4745962`) | Auto-renewal waits after a refresh that makes no progress. |
| RSK-9F0AA293 | `dd5e57d` | The fuzz crate depends on the renamed package. |
| RSK-79738020 | `dd5e57d`, `79a28d3` | The release workflow publishes with `--locked`. |
| RSK-A9CD2563 | `7c95579`, `7e05965` | `rust-version` is verified by a CI `msrv` job. |
| RSK-E17B794B | `62191fe`, `7e05965` | `cargo deny` and `cargo audit` gate CI. |
| upstream issue #2 | `43d7988` | kpasswd result bytes are kept as received (`text_raw`). |
| upstream issue #5 | `236c4ce` (merge `be6e156`) | Same change as RSK-8EC67CA1. |
| upstream issue #11 | `7a61eb2` | `include`/`includedir` are bounded, with cycle detection through roots and directories. |
| upstream issue #12 | `bdf278c` | `hex` is a dev-dependency, so the integration tests build. |
| upstream issue #13 | `782dcb8` | A TGS authenticator can carry a subkey. |
| upstream issue #14 | `d461654` | `PA_FX_COOKIE`, `PA_AS_FRESHNESS` and `random_nonce` are exported. |

Upstream issue #10 was only partly closed before the backlog: `1450607` added
the environment-free constructors. Its remainder (`LibDefaults::new()` still
read `UID` and `HOME`) is the `upstream issue #10` row of
[`config-enctype.md`](config-enctype.md).
