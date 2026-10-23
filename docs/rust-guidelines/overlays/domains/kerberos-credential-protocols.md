# Overlay: Kerberos and Credential-Bearing Protocol Clients

**Load this overlay for** clients of binary, credential-bearing protocols: Kerberos V5 and
kpasswd, and, where the stated properties hold, LDAP password-modify or SASL/SCRAM. It was
Section 14 of the per-project guides. Its subsections keep their original wording; "Section
N" references below point to the universal core.

**Scope note (from core Section 10, TLS).** The core covers the HTTP surface. TLS is not the
only boundary a service defends. A client that speaks a binary credential-bearing protocol
(Kerberos, LDAP password-modify, SASL/SCRAM) carries a separate set of obligations: outcome
classification, enumeration oracles, frame bounding, algorithm allowlists, and zeroization.
Those are this overlay.

The core (Section 10) and `http-services.md` cover the HTTP surface. This overlay covers the client side
of a binary cryptographic protocol spoken to a configured authority on a user's
behalf. Kerberos V5 ([RFC 4120](https://www.rfc-editor.org/info/rfc4120)) and
the change-password protocol
([RFC 3244](https://www.rfc-editor.org/info/rfc3244)) are the worked example.

Three properties drive every rule below. Apply a rule to another protocol
(LDAP password-modify, SASL/SCRAM) only where its property actually holds:

1. A **presented** secret becomes key material locally, and only derived
   material proves possession of it.
2. Failures are attacker-observable, so the failure taxonomy is part of the
   security surface.
3. Frames are length-prefixed binary from a peer not yet authenticated.

**This is client-side guidance.** A KDC or kpasswd *server* shares the frame
parsing and oracle concerns, but its credential sources, lifecycles, timeouts
and cancellation semantics differ; re-derive those rather than applying the
client rules mechanically.

**Back realm-specific behaviour with tests or captures, not citations.** MIT,
Heimdal and AD do not behave identically, and an RFC citation is not evidence
for any of them.

Snippets below share this vocabulary:

```rust
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const TRANSPORT_IO_TIMEOUT: Duration = Duration::from_secs(5);
const EXCHANGE_DEADLINE: Duration = Duration::from_secs(30);

pub struct KpasswdReply {
    pub code: u16,
    pub result_text: Vec<u8>,
}

#[derive(thiserror::Error)]   // Debug is hand-written below, not derived
#[non_exhaustive]
pub enum ChangeError {
    #[error("authentication failed at the AS exchange")]
    AuthFailed { detail: String },
    #[error("password changed too recently")]
    TooSoon,
    #[error("realm unavailable: {detail}")]
    RealmUnavailable { detail: String },
    #[error("internal error: {detail}")]
    Internal { detail: String },
}

// `thiserror::Error` requires `Debug` via `std::error::Error`. It is written by
// hand rather than derived - see the anti-oracle rule for why.
impl fmt::Debug for ChangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthFailed { .. } => f.write_str("AuthFailed"),
            Self::TooSoon => f.write_str("TooSoon"),
            Self::RealmUnavailable { detail } => write!(f, "RealmUnavailable({detail})"),
            Self::Internal { detail } => write!(f, "Internal({detail})"),
        }
    }
}
```

Every GOOD snippet was compiled and linted under the Section 9 posture, so none
of them contains an `unwrap`, an index, a wildcard classifier arm, a truncating
`as`, or an implicit clone. If one trips a lint in your tree, understand the
divergence before copying it.

Everything else is a placeholder for your stack's equivalent. `KrbError` is
your Kerberos crate's error type; `FrameError` and `ConfigError` your own parse
and config errors; `Config`, `KdcTransport`, `KrbClient` and `ChangeRequest`
your config, transport, client and request types; `is_permitted`,
`classify_kdc_code`, `classify_kpasswd_code`, `classify_soft_error`,
`permitted_names`, `effective_enctype_ids`, `rendered_krb5_conf`,
`exchange_with` and `exchange_before` your policy check, classifiers, policy
list, derived-enctype accessor, rendered configuration, and owning and
deadline-aware exchanges.

### DO: Classify by numeric code before consulting reply text

[RFC 3244 section 2](https://www.rfc-editor.org/rfc/rfc3244.html#section-2) defines a
16-bit result code: 0-4 inherited from the original change-password protocol,
5-7 (`ACCESSDENIED`, `BAD_VERSION`, `INITIAL_FLAG_NEEDED`) added by RFC 3244,
and `0xFFFF` for anything else. That number is the contract. The result string
is described as "information which might be useful to the user" and **may be
omitted entirely**; its content is implementation-defined and localizable.

RFC 3244 does specify the string as UTF-8, so non-UTF-8 output is a server
defect rather than a permitted case. Keep the raw bytes anyway: you need
byte-exact evidence in the audit record, and a decoder that silently repairs
malformed input hides the defect instead of surfacing it.
`String::from_utf8_lossy` substitutes `U+FFFD` for each invalid sequence, so a
classifier reading repaired text branches on bytes the server never sent.

```rust
// BAD: lossy conversion repairs malformed input in place, and the match is
// against prose the server never promised to keep stable.
let text = String::from_utf8_lossy(&reply.result_text);
if text.contains("too soon") { return Err(ChangeError::TooSoon); }

// GOOD: the number decides. Raw bytes stay verbatim for the audit record and
// are decoded only for display.
match reply.code {
    0 => Ok(reply),
    4 => classify_soft_error(&reply.result_text),   // the bounded exception
    code => Err(classify_kpasswd_code(code)),
}
```

**The bounded exception.** Where a protocol code provably covers several
user-visible causes, the numeric space alone cannot separate them. Then, and
only then:

- Match on the **raw bytes**, never on a lossily-decoded `String`.
- Use a closed allowlist of patterns, defaulting to the *safe* class.
- Pin every pattern to a measured reply from a real server, in a test. Realms
  word these differently and change them between releases.
- Confine it to one named function whose doc comment states which numeric code
  the exception covers **and cites the fixture**, so the exception is auditable
  rather than folklore.

MIT is the common instance: it collapses complexity, history *and* minimum-age
rejections onto `KRB5_KPASSWD_SOFTERROR` (4). Heimdal likewise returns
`SOFTERROR` for password-quality failures. AD exposes policy detail differently
again - measure the realm you actually target.

### DO: Make the outcome classifier exhaustive over the client library's error type

A wildcard arm in a security classifier is not a style issue. `_ =>
ChangeError::AuthFailed` tells a user their password is wrong when the cause was
clock skew, DNS failure, or an oversized frame. That misdirects users during an
outage, and pollutes the anti-enumeration class from the next rule with outcomes
that are **not evidence about a credential**.

`wildcard_enum_match_arm = "deny"` (Section 9) enforces this, so upgrading a
dependency that adds a variant fails the build instead of silently defaulting.

```rust
// BAD: every present and future variant collapses onto a credential verdict.
match err {
    KrbError::Krb(_) => ChangeError::AuthFailed { detail: String::new() },
    _ => ChangeError::AuthFailed { detail: String::new() },
}

// GOOD: exhaustive over variants, so a new variant is a build failure.
// Note `&err`: matching a reference makes `code` a `&i32`.
// `Transport` and `Decode` carry error types here, so `to_string()` is a
// `Display` call. If a variant carries a `String`, use `.clone()` instead -
// `to_string()` on a `&String` derefs and clones implicitly, which
// `clippy::implicit_clone` flags and Section 4 forbids.
#[must_use]
fn classify(err: &KrbError) -> ChangeError {
    match err {
        KrbError::Krb(code)    => classify_kdc_code(*code),
        KrbError::Transport(e) => ChangeError::RealmUnavailable { detail: e.to_string() },
        KrbError::Skew         => ChangeError::RealmUnavailable { detail: "clock skew".to_owned() },
        KrbError::Decode(e)    => ChangeError::Internal { detail: e.to_string() },
    }
}
```

`#[must_use]` is not decoration here. A classifier whose result is dropped
silently converts a failure into a success path; `Result` carries it for free,
a bare outcome enum does not (Section 3).

**Do not erase the error type before you classify it.** This rule depends on the
concrete enum still being visible. A provider boundary returning
`anyhow::Error` or `Box<dyn Error>` destroys exhaustiveness: the lint has
nothing to check, and callers end up classifying by downcast or by string
content - the very thing the previous rule forbids.

```rust
// BAD: erased at the boundary. Nothing can enforce exhaustive classification.
async fn exchange(&self, req: ChangeRequest<'_>) -> Result<KpasswdReply, anyhow::Error>;

// GOOD: classify while the concrete enum is visible, then expose only the
// already-classified domain error outward.
async fn exchange(&self, req: ChangeRequest<'_>) -> Result<KpasswdReply, KrbError>;
```

Erase behind `dyn Trait` only *after* the value has become your domain error.

Fallbacks differ by namespace, and getting them backwards either invents a
credential verdict from a transport bug or leaks account state through a novel
code:

- An unknown **library error variant** is not evidence about a credential, so it
  falls back to an internal or realm-unavailable class. Never a credential
  verdict.
- An unknown **KRB-ERROR code** arrived on the credential channel, and `i32`
  cannot be enumerated. Its fallback is the *least-disclosing* class - the same
  uniform credential-failure class used for unknown principal and wrong
  password.

Only the second always exists, so pin that one with a test. A library-variant
fallback should **not** exist where the dependency's error enum is exhaustively
matchable: there the compiler is the enforcement, and a wildcard arm is itself
the defect.

**When the dependency enum is `#[non_exhaustive]`.** Compile-time exhaustiveness
is then unavailable: Section 3 tells you to mark your own public enums
`#[non_exhaustive]`, and the flip side is that a dependency doing so forces a
wildcard on you, converting a build break into a silent runtime default. Test
every *constructible* known variant (opaque or privately-constructed variants
may not be reachable from your test), and record the wildcard as an
upgrade-review hazard.

### DON'T: Let the failure taxonomy become an existence oracle

Kerberos exposes distinct codes for unknown principal
(`KDC_ERR_C_PRINCIPAL_UNKNOWN`, 6), failed pre-authentication
(`KDC_ERR_PREAUTH_FAILED`, 24), and revoked client credentials
(`KDC_ERR_CLIENT_REVOKED`, 18 - which realms commonly return for disabled or
locked accounts, though the RFC wording is broader). Mapping those to distinct
user-visible outcomes builds a username-enumeration oracle out of correct
protocol handling.

Collapse them into **one variant** whose `Display` is constant, so no call site
can widen the class by choosing a different message. That is necessary but not
sufficient: **a derived `Debug` prints the variant name and every field**, so
`derive(Debug)` on `ChangeError` would emit `AuthFailed { detail: "..." }`. That
is why the prelude writes `Debug` by hand.

The hand-written `Debug` fixes formatting only. `detail` is a field of a `pub`
variant, so downstream code can still destructure and print it. If the detail
must be unreachable outside the crate, give the variant a private wrapper type
(`AuthFailed { detail: AuthFailureDetail }` with a private inner `String`)
rather than a bare `String`. Decide which property you need; the first does not
give you the second.

Two corollaries:

- **Timing is part of the class.** An unknown principal fails in milliseconds; a
  wrong password costs a full AS exchange. Adding a *constant* delay preserves
  the gap. Pad to a fixed total elapsed time measured **from request start**,
  and emit immediately if a slow realm already exceeded the floor. Test the
  collapsed causes for equal status, body **and** floor - equal timing with
  unequal body length is still an oracle.
- **Do not over-collapse.** Only outcomes that are evidence about a credential
  belong in the class. Clock skew, DNS failure and malformed frames are
  infrastructure faults; filing them under "authentication failed" both lies to
  the user and dilutes the class it was meant to protect.

### DO: Bound length-prefixed frames before allocating

A naive reader hands a 4 GiB allocation hint to `vec![0u8; len]` on behalf of a
peer that has not authenticated yet. `overflow-checks = true` does not help:
nothing overflowed. The number was faithfully parsed and faithfully enormous.

```rust
// BAD: indexes the header, converts with a truncating `as`, and allocates
// whatever an unauthenticated peer asked for.
let len = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
let mut body = vec![0u8; len];
stream.read_exact(&mut body).await?;

// GOOD: bounds-checked slice, propagated conversion error, capped length.
// `bool::ok_or` (Section 2) keeps each invariant to one line; the receiver is
// the condition that must hold for SUCCESS.
let hdr: [u8; 4] = buf.get(..4)
    .ok_or(FrameError::ShortHeader)?
    .try_into()
    .map_err(|_| FrameError::ShortHeader)?;
let raw = u32::from_be_bytes(hdr);
let len = usize::try_from(raw).map_err(|_| FrameError::Truncated)?;
(len <= MAX_RESPONSE_BYTES).ok_or(FrameError::TooLong { len })?;
let mut body = vec![0u8; len];
stream.read_exact(&mut body).await?;
```

Rules:

- Read multi-byte fields with `from_be_bytes` over a bounds-checked slice, never
  by indexing. `indexing_slicing = "deny"` and `unwrap_used = "deny"`
  (Section 9) both apply, so propagate the `TryFromSliceError` - the idiom is in
  Section 4.
- Cap **before** allocating, against a configured maximum. "The server would
  never send that" is not a bound; the peer is whoever answers on that socket.
- Use `checked_add` for offset arithmetic. Release-mode abort on overflow is
  fail-stop hardening, not input validation.
- Add fuzz targets for **both** the outer frame parser and the inner body
  parser. They are the first code a hostile or misconfigured peer reaches, they
  run before authentication completes, and they are where malformed input turns
  directly into an allocation or a panic.

**Reserved bits, only where the transport defines them.** Reject a set reserved
bit for the transport that specifies one, and cite that transport exactly.
[RFC 4120 section 7.2.2](https://www.rfc-editor.org/rfc/rfc4120.html#section-7.2.2)
governs the **KDC** TCP transport (port 88):

> "Each request (KRB_KDC_REQ) and response (KRB_KDC_REP or KRB_ERROR) sent over
> the TCP stream is preceded by the length of the request as 4 octets in network
> byte order. The high bit of the length is reserved for future expansion and
> MUST currently be set to zero."

```rust
// Only for the KDC TCP transport. RFC 3244 gives kpasswd its own 4-octet
// header and does NOT restate this, so do not apply it there.
(raw & 0x8000_0000 == 0).ok_or(FrameError::ReservedBitSet)?;
```

Bounding an oversized frame is correct on both transports; only this check and
its citation are KDC-specific.

### DO: Apply enctype allowlists through the config entry point, then re-assert

Kerberos configuration bindings commonly expose enctype *names* as a public
field while the values that reach the AS-REQ are a **derived** numeric id list
compiled from those names during construction. Where the derivation runs only at
construction, assigning the public field afterwards is not a configuration
change: it fails open, with logs showing the requested allowlist while the ids
on the wire remain whatever they were.

```rust
// BAD: the names are yours, the ids are stale. The derivation ran during
// `default()` and does not run again.
let mut config = Config::default();
config.requested_enctype_names = permitted_names().to_vec();

// GOOD: build through the entry point that re-derives, then assert on the
// DERIVED value - not on the value you set.
let config = Config::from_text(&rendered_krb5_conf)?;
// `.copied()`: the ids are `Copy`, and taking a scalar by reference trips
// `clippy::trivially_copy_pass_by_ref` on `is_permitted`.
config.effective_enctype_ids().iter().copied().all(is_permitted)
    .ok_or(ConfigError::AllowlistEscaped)?;
```

The general rule: **when a library derives internal state from a public field at
construction time, mutating that field afterwards is not a configuration
change.** Build through the constructor and verify the derived representation,
because that is the one the protocol sees. Where no such derived state exists,
the rule does not apply - do not add ceremony hunting for it.

Two Kerberos-specific corollaries:

- **Deny by name *and* by numeric id, independently of the allowlist.** A
  library's own "is this weak?" predicate encodes *its* policy, not yours - some
  match only export-grade RC4 and single-DES, leaving plain `rc4-hmac` (23) to
  pass an `allow_weak_crypto = false` setting. Measure the predicate rather than
  trusting it, and re-measure on upgrade. RC4 and 3DES are deprecated by
  [RFC 8429 (BCP 218)](https://www.rfc-editor.org/info/rfc8429), DES and
  RC4-HMAC-EXP by [RFC 6649 (BCP 179)](https://www.rfc-editor.org/info/rfc6649);
  the id-to-name mapping is the
  [IANA Kerberos Encryption Type Numbers registry](https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml).
  Which ids your project permits is a policy decision - realms differ, and AD in
  particular has its own defaults.
- **Reject, never silently narrow.** Filtering a forbidden enctype out of the
  requested set leaves an operator believing it was honoured. Fail startup and
  name the enctype.

Verify the **encoded** AS-REQ `etype` list, not the requested config field. A
packet capture or an assertion on the encoded request is evidence; the config
object alone is not.

### DON'T: Let a Kerberos library discover configuration or credentials ambiently

Kerberos stacks read endpoint configuration from `/etc/krb5.conf`,
`KRB5_CONFIG`, and DNS (SRV, and URI/TXT where enabled), and discover ambient
*credentials* from a credential cache (`KRB5CCNAME`) or keytab (`KRB5_KTNAME`,
`KRB5_CLIENT_KTNAME`). Both classes are unsigned input, and they fail
differently: endpoint configuration can redirect the exchange, while an ambient
credential source can authenticate as a principal nobody intended.

The redirect case is why this matters. An AS-REQ carrying `PA-ENC-TIMESTAMP`
contains password-derived material, so redirecting a client that sends encrypted
timestamp pre-authentication yields ciphertext an attacker can attack offline.

The rule is about **ambient discovery**, not about credentials as such. An
explicitly configured service or admin keytab is a legitimate authentication
mode for set-password and administrative flows; what is forbidden is a
credential or config path arriving from process ambient state that nobody
chose.

- Build configuration through the stack's **non-ambient** entry point under
  first-party control, typically a parser over an in-memory string. Where a
  stack only supports ambient discovery (notably libkrb5 FFI), record it as an
  accepted risk rather than claiming compliance.
- Treat ambient file, env, ccache and keytab *discovery* constructors as
  forbidden API; explicitly configured credential sources get the same review as
  any other presented secret. Enforce it mechanically - an approved wrapper, or
  a source-guard test that also catches aliases and re-exports.
- Fail startup when a monitored ambient variable is present, even where today's
  code path ignores it; the tripwire is what catches a dependency upgrade that
  starts reading one. Warning-only downgrades belong in a threat model.
- Enumerate those inputs from the dependency's source - the names above are a
  baseline. Config files pull in more via `include`, `includedir` and `module`,
  and libkrb5 also honours `KRB5_KDC_PROFILE`, the `KRB5RCACHE*` variables, and
  `KRB5_TRACE`, which can write protocol detail to an attacker-chosen path.

```rust
// NOTE: you can refuse to start, but you cannot sanitize in place.
// `std::env::remove_var` and `set_var` became `unsafe` in edition 2024 (they
// race with any concurrent getenv), so under `unsafe_code = "forbid"`
// (Section 9) clearing a hostile variable is unavailable. Design the check as a
// tripwire. If some other boundary clears the environment, document why it runs
// before any concurrent environment access.
pub fn assert_no_ambient_krb5_env(monitored: &[&'static str]) -> Result<(), ConfigError> {
    for &name in monitored {
        std::env::var_os(name)
            .is_none()
            .ok_or(ConfigError::AmbientEnv { name })?;
    }
    Ok(())
}
```

### DO: Treat credential-mutating futures as NOT cancel-safe

Section 5 requires a cancel-safety annotation on every async fn. Treat a
credential-mutating exchange as **NOT cancel-safe** unless the implementation
can prove cancellation cannot occur after the point where the server may commit.
Dropping the future does not roll the server back: the change may already have
been applied while the caller observes only a timeout, so the natural retry hits
minimum-age or history policy and surfaces as "your new password was rejected"
when it was in fact accepted.

Two obligations, one on each side of the API:

- **Implementation:** enforce the deadline *inside* the exchange, so no drop
  happens mid-commit. Wrapping the whole exchange in `tokio::time::timeout`
  does not do this - it drops the future at the deadline, which is precisely the
  cancellation this rule forbids.
- **Caller:** cancellation for shutdown or client disconnect is legitimate and
  cannot be designed away. What must not happen is treating a cancelled exchange
  as "did not happen". Record the outcome as *unknown* and do not blindly retry.

```rust
/// # Cancel safety
///
/// **NOT cancel-safe.** Dropping this future mid-exchange does not roll the
/// server back; the change may already have been applied. If it is dropped for
/// shutdown, the outcome is unknown and must not be retried as if it had not
/// happened.
async fn change_password(
    &self,
    req: ChangeRequest<'_>,
) -> Result<KpasswdReply, ChangeError> {
    let transport = KdcTransport::new()
        .with_io_timeout(TRANSPORT_IO_TIMEOUT)
        .with_response_limit(MAX_RESPONSE_BYTES);

    // Contract of `exchange_before`: check the deadline BEFORE each network
    // step, and return a timeout error before starting the commit-capable step.
    // It must not implement the deadline by wrapping itself in
    // `tokio::time::timeout` - that reintroduces the mid-commit drop.
    self.exchange_before(Instant::now() + EXCHANGE_DEADLINE, req, transport)
        .await
}
```

**Set dependency defaults that govern a stated requirement.** A dependency's own
transport deadline, retry count or response cap can silently pre-empt a longer
documented requirement, making the stated number dead code. Where a requirement
names a value - `TRANSPORT_IO_TIMEOUT`, `EXCHANGE_DEADLINE`,
`MAX_RESPONSE_BYTES` above - set the corresponding library knob explicitly at
the boundary, or record why the default already satisfies it.

### DO: Own the zeroization boundary, and state exactly where it ends

In a change flow authenticated with the current password, that password is never
transmitted: it plus the salt from `ETYPE-INFO2` run through string-to-key, and
the derived key encrypts a timestamp (`PA-ENC-TIMESTAMP`). Possession is proven
by producing that ciphertext. The *new* password does travel, sealed in a
`KRB-PRIV` envelope. Set-password and administrative flows differ - there the
presented credential may be a service or admin credential instead - but the
handling rule is the same for whichever secret the client presents.

Wrap presented and newly-chosen secrets in `zeroize::Zeroizing` (or
`secrecy::Secret`, Section 10) and construct the protocol client **per
request**, so no credential outlives the request that supplied it:

```rust
pub struct ChangeRequest<'a> {
    pub realm: &'a str,
    pub username: &'a str,
    pub current_password: Zeroizing<String>,
    pub new_password: Zeroizing<String>,
}
```

**Use ownership to cut copies.** A one-shot credential-mutating call should
*consume* its request. Borrowing it forces a second owned plaintext buffer for
any library that takes ownership, and keeps the original alive alongside it:

```rust
// BAD: borrowed request. The secret cannot move out, so reaching an owning
// callee costs a full plaintext copy.
async fn change_password(&self, req: &ChangeRequest<'_>) -> Result<KpasswdReply, ChangeError> {
    self.exchange_with(req.current_password.clone()).await
}

// GOOD: consume the one-shot request so the secret moves instead of copying.
async fn change_password(&self, req: ChangeRequest<'_>) -> Result<KpasswdReply, ChangeError> {
    self.exchange_with(req.current_password).await
}
```

Where the request genuinely must be borrowed - several phases reuse it - keep
every forced copy inside a zeroizing wrapper rather than handing over a bare
`Vec<u8>`:

```rust
let password = Zeroizing::new(req.current_password.as_bytes().to_vec());
let client = KrbClient::with_password(config, principal, password);
```

If the API accepts only a plain `Vec<u8>`, pass the temporary directly and
record that allocation as a residual. "Consumed by the callee" is not "zeroized
by the callee", and you cannot claim the latter without reading it.

The guarantee fails at these boundaries:

- **`panic = "abort"` does not run `Drop`.** Abort is legitimate fail-stop
  hardening - no unwinding through frames that held key material - but it
  zeroizes nothing on the way out. It must never be cited as a secrets control;
  disabled core dumps are the compensating control.
- **Dependency-owned copies are not yours.** Do not claim zeroization for a
  buffer the dependency owns unless it documents or demonstrably performs it.
  Wrapping only the first of several copies produces a control that is mostly
  false; record the residual and the condition that would close it.
- **A derived `Debug` re-opens the leak.** One `#[derive(Debug)]` on a struct
  holding a secret field can put it in a log line. Redaction tests must assert
  on the output your code actually emits, never on `{:?}`.
- **A zeroizing global allocator is not a control.** The Rust 1.99
  `GlobalAlloc` documentation states that allocations "may non-deterministically
  entirely skip the underlying allocator" - they may be stack-promoted, merged,
  or skipped - so the deallocation of a secret may never reach the allocator.
  When `dealloc` is called the allocator may overwrite the bytes, but it cannot
  rely on reading initialized contents. Attach zeroization to the value instead.

- **Validation libraries are sinks too.** Hand plaintext to a scoring or
  strength-estimation library only after its allocation and logging behaviour is
  audited and accepted; otherwise validate inside your own boundary and record
  what that policy cannot check.

Zeroization also does not prevent offline guessing from captured
encrypted-timestamp pre-authentication - without FAST armor
([RFC 6113](https://www.rfc-editor.org/info/rfc6113)) that exchange is an
offline verifier by construction. That is why ambient endpoint discovery is a
credential control and not hygiene.

Core Section 10's lossy UTF-8 helpers (`from_utf8_lossy_owned`, `into_utf8_lossy`) are for display
only; classifiers keep reply text as `Vec<u8>` for exactly the reason given above.

## Checklist (in addition to the core checklist)

- [ ] Outcomes classified by numeric protocol code before any reply text is consulted
- [ ] Any text matching confined to one named function over raw bytes, allowlisted, defaulting to the safe class, and pinned to a measured server reply
- [ ] Reply text kept as `Vec<u8>`; `from_utf8_lossy` never feeds a classifier
- [ ] Classifier exhaustive over the library error type; a wildcard where the enum IS exhaustively matchable is itself the defect
- [ ] Concrete dependency error type preserved to the classification point; no `anyhow`/`Box<dyn Error>` erasure before the domain error exists
- [ ] Unknown protocol error code falls back to the least-disclosing class, pinned by test; a dependency-enum wildcard exists only where non-exhaustiveness forces it, and never returns a credential verdict
- [ ] `#[non_exhaustive]` dependency enums: every constructible variant tested, wildcard recorded as an upgrade-review hazard
- [ ] Existence, wrong-secret and disabled outcomes collapse into one variant with a constant `Display`; `Debug` hand-written; private wrapper type used if `detail` must also be unreadable downstream
- [ ] Anti-enumeration floor measured from request start (not a constant delay), with status, body AND timing tested equal across the collapsed causes
- [ ] Infrastructure faults (skew, DNS, malformed frames) NOT filed under the credential class
- [ ] Frames: length capped before allocation, no indexing, no `as` on the length, `checked_add` offsets, both parsers fuzzed
- [ ] Reserved-bit rejection applied only where the transport defines one, and cited to that transport (RFC 4120 section 7.2.2 is the KDC transport, not RFC 3244 kpasswd framing)
- [ ] Where the stack derives wire state from a public field at construction, config built through the non-ambient entry point and asserted on the DERIVED value
- [ ] Encoded AS-REQ etype list verified by capture or encoded-request assertion, never by reading the config object back
- [ ] Forbidden enctypes denied by name AND numeric id, independently of the library's weak-algorithm predicate; predicate re-measured on upgrade; rejected, never silently narrowed
- [ ] No ambient discovery of config or credentials, enforced mechanically; explicitly configured credentials reviewed like any presented secret
- [ ] Ambient tripwire fails startup and covers every ambient input the stack reads, enumerated from the dependency source rather than assumed; warning-only downgrades live in a threat model
- [ ] Credential-mutating futures documented NOT cancel-safe unless cancellation provably cannot occur after server commit; deadline enforced inside the exchange, not wrapped around it; cancelled exchanges recorded UNKNOWN, never retried as "did not happen"
- [ ] Dependency defaults governing a stated requirement set explicitly at the boundary or justified in writing
- [ ] One-shot credential-mutating calls consume their request so secrets move rather than copy; where borrowing is unavoidable every forced buffer stays in `Zeroizing`
- [ ] Secrets wrapped in `Zeroizing`/`Secret`; client constructed per request; dependency-owned copies that cannot be zeroized recorded as residuals with the condition that would close them
- [ ] `panic = "abort"` never cited as a secrets control (abort skips `Drop`)

## References

Verified against RFC Editor and IANA, 2026-09-03.

- [RFC 4120](https://www.rfc-editor.org/info/rfc4120) - Kerberos V5 core.
  **Proposed Standard.** KDC TCP framing is
  [section 7.2.2](https://www.rfc-editor.org/rfc/rfc4120.html#section-7.2.2); KRB-ERROR
  codes are section 7.5.9; recommended acceptable clock skew (5 minutes) is section 8.2.
- [RFC 3244](https://www.rfc-editor.org/info/rfc3244) - Kerberos change/set
  password protocol. **Informational.** Result codes are
  [section 2](https://www.rfc-editor.org/rfc/rfc3244.html#section-2).
- [RFC 3961](https://www.rfc-editor.org/info/rfc3961) - encryption and checksum
  profile, including string-to-key. **Proposed Standard.**
- [RFC 6113](https://www.rfc-editor.org/info/rfc6113) - FAST pre-authentication
  framework. **Proposed Standard.**
- [RFC 3962](https://www.rfc-editor.org/info/rfc3962) - AES enctypes 17 and 18.
  **Proposed Standard.**
- [RFC 8009](https://www.rfc-editor.org/info/rfc8009) - AES-SHA2 enctypes 19 and
  20. **Informational.**
- [RFC 6649](https://www.rfc-editor.org/info/rfc6649) - deprecates DES and
  RC4-HMAC-EXP. **BCP 179.**
- [RFC 8429](https://www.rfc-editor.org/info/rfc8429) - deprecates 3DES and RC4.
  **BCP 218.** Reclassified RFC 4757 as Historic.
- [RFC 4757](https://www.rfc-editor.org/info/rfc4757) - RC4-HMAC enctype 23.
  **Historic.** Cite only to explain what 23 is.
- [IANA Kerberos Encryption Type Numbers](https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml)
  - authoritative id-to-name mapping and deprecation status.
