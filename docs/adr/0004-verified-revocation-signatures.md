# ADR 0004: Cryptographic Verification of Revocation Signatures

## Status

Accepted

## Date

2026-04-23

## Context

rpgp's parser admits any packet tagged `KeyRevocation` (type 0x20),
`SubkeyRevocation` (0x28), or `CertRevocation` (0x30) into the parsed
key structure without cryptographically verifying the signature on it.
`composed/signed_key/key_parser.rs` performs framing and type checks
only — it never calls `Signature::verify_key`,
`verify_subkey_binding`, or `verify_certification`. Every revocation
packet with a valid wire format survives parsing, regardless of who
signed it.

Before this ADR, wecanencrypt trusted those packet-type tags at face
value. `internal::policy::is_subkey_revoked`, `is_details_revoked`,
and the inline `CertRevocation` scan in `parse.rs::extract_key_info`
all tested `sig.typ() == Some(SignatureType::…Revocation)` and
accepted the first match. A single existing helper,
`verified_primary_revocation` (added in PR #16 for the schema v4
summary cache), did verify `KeyRevocation` signatures — but it was
only used in two keystore paths (`import_key`, schema v4 backfill).
Every other revocation check in the library, including every one in
`verify.rs`, `sign.rs`, `ssh.rs`, `encrypt.rs`, and the public
`parse_key_bytes` surface, remained unverified.

An attacker who can inject packets into a third-party cert export
can exploit this to cause:

1. **DoS on signature verification.** `verify.rs` gates every
   `verify()` call on `is_subkey_revoked` and
   `is_primary_key_valid_for_verification`. A forged subkey
   revocation against any cert a user downloads from a keyserver,
   WKD endpoint, or MITM-able HKP fetch causes all legitimate
   signatures from that subkey to be silently rejected.

2. **DoS on signing, encryption, and SSH authentication.**
   `sign.rs::find_signing_subkey`, `encrypt.rs::valid_encryption_keys`,
   and `ssh.rs::ssh_authenticate_for_hash_on_card` skip revoked
   subkeys. A forged subkey revocation grafted onto a user's own
   stored key denies them the ability to sign, encrypt to their own
   backup recipient, or authenticate over SSH with their hardware
   token.

3. **Forged UID revocation in public API.** `KeyInfo.user_ids[]`
   surfaces `revoked` and `revocation_time` from an unverified
   `CertRevocation` scan. Downstream UIs (tumpa, `tcli`) display
   this as authoritative. An attacker could add a forged
   `CertRevocation` to a victim's cert on a keyserver and cause
   every wecanencrypt consumer fetching that cert to display the
   UID as revoked at an attacker-chosen timestamp.

The incident that prompted this review was
[sequoia-git commit `f9c9074b`][sq-git-fix], which documents a
materially equivalent bypass in a different codebase: `sq-git`'s
policy-deduplication cache allocated a 0-length `Vec` as a SHA-512
output buffer, causing every policy to hash to the empty key, so
only the first policy encountered during BFS got checked for hard
revocations. sq-git's fix is a one-character buffer change, but the
generalisable lesson — do not trust unverified revocation packets,
anywhere — applies directly to wecanencrypt's own packet-type-only
checks.

Sequoia-PGP solves this at the policy layer: `StandardPolicy`
enforces cryptographic verification of every revocation signature
before surfacing it in `ValidCert`. rpgp has no equivalent. GnuPG
verifies revocation signatures in `g10/sig-check.c::check_revocation_keys`
and rejects bad ones at parse time (with a warning). wecanencrypt
now performs equivalent verification at every consumption site via
shared policy helpers.

## Decision

### 1. Every revocation check verifies the signature against the primary key

The three revocation types and the rpgp methods that verify them:

| Type | Code | Signed by | rpgp method |
|---|---|---|---|
| `KeyRevocation` | 0x20 | primary key (self-revocation) | `Signature::verify_key` |
| `SubkeyRevocation` | 0x28 | primary key over subkey binding | `Signature::verify_subkey_binding` |
| `CertRevocation` | 0x30 | primary key over UID certification | `Signature::verify_certification` |

All three are self-revocations produced by the primary key revoking
itself, one of its subkeys, or one of its UIDs. Designated-revoker
signatures (revocations via a separate "revocation key" subpacket)
are explicitly out of scope — verifying them would require resolving
the `Revocation Key` subpacket against an external keyring, which
the current architecture does not wire up.

`SubkeyBinding` and `SubkeyRevocation` signatures hash exactly the
same input (primary public key packet + subkey public key packet per
RFC 4880 §5.2.4), so `verify_subkey_binding` is the correct rpgp
method for both types — the signature-type byte is read from the
signature's own config, not from the method name. Passing the
subkey's *public* form is mandatory: `PublicSubkey` and `SecretSubkey`
have different `Serialize` impls (tag 14 vs tag 7), so hashing over
the secret form produces a byte stream that will never verify
against a signature computed over the public form.

### 2. Verification happens inside the policy helpers, not at call sites

`internal::policy` is the single source of truth. `is_subkey_revoked`,
`is_subkey_valid`, `is_primary_key_revoked`, and `is_primary_key_valid_for_verification`
now all internally verify against the primary key. Every existing
consumer — `verify.rs`, `parse.rs`, `sign.rs`, `ssh.rs`, `encrypt.rs`,
`key.rs`, `card/crypto.rs` — picks up the verified behaviour
automatically by calling the same helper with the primary passed in.

This is strictly stronger than adding parallel `verified_*` helpers
that callers must opt into. Parallel helpers leave the unverified
ones around as a footgun; every new call site is a fresh opportunity
to forget. The helper-level fix is invisible to callers that already
had the primary key in scope (all of them, in practice).

### 3. Helper signatures take the primary key by reference

The subkey family takes the primary as a `&pgp::packet::PublicKey`:

```rust
fn is_subkey_revoked(primary: &PublicKey, subkey: &SignedPublicSubKey) -> bool;
fn is_subkey_valid(primary: &PublicKey, subkey: &SignedPublicSubKey, allow_expired: bool) -> bool;
```

A parallel `is_secret_subkey_revoked(primary, &SignedSecretSubKey)` exists
for `sign.rs` and `ssh.rs`, which iterate `secret_subkeys` rather than
`public_subkeys`. Both paths funnel through a single
generic `any_verified_subkey_revocation` core that is parametric over
`K: KeyDetails + Serialize`, so `PublicSubkey` and `SecretSubkey`
share code — the hash is always computed over the public form thanks
to the trait bounds and the verification-time serialization.

The UID family takes a `&pgp::packet::PublicKey` and `&SignedUser`:

```rust
fn verified_user_id_revocation<'a>(primary: &PublicKey, user: &'a SignedUser)
    -> Option<&'a Signature>;
```

Callers that need the revocation timestamp (only `parse.rs` today)
use the `verified_user_id_revocation` variant that returns the
signature; a `bool` wrapper is intentionally not provided because
the sole caller already wants the signature itself.

### 4. Primary-revocation checks have two variants for ergonomic reasons

```rust
fn is_primary_key_revoked(key: &SignedPublicKey) -> bool;
fn is_primary_secret_key_revoked(key: &SignedSecretKey) -> bool;
```

Both delegate to `verified_primary_revocation` (for the public
variant) or a secret-key equivalent that calls
`sig.verify_key(key.primary_key.public_key())`. Merging them into
one generic form was considered but rejected — the two call-site
groups are small and the concrete types are clearer.

`is_details_revoked(&SignedKeyDetails)`, which existed pre-ADR, is
deleted. `SignedKeyDetails` alone does not carry enough information
to verify a signature (no primary key), so a function that took only
details could never be upgraded to the verified path. Every caller
now passes the full key. `validate_signing_usage` is split into
`validate_public_signing_usage(&SignedPublicKey, …)` and
`validate_secret_signing_usage(&SignedSecretKey, …)` for the same
reason.

### 5. Retention of the `verified_primary_revocation` helper

The function that was the original partial fix (`verified_primary_revocation`)
is preserved as-is. It is still the correct helper for callers that
need the revocation signature itself (not just a bool), notably the
keystore's schema v4 backfill and `parse.rs`'s `revocation_time`
extraction. Its documentation is unchanged; the only difference is
that it is no longer the *only* verified path.

### 6. Verification cost

Every subkey check in `verify.rs`, `sign.rs`, `ssh.rs`, and
`encrypt.rs` now runs one signature verification per revocation
packet attached to each subkey. In practice:

- Legitimate certs have zero revocation packets on healthy subkeys,
  so the verification loop exits immediately.
- A cert with one genuine revocation runs exactly one verify per
  check. An Ed25519 verify is microseconds; this is negligible next
  to the surrounding parse/verify work.
- A cert with many forged revocations attached would incur O(n)
  verifications per check, but also O(n) verifications inside rpgp
  just to parse the signature subpackets. A pathological cert is
  bounded by how much rpgp is willing to parse in the first place.

No caching layer is introduced. If profiling shows this is hot, a
per-key verification cache could be added in a follow-up ADR — but
premature caching here risks reintroducing the exact class of bug
that sq-git fell into.

## Consequences

### Positive

- DoS vectors via forged `KeyRevocation`, `SubkeyRevocation`, and
  `CertRevocation` are closed across the entire public API.
- The keystore summary cache is no longer the only path that
  verifies revocations — the in-memory `parse_key_bytes`,
  `verify_bytes`, `sign_bytes`, `encrypt_bytes`, and SSH-auth flows
  all enforce the same invariant.
- The public API's `KeyInfo.is_revoked`, `KeyInfo.user_ids[].revoked`,
  and `revocation_time` values reflect cryptographic truth rather
  than packet-type tags.
- `is_details_revoked` is gone — a helper that by construction could
  never verify — which removes a tempting wrong-path for future
  contributors.
- Downstream UIs (tumpa, `tcli`) get the correct behaviour for free;
  no changes needed in those consumers.

### Negative

- Breaking internal API changes: `is_subkey_revoked`,
  `is_subkey_valid`, and `validate_signing_usage` signatures all
  change. All are `pub(crate)`, so no semver bump is required — but
  any downstream fork maintaining patches against these helpers will
  need a rebase.
- Every subkey evaluation now runs at least one signature
  verification. The cost is negligible on healthy keys (most have no
  revocation packets) but non-zero on every call.
- Designated-revoker support is not added. Certs that list a third
  party as their designated revoker will not have that revocation
  honored by wecanencrypt. This was already the prior behaviour —
  the ADR does not regress it — but it is now an explicit gap
  rather than an implicit one.

## Alternatives Considered

### Parallel `verified_*` helpers, migrate call sites gradually

The initial plan was to add `verified_subkey_revocation`,
`verified_cert_revocation`, etc., alongside the existing
unverified helpers and migrate call sites one by one. Rejected
because it leaves unverified helpers in the codebase as a footgun —
every new call site is a fresh opportunity to pick the wrong one.
The helper-level change forces every consumer onto the verified
path automatically.

### Verify at parse time, stash a verified-boolean on the key

Attractive because it pays the verification cost exactly once per
parse. Rejected because it requires mutating rpgp's `SignedPublicKey`
/ `SignedSecretKey` representation (or wrapping them in a
wecanencrypt-owned type), which ripples across every parse boundary
and every call site. The helper-level fix achieves the same
correctness with ~0 lines of type surgery and verification cost
that is dominated by existing parse/verify work.

### Submit the fix upstream to rpgp's parser

Correct in principle — rpgp should reject unverified revocations at
parse time, just as it rejects malformed packets. Considered for a
future contribution but out of scope for this change, which needs
to ship on the currently-pinned rpgp 0.19.x without blocking on
upstream review. The current design is fully compatible with a
future upstream fix: our helpers would become no-ops on
already-verified signatures.

### Also resolve designated-revoker subpackets

Considered and rejected. Designated-revoker support requires a
trust-store abstraction (to resolve the revoker fingerprint against
a keyring the user trusts) that does not currently exist in
wecanencrypt. Adding it would be a larger architectural change that
deserves its own ADR. The current scope is limited to self-
revocations, which is strictly better than the prior (unverified)
state and matches rpgpie's posture.

### Merge `is_primary_key_revoked` and `is_primary_secret_key_revoked`

Considered a generic form that takes any type implementing a
common trait exposing `primary_key.public_key()` and
`details.revocation_signatures`. Rejected because the two callers
in practice are a handful of sites each, the concrete types are
clearer to read, and the trait abstraction would add a new
indirection for no runtime benefit.

## References

- sequoia-git commit [`f9c9074b`][sq-git-fix] — the incident that
  prompted this review; demonstrates a materially equivalent
  revocation-bypass caused by unverified policy deduplication
- RFC 4880 §5.2.1 "Signature Types" — definitions of 0x20, 0x28, 0x30
- RFC 4880 §5.2.4 "Computing Signatures" — identical hash input for
  SubkeyBinding and SubkeyRevocation
- RFC 9580 §5.2 — carryover of the above for v6 keys
- rpgp 0.19 `src/packet/signature/types.rs::verify_key` /
  `verify_subkey_binding` / `verify_certification` — the three
  verification primitives used here
- GnuPG `g10/sig-check.c::check_revocation_keys` — reference
  implementation of revocation verification
- Sequoia-PGP `openpgp/src/cert/mod.rs::valid_revocation_keys` —
  reference implementation of policy-level revocation checking
- ADR 0001: RFC 4880 "latest self-signature wins" for key flags
- ADR 0002: Secret-key-aware merging (introduces
  `verify_bindings` on subkey absorption — complementary to this
  change but distinct)
- PR #16 and commit `a8d6…`: first use of `verified_primary_revocation`
  in the schema v4 summary cache (the starting point that this ADR
  generalises)

[sq-git-fix]: https://gitlab.com/sequoia-pgp/sequoia-git/-/commit/f9c9074bd80023456221f09c3c4ff19957ee9c58
