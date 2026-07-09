# ADR 0003: V6 (RFC 9580) Key Support

## Status

Accepted

## Date

2026-04-18

## Context

wecanencrypt 0.10 generated only V4 (RFC 4880) keys. RFC 9580 defines V6
keys with SHA-256 fingerprints, 16-byte signature salts, Argon2-based S2K,
SEIPDv2/AEAD messages, and a stricter algorithm set (Ed25519Legacy and
ECDH-Curve25519 forbidden). GnuPG 2.5, Sequoia, and rpgp itself already
produce and consume V6 artifacts; wecanencrypt needed to follow to stay
interoperable.

Three design tensions shaped the API:

1. **Don't break existing V4 callers.** The library has downstream users
   (tumpa, johnnycanencrypt consumers) who call `create_key`, `merge_keys`,
   and `encrypt_bytes_to_multiple` today. A V4 user should not need to
   change a single call site to pick up the 0.11 release.

2. **Don't silently mix versions.** RFC 9580 §10.1.1 forbids V6 subkeys
   under a V4 primary and vice versa; §5.1.2 / §5.3.2 forbid V6 ESK
   packets preceding SEIPDv1 and vice versa. A mixed keyring or
   mixed-version recipient list is either an RFC violation or user error,
   never a legitimate operation.

3. **Keep card support separate.** V6 key upload to smart cards has its
   own protocol considerations (AEAD PKESK encoding, key-material OID
   selection, touch policy). That work is deferred to a later ADR.

## Decision

### 1. Explicit, parallel V4 / V6 functions

`create_key` (V4, 9 args) keeps its 0.10 signature unchanged. A sibling
`create_key_v6` (V6, 9 args) takes the same parameter list. A private
`create_key_internal` (10 args, adds `key_version: KeyVersion`) holds the
single implementation; both public functions delegate to it.

```rust
pub fn create_key(..., can_primary_expire: bool) -> Result<GeneratedKey>;
pub fn create_key_v6(..., can_primary_expire: bool) -> Result<GeneratedKey>;
pub fn create_key_simple(password, user_ids) -> Result<GeneratedKey>;     // V4
pub fn create_key_v6_simple(password, user_ids, cipher) -> Result<...>;   // V6
```

V6 rejects `CipherSuite::Cv25519` (legacy Ed25519Legacy + ECDH-Curve25519)
with `Error::InvalidInput` per RFC 9580 §9.2; all other suites are
accepted.

### 2. No cross-version mixing - enforced at four layers

`Error::KeyVersionMismatch { existing, incoming }` is returned by:

| Layer | Function | Trigger |
|-------|----------|---------|
| Merge | `keyring::merge_keys` | orig and update primary versions differ |
| Encrypt | `encrypt_bytes_to_multiple*` | recipient list contains both V4 and V6 primaries, or a primary/subkey version mismatch within a single key |
| Import | `KeyStore::import_key` | stored row exists for the fingerprint with a different primary version |

The subkey-version cross-check in `collect_encryption_keys` is
defense-in-depth: rpgp 0.19 already refuses to parse mismatched keys at
load time, but the explicit check covers future parser relaxations and
in-memory-constructed keys that bypass parsing.

### 3. SEIPDv1 vs v2 is auto-dispatched by recipient version

`encrypt_bytes_to_multiple` inspects recipient primaries and routes:

- **All V4 recipients** → `MessageBuilder::seipd_v1` + AES-256 + MDC
  (unchanged from 0.10, byte-identical output)
- **All V6 recipients** → `MessageBuilder::seipd_v2` + AES-256 + OCB (AEAD)
- **Mixed** → `Error::KeyVersionMismatch`

The explicit `encrypt_bytes_to_multiple_seipd_v2` and
`encrypt_bytes_to_multiple_with_algo` entry points remain available for
callers that need to override the defaults.

### 4. Password protection delegates to rpgp

No new parameters for S2K selection. rpgp's `SecretKeyParamsBuilder`
picks the version-appropriate S2K automatically: iterated+salted+AES-CFB
for V4, Argon2id+AES-256+OCB for V6 (per RFC 9580 §3.7.2). `update_password`
is version-preserving by construction - it decrypts with the old
password using the key's existing S2K and re-encrypts with rpgp's
default for that version.

### 5. `KeyInfo` / `SubkeyInfo` expose `key_version`

Both structs gain a `pub key_version: KeyVersion` field so callers can
filter or display without re-parsing. Adding public fields is a
struct-literal-breaking change for external users who construct these
types - acceptable under the 0.x → 0.11 version bump.

## Consequences

### Positive

- V4 call sites port from 0.10 to 0.11 with **zero changes**.
- V6 is discoverable by name: autocomplete on `create_key_v6`,
  `create_key_v6_simple` makes the intent obvious in review.
- One code path (`create_key_internal`) - no risk of V4 and V6 logic
  drifting apart.
- Cross-version mixing fails fast with a precise error at four layers,
  matching the RFC's structural guarantees end-to-end.
- Auto-SEIPD dispatch means downstream users who import a V6 key from a
  keyserver and call `encrypt_bytes` do the RFC-compliant thing by
  default.

### Negative

- Public API surface grew: four key-creation functions instead of two.
  Justified by the "no breaking change for V4" goal - collapsing them
  again would require re-introducing a `KeyVersion` argument.
- `KeyInfo` / `SubkeyInfo` struct-literal construction breaks for
  external callers. 0.x semver permits this; tests and in-tree users are
  updated.
- V6 keystore rows and V4 keystore rows coexist by fingerprint (they can
  never collide - structurally different hashes), but a single import
  operation cannot upgrade a V4 row to V6 or vice versa. Users who want
  to migrate a key from V4 to V6 must generate a fresh V6 key and
  cross-sign; there is no in-place upgrade tool.

## Alternatives Considered

### Single `create_key` with a `KeyVersion` parameter

Initial design. Rejected: makes V4 a breaking change for every caller
just to enable V6.

### New `CipherSuite` variants carrying the version (e.g. `Cv25519V6`)

Considered. Rejected: conflates two orthogonal concerns (algorithm and
packet version) and doesn't scale - a new V7 would require a full
duplication of every cipher suite variant.

### Auto-pick V6 when `CipherSuite::Cv25519Modern` or `Cv448Modern` is chosen

Considered. Rejected: these cipher suites are valid under V4 too (rpgp
accepts Ed25519 / X25519 in V4 keys), and silently changing the packet
version based on algorithm choice would surprise callers who want V4
compatibility with modern algorithms.

### Allow mixed V4 + V6 recipient lists

Considered. Rejected: RFC 9580 §5.1.2 / §5.3.2 forbid V6 ESK preceding
V1 SEIPD and vice versa. There is no standards-compliant wire format for
a mixed message; refusing is the only correct behaviour.

## References

- RFC 9580 §5.5 (V6 key packet), §5.2.3 (V6 signature salt), §9.2
  (V6-forbidden algorithms), §10.1.1 (subkey version parity), §3.7.2
  (Argon2 S2K for V6 secret keys)
- rpgp 0.19: `SecretKeyParamsBuilder::version`,
  `SignedPublicKey::primary_key.version()`,
  `MessageBuilder::seipd_v2`
- `WECANENCRYPT_DIFFERENTIAL_REVIEW_2026-04-15_RFC9580.md` - prior
  review flagging that `Cv448Modern` was producing V4 keys
- `WECANENCRYPT_DIFFERENTIAL_REVIEW_2026-04-18_V6_SUPPORT.md` - security
  review of this change
- ADR 0002: key merge semantics (the mixing guard slots into
  `merge_keys` ahead of the fingerprint compare)
