# ADR 0002: Secret-Key-Aware OpenPGP Key Merging

## Status

Accepted

## Date

2026-04-16

## Context

`merge_keys(key_data, update_data)` is the single entry point for
reconciling two OpenPGP keys that share a primary key. It is called
from tumpa's `--import` path whenever the incoming key already exists
in the keystore, and from any downstream consumer that wants to fold a
keyserver / WKD / file-delivered update into a stored key.

Three concerns collide in this function:

1. **Correctness of the public-side merge** — accumulating new
   signatures, UIDs, user attributes, and subkeys without dropping
   existing ones. This was solved in ADR 0001 (latest self-signature
   wins) and supporting code.

2. **Treatment of secret key material.** OpenPGP data can arrive as a
   Transferable Public Key (TPK) or a Transferable Secret Key (TSK).
   The old implementation parsed both sides through
   `parse_key → SignedSecretKey::to_public_key()`, which *unconditionally
   strips secret packets*. Re-importing a `.sec` file for a key that
   was already stored as public would silently downgrade the stored
   key to public-only (observed in the field via
   `tcli --import ~/KEY.sec` followed by `tcli --list-keys` showing
   `pub` instead of `sec`).

3. **Trust boundary when absorbing new subkeys.** When an update
   carries a secret subkey whose fingerprint we have not seen before,
   accepting it blindly lets a crafted update inject an arbitrary
   "secret subkey" under a primary fingerprint the victim already
   trusts. RFC 9580 defines no merge policy here — implementations
   must decide.

Neither RFC 4880 nor RFC 9580 specifies merge semantics; the spec only
says that Transferable Key packet sequences "may be concatenated." We
therefore align with the two de-facto references:

- **Sequoia-PGP** — `Cert::merge_public` (public-only, used by key
  servers; always strips the incoming secret material) vs
  `Cert::merge_public_and_secret` (prefers any variant that carries
  secret material).
- **rpgpie** (the rsop SOP implementation, on the same rpgp stack we
  use) — `Certificate::merge` for public keys and `Tsk::merge` for
  secret-aware merging.

Both split API surface into a public-only path and a secret-aware
path. **wecanencrypt consolidates both into a single secret-aware
`merge_keys`** because (a) our only in-tree callers always want the
secret preserved when present, and (b) a keyserver-style consumer can
always post-process the result by calling `to_public_key()` itself.

## Decision

### 1. Dispatch matrix

`merge_keys(orig, update)` dispatches on the secret-ness of each side,
detected via `parse_key` (which already returns `(SignedPublicKey,
is_secret: bool)`):

| `orig`  | `update` | Result                                                                             |
|---------|----------|------------------------------------------------------------------------------------|
| public  | public   | `SignedPublicKey::to_bytes` (unchanged behaviour)                                  |
| public  | secret   | incoming secret becomes the base; orig's public key folded in → secret bytes       |
| secret  | secret   | orig's secret is the base; update's secret subkeys merged by FP → secret bytes     |
| secret  | public   | orig's secret is the base; update's public signatures/components folded in         |
| FP mismatch on primary | — | **`Error::InvalidInput`**, always — no override                          |

All secret-bearing outputs are wrapped in `Zeroizing<Vec<u8>>` so the
serialized secret bytes are scrubbed on drop.

### 2. Fingerprint mismatch is a hard error

The previous `force: bool` parameter bypassed the primary-FP check.
That parameter is removed. There is no legitimate workflow for
merging two different primary keys: a user who actually wants to
import key B should call `import_key(B)` directly, not
`merge_keys(A, B)`.

### 3. Binding verification when absorbing a new secret subkey

When the `(secret, secret)` branch encounters a secret subkey in the
update whose fingerprint is not already in
`orig.secret_subkeys`, the subkey's binding signature is verified
against our primary's public key via
`SignedSecretSubKey::verify_bindings`. On failure the subkey is
dropped (with a warning to stderr naming the fingerprint and the rpgp
error); the rest of the merge proceeds unaffected.

This is strictly stronger than what rpgp itself does during parsing:
rpgp retains any subkey with at least one signature, regardless of
whether that signature verifies. We cannot relax this: once a bogus
secret subkey is in `secret_subkeys`, signing/encryption operations
that pick it (e.g. via `find_signing_subkey`) will use it.

### 4. Signature preservation during subkey promotion

"Promotion" is the act of moving a subkey from `orig.public_subkeys`
(we hold only the public half) to `orig.secret_subkeys` (we now hold
the secret half too). It happens when a `(secret, secret)` merge
encounters a secret subkey in the update whose public form was already
in `orig.public_subkeys`.

The public-form entry typically carries accumulated signatures: the
original binding sig, any third-party certifications on the subkey,
any revocation signature. Dropping the public-form entry during
promotion would silently lose all of that.

Therefore, before promoting, we collect every signature attached to
any matching public-form entry, merge them into the incoming secret
subkey's signatures via `merge_signatures` (which dedups by signature
bytes so identical sigs on both sides collapse), and only then remove
the public-form entry and push the promoted secret subkey.

### 5. Examples

In all examples below, "FP" is the 40-hex primary-key fingerprint and
"K1"/"K2"/… are subkey fingerprints. The code path indicated is the
match arm in `merge_keys`.

#### 5.1 Public + public — keyserver refresh (unchanged behaviour)

Stored: Bob's public key `FP=ABCD…`, with UID and binding sigs on K1, K2.
Update: the same key fetched from keys.openpgp.org, now carrying a
third-party certification from Carol on the UID.

```
orig.public_subkeys = [K1, K2]
orig.details.users[0].signatures = [self-sig]
update.details.users[0].signatures = [self-sig, carol's cert-sig]
```

Dispatch: `(false, false)` → `merge_public_key` → `merge_details` dedups
self-sig by signature bytes, appends Carol's cert-sig. Serialized as
`SignedPublicKey`. Result is public-only.

#### 5.2 Public + secret — you imported your public key earlier, now you have the secret

Stored: Bob's public key, no secret material.
Update: Bob's `.sec` file from his old laptop, same FP.

Dispatch: `(false, true)` → the incoming secret becomes the base:

```rust
let mut merged = parse_secret_key(update_data)?;
merge_secret_key(&mut merged, SecretMergeSource::Public(Box::new(orig_public)));
```

Inside `merge_secret_key`, the public form of the stored key is
walked: its UIDs, user-attrs, and subkey signatures are folded into
the secret-bearing base. Any signatures that had accumulated on the
public side (third-party certs, etc.) survive. Result: a secret key
that has both the freshly-imported secret material *and* all the
social data we had accumulated.

Before this ADR: this scenario silently dropped the secret material
because `merge_keys` serialized as `SignedPublicKey`.

#### 5.3 Secret + secret — re-importing, or merging two backups

Stored: Bob's secret key with subkeys K1 (signing) and K2 (enc).
Update: Bob's secret key again, this time with an additional new
self-signature on the UID (he recently bumped the expiry) and a
freshly generated subkey K3 (auth).

Dispatch: `(true, true)` → `merge_secret_key` with
`SecretMergeSource::Secret`. For `src_pub_subkeys` (empty in the
typical case — all subkeys in a fresh export live on the secret side)
the public loop is a no-op. For `src_sec_subkeys`:

- K1, K2 fingerprints match existing entries → sigs deduped via
  `merge_signatures`. The existing secret packets are kept (preferred
  over the incoming copies, per Sequoia's rule: any variant with
  secret material stays).
- K3 fingerprint does not match → binding verification runs against
  the primary; on success, K3 is appended to `secret_subkeys`.

Result: one key carrying K1, K2, K3 as secret subkeys and the new UID
self-sig merged alongside the old one (latest-wins resolution happens
later at read time per ADR 0001).

#### 5.4 Secret + public — key-signing workflow

Stored: Bob's secret key.
Update: Bob's public key returned from Carol after she signed his
UID at a key signing party.

Dispatch: `(true, false)` → `merge_secret_key` with
`SecretMergeSource::Public`. The `src_pub_subkeys` loop walks the
public subkeys from Carol's returned key. For each, we look up the
FP:

- If it matches one of our `orig.secret_subkeys`, merge sigs into that
  secret subkey (preserves the secret packet, adds any new binding/
  revocation sigs).
- Else if it matches one of our `orig.public_subkeys`, merge sigs
  there.
- Else push to `public_subkeys`.

Carol's third-party certification on the UID is absorbed via
`merge_details`. Bob's secret subkeys never move. Result: a secret
key with Carol's attestation attached.

Before this ADR: this also silently dropped Bob's secret material.

#### 5.5 Fingerprint mismatch — refused

Stored: key `FP=ABCD…`.
Update: key `FP=DEAD…`.

```
Error::InvalidInput("Key fingerprints do not match: ABCD… vs DEAD…")
```

No override. If the caller genuinely wants to add DEAD… to the store,
they should `import_key(update_data)` directly.

#### 5.6 Tampered secret subkey — rejected with warning

Stored: Alice's secret key `FP=ABCD…`.
Update: a crafted secret key that advertises Alice's primary (FP
ABCD…) but smuggles in a secret subkey `K_bad` whose binding
signature was made by some *other* primary `DEAD…`. Rpgp accepts this
at parse time because the signature packet is well-formed.

Dispatch: `(true, true)` → the `K_bad` entry falls into the
new-subkey else-branch. `K_bad.verify_bindings(&alice_primary_pub)`
fails (the sig was made by DEAD…, not ABCD…). Stderr gets:

```
Warning: dropping secret subkey <K_bad FP> with invalid binding: …
```

K_bad is not inserted. Alice's legitimate subkeys remain untouched.

#### 5.7 Demoted-then-promoted subkey — prior signatures preserved

Stored: Bob's secret key. K1 is in `public_subkeys` carrying both its
original binding signature and a subkey revocation signature Bob
issued last month (but the secret packet is absent — for example,
this key was produced earlier via
`gpg --export-secret-subkeys` with K1 excluded).

Update: Bob's full secret key from a backup, with K1 on the secret
side. K1's secret subkey carries a freshly-regenerated binding sig
(different bytes from the original) and no revocation signature.

Dispatch: `(true, true)` → `merge_secret_key` with
`SecretMergeSource::Secret`.

- K1 is not in `orig.secret_subkeys` → else-branch.
- `verify_bindings(&primary_pub)` passes — the incoming binding sig
  is legitimate.
- Preservation splice: collect K1's signatures from
  `orig.public_subkeys` (original binding + revocation), merge them
  into `sk_update.signatures` via `merge_signatures` (dedups by
  signature bytes).
- `retain()` removes K1 from `orig.public_subkeys`.
- `push()` adds the fully-signed K1 to `orig.secret_subkeys`.

Result: K1 on the secret side carrying the new binding sig AND the
original binding sig AND the revocation sig. Whoever later evaluates
K1's validity (via ADR 0001's latest-self-sig-wins policy) will see
all three and act on the revocation — exactly as they would have
before the secret promotion.

Without the preservation splice, the original binding sig and the
revocation would both be silently lost, leaving Bob's keystore
claiming K1 was an active, just-issued subkey.

### 6. Return type

`merge_keys` returns `Result<Zeroizing<Vec<u8>>>`. Public-only output
is wrapped too (for type uniformity; the zeroing is cheap and
harmless). This matches the trajectory of commit `1644d9f`
("security: apply zeroize to secret key material and card upload
paths"). `Zeroizing<Vec<u8>>` derefs to `&[u8]`, so existing call
sites that pass the result into `import_key` or compare against
other byte slices keep working.

## Consequences

### Positive

- The reported bug (`tcli --list-keys` shows `pub` after importing a
  `.sec` file) is fixed end-to-end. Secret material survives every
  merge that involves at least one secret-bearing input.
- The key-signing workflow works without any user-facing knob.
- Subkey injection attacks via crafted secret-key updates are
  blocked at the merge layer, not only at a hypothetical downstream
  `verify_bindings()` call that no current consumer makes.
- FP mismatch is unconditionally rejected — safer default than the
  previous `force=true` escape hatch.
- Secret-bearing output is zeroized on drop. `merge_keys` now fits
  the codebase's secret-handling idiom.

### Negative

- Breaking public API change: the `force: bool` parameter is gone and
  the return type changed from `Vec<u8>` to `Zeroizing<Vec<u8>>`.
  Requires a minor-version bump of `wecanencrypt` before publishing.
- Binding verification costs one or more signature verifications per
  newly-absorbed secret subkey. Normal merges (matching fingerprints
  all around) incur no extra verification work; the cost is paid only
  when new secret subkeys arrive.
- Third-party subkey revocation signatures with issuers other than
  the primary will fail `verify_bindings`. In the current codebase
  this is acceptable — third-party subkey revocations are vanishingly
  rare outside explicit revocation-key workflows, which we do not
  support today.

## Alternatives Considered

### Keep a separate `merge_keys_preserving_secrets` function

This was the initial plan, mirroring Sequoia's split API. Rejected
because (a) every in-tree caller wants secret preservation when
possible, and (b) a two-function API creates a footgun: callers can
forget and accidentally strip secrets by picking the wrong one. A
keyserver-style consumer that wants strictly public output can call
`SignedPublicKey`'s parsing path directly or post-process the merge
result with `to_public_key()`; the underlying parse is cheap.

### Keep `force` with new meaning "allow unsafe merges"

Proposed at one point as a gate on `secret + public` merges (i.e.,
refuse by default, opt in with `force`). Rejected when we realised
this would block the key-signing workflow (third-party certifications
returning on a public key), which is the most common `secret +
public` case and is entirely safe because the merge is secret-aware.

### Reject the whole merge on any binding-verification failure

Instead of dropping the offending subkey and warning, fail the entire
call with an error. Rejected because a single tampered subkey in an
otherwise-legitimate update would block the user from receiving new
third-party certs and legitimate updates. Dropping the bad subkey
matches GnuPG's general behaviour (`gpg --import` silently drops
packets it cannot canonicalise). The warning surfaces the issue
without denying service.

### Verify *all* subkey bindings at merge time, not just newly-
promoted ones

Attractive but changes the defence-in-depth model across the whole
library. Existing subkeys already in the keystore have not been
verified either (no code path calls `verify_bindings()`), so blocking
them at merge time would break on any previously stored data that
happens to fail verification under a stricter policy. Tracked as
follow-up: a systematic `verify_bindings()` pass across
parsing/merging/reading should be its own ADR.

### Return `Vec<u8>` to keep the API stable

Keeps the signature unchanged but means secret-bearing bytes would
sit unzeroed in the caller's allocator until reuse. Incompatible with
the project's stated posture (1644d9f). The minor-version bump is the
acceptable cost.

### Drop public-side signatures during subkey promotion

The simpler implementation of promotion is just
`public_subkeys.retain(…); secret_subkeys.push(sk_update);` — two
lines, no signature accounting. Rejected because it silently discards
subkey revocation signatures, third-party subkey certifications, and
historical binding sigs that were attached to the public-form entry.
The worst case is loss of a revocation: a previously-revoked subkey
would look active again after a promotion. The extra ~10 lines that
splice `prior_sigs` into the incoming secret subkey (deduping via
signature bytes) close that hole.

## References

- RFC 9580 §10.1 "Transferable Public Keys" — concatenation grammar
  with no merge semantics defined
- Sequoia `Cert::merge_public` / `Cert::merge_public_and_secret` —
  <https://docs.rs/sequoia-openpgp/latest/sequoia_openpgp/cert/struct.Cert.html>
- rpgpie `src/merge.rs::Certificate::merge` / `Tsk::merge`
- GnuPG `g10/import.c::merge_keysig` / `merge_sigs`
- Hagrid (keys.openpgp.org) `database/src/lib.rs::merge` — always
  `merge_public`, strict no-secret-material policy
- ADR 0001: RFC 4880 "latest self-signature wins" for key flags
- Commit `1644d9f`: "security: apply zeroize to secret key material
  and card upload paths"
- Reported issue: `tcli --import KEY.sec` showing `pub` in
  `tcli --list-keys` after re-import
