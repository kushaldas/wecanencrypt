# ADR 0005: Fedora `crypto-policies` Integration

## Status

Accepted

## Date

2026-05-10

## Context

`wecanencrypt` wraps `rpgp` (the `pgp` crate). On Fedora, system-
wide cryptographic algorithm policy is configured by
`update-crypto-policies --set {DEFAULT,LEGACY,FUTURE,FIPS}`, which
writes per-backend templates under `/etc/crypto-policies/back-ends/`.
The relevant template for OpenPGP libraries is
`sequoia.config` — a TOML document declaring per-algorithm
allow/deny dispositions for hash, symmetric, AEAD, and asymmetric
primitives.

Before this ADR, `wecanencrypt` had **no integration with
crypto-policies**. Every RFC 4880 / 9580 legacy algorithm (MD5,
SHA-1, DES/3DES, IDEA, Blowfish, CAST5, RSA-1024) was
unconditionally enabled at the library level. Running
`update-crypto-policies --set DEFAULT` had no effect on
`wecanencrypt`-using applications: a tumpa-cli user on a
DEFAULT-strict host could still verify a SHA-1 signature, decrypt
an IDEA-SKESK-encrypted message, or load an RSA-1024 key, all
without warning.

`rpgp` upstream does not currently expose a `Policy` trait or
configuration seam at all. The two narrow self-hardenings present
in `rpgp` 0.19.0 (S2K v6 weak-hash rejection and the PQC-mandated
≥256-bit hash for ML-DSA / Ed25519) are not user-configurable.
The closest reference implementations are:

- **Sequoia.** `sequoia-openpgp::policy::StandardPolicy` exposes
  a configurable policy with cutoff-date semantics. The companion
  crate `sequoia-policy-config` parses `sequoia.config` into a
  `StandardPolicy`. `rpm-sequoia` consumes both.
- **GnuPG.** Hard-coded allow/deny lists in `g10/main.h`; uses the
  `gpg.conf` `personal-{cipher,digest}-preferences` directives for
  per-user overrides, but no system-wide policy file.

A prior attempt (rpgp Phase A) added the policy logic *inside* the
rpgp tree as a Fedora downstream patch. That approach was reverted
in favour of putting the enforcement one layer up, in
`wecanencrypt` itself, because:

1. `rpgp` is upstream code we do not own. A carried patch creates
   ongoing maintenance cost across rpgp releases and keeps the
   Fedora `rust-pgp` package divergent from crates.io.
2. `wecanencrypt` is the single library we (and tumpa-cli, Tumpa
   Mail) actually depend on. Putting policy at this layer reaches
   every consumer that already routes through `wecanencrypt`.
3. The most security-critical operations (verify, decrypt, key
   parse) all flow through `wecanencrypt`'s public API. Inbound
   message-level algorithm declarations are visible at this layer
   before any rpgp internal crypto runs.

This is a deliberate **perimeter-only** model. Crypto operations
entirely inside rpgp internals (e.g. self-cert verification during
`Message::decrypt`'s subkey traversal) are not gated by this ADR.
Defence in depth would require an upstream rpgp `Policy` trait,
which is out of scope here.

The rest of this document describes the policy-language semantics,
the hook map, the runtime configuration, the testing strategy, and
the four self-review findings that fell out of the implementation.

## Decision

We integrate the system crypto policy at every public-API entry
point in `wecanencrypt` that consumes a caller-supplied or
caller-derived algorithm. The policy is consulted *before* any
key material is touched or any cryptographic primitive is run.
Banned algorithms surface as `Error::PolicyViolation { what }`.

### Lookup precedence (first match wins)

Implemented in `crypto_policy::load_from_environment` and called
once per process via a `RwLock<Option<Arc<dyn Policy>>>`-backed
lazy initialiser:

1. **`WECANENCRYPT_CRYPTO_POLICY` env var.**
   - Value `off` (case-insensitive) → `NullPolicy` (accept
     everything). Documented escape hatch.
   - Other non-empty value → treat as a path to a TOML config
     file. Parse and install. On parse failure: emit
     `log::warn!` and fall through (see *F2 fix* below).
2. **`SEQUOIA_CRYPTO_POLICY` env var** → file path. Same
   parse-or-fall-through behaviour. Honoured for ecosystem
   parity with `rpm-sequoia`.
3. **`/etc/crypto-policies/back-ends/sequoia.config`** — the
   Fedora default location.
4. None of the above produces a parseable file → `NullPolicy`
   fallback. Keeps the library safe to ship on hosts without
   `crypto-policies` (macOS, BSD, dev containers).

### Policy language

The TOML format matches what Fedora's `update-crypto-policies`
emits. Four sections:

```toml
[hash_algorithms]
md5.collision_resistance = "never"
md5.second_preimage_resistance = "never"
sha1.collision_resistance = "never"
sha1.second_preimage_resistance = "never"
sha256.collision_resistance = "always"
sha256.second_preimage_resistance = "always"
default_disposition = "never"

[symmetric_algorithms]
idea = "never"
tripledes = "never"
aes256 = "always"
default_disposition = "never"

[aead_algorithms]
default_disposition = "always"

[asymmetric_algorithms]
rsa1024 = "never"
rsa2048 = "always"
rsa4096 = "always"
cv25519 = "always"
ignore_invalid = [ "x25519", "ed25519", "mlkem768-x25519" ]
```

Recognised disposition values:
- `"always"` → permit
- `"never"` → reject
- TOML datetime → cutoff. The algorithm is permitted iff the
  current time is *before* the cutoff. Parsed via `chrono` from
  RFC-3339 or naive-local form.

Hash-algorithm entries may be a single disposition string OR a
sub-table with `collision_resistance` and
`second_preimage_resistance` keys. The hash is rejected if either
resistance attribute resolves to `Never`. (This matches Sequoia's
interpretation: a hash needs both properties to be cryptographically
useful.)

`default_disposition` per section sets the disposition for any
algorithm name not explicitly listed. `ignore_invalid` is a
forward-compat hint Fedora uses to mark algorithm names newer
parsers should silently accept; we treat it as a no-op.

### Algorithm name → rpgp enum mapping

| Section | TOML name | rpgp enum |
|---|---|---|
| hash | `md5` | `HashAlgorithm::Md5` |
| hash | `sha1` | `HashAlgorithm::Sha1` |
| hash | `ripemd160` | `HashAlgorithm::Ripemd160` |
| hash | `sha224` | `HashAlgorithm::Sha224` |
| hash | `sha256` | `HashAlgorithm::Sha256` |
| hash | `sha384` | `HashAlgorithm::Sha384` |
| hash | `sha512` | `HashAlgorithm::Sha512` |
| hash | `sha3-256`, `sha3_256` | `HashAlgorithm::Sha3_256` |
| hash | `sha3-512`, `sha3_512` | `HashAlgorithm::Sha3_512` |
| symmetric | `idea`, `tripledes`/`3des`, `cast5`, `blowfish`, `aes128/192/256`, `twofish`, `camellia128/192/256` | `SymmetricKeyAlgorithm::*` |
| aead | `eax`, `ocb`, `gcm` | `AeadAlgorithm::*` |
| asym (bit-suffix) | `rsa1024`/`rsa2048`/...  | `PublicKeyAlgorithm::{RSA, RSAEncrypt, RSASign}` + `min_rsa_bits` floor |
| asym (bit-suffix) | `dsa1024`/`dsa2048`/... | `PublicKeyAlgorithm::DSA` + `min_dsa_bits` floor |
| asym (bare) | `nistp256`/`nistp384`/`nistp521`, `brainpoolp{256,384,512}` | `PublicKeyAlgorithm::{ECDSA, ECDH}` |
| asym (bare) | `cv25519` | `PublicKeyAlgorithm::{EdDSALegacy, ECDH}` |
| asym (bare) | `x25519` | `PublicKeyAlgorithm::X25519` |
| asym (bare) | `x448` | `PublicKeyAlgorithm::X448` |
| asym (bare) | `ed25519` | `PublicKeyAlgorithm::Ed25519` |
| asym (bare) | `ed448` | `PublicKeyAlgorithm::Ed448` |
| asym (bare) | `eddsa` | `PublicKeyAlgorithm::EdDSALegacy` |
| asym (bare) | `elgamal` | `PublicKeyAlgorithm::Elgamal` |

Unknown names parse to `None` and are silently ignored — the
enclosing section's `default_disposition` then applies. Fedora's
`ignore_invalid = [...]` lists ML-KEM / ML-DSA / SLH-DSA placeholder
names so older parsers don't error on a newer template.

### Hook map

Every public surface that consumes an algorithm declared in a
parsed packet, or that picks an algorithm internally for a sign or
encrypt, calls into `crypto_policy::current()` before proceeding.

| Surface | File | Hook |
|---|---|---|
| `parse_public_key` / `parse_secret_key` | `src/internal/helpers.rs` | `check_certificate(&cert)` walks primary, every direct/UID/UA/subkey signature, and every subkey's pubkey + bit-length. |
| `verify_bytes_detached` | `src/verify.rs` | `check_signature(&sig.signature)` on the parsed `DetachedSignature`. |
| `verify_cleartext` (called by `verify_bytes`) | `src/verify.rs` | Iterate `msg.signatures()` on the parsed `CleartextSignedMessage`. |
| `verify_inline_signed` (called by `verify_bytes`) | `src/verify.rs` | If the message is `Message::Signed`, iterate `reader.signatures()`. |
| `extract_cleartext`, `extract_inline_signed` | `src/verify.rs` | Same patterns, gates before extraction. |
| `decrypt_with_key` (called by `decrypt_bytes` / `decrypt_bytes_legacy`) | `src/decrypt.rs` | Walk `Message::Encrypted { esk, .. }`: for each PKESK, gate `algorithm()` (pubkey); for each SKESK, gate `sym_algorithm()` and `s2k().hash_alg()`. |
| `decrypt_and_verify` | `src/decrypt.rs` | Same ESK walk + gate `cfg.hash_alg` for every inner OnePass signature before attempting verification against a resolved signer. |
| `encrypt_bytes_to_multiple_with_algo` and SEIPDv2 sibling | `src/encrypt.rs` | `validate_sym_algo(sym)` consults the policy at the top, before any builder construction. Default-algo wrappers (`encrypt_bytes`, `encrypt_bytes_to_multiple`) flow through this. |
| `sign_and_encrypt_to_multiple` | `src/encrypt.rs` | Gate the hash picked by `select_hash_for_params` before signing. |
| `sign_bytes_internal` (binary + cleartext) | `src/sign.rs` | Gate the hash picked by `select_hash_for_params` for the binary-sig path. (Cleartext signing uses rpgp's internal default-hash selection — see *Out of scope*.) |
| `sign_bytes_detached_with_hash` | `src/sign.rs` | Gate caller-supplied hash at function entry. |
| `sign_bytes_detached_impl` | `src/sign.rs` | Gate the resolved hash (override or default) before each `DetachedSignature::sign_binary_data`. |

### Strict cert-walk

`check_certificate` walks every signature attached to a parsed
certificate:

1. Primary key: gate `algorithm()` and bit length (RSA/DSA only).
2. `cert.details.revocation_signatures` — every key revocation
   signature's hash.
3. `cert.details.direct_signatures` — every direct-key signature's
   hash.
4. `cert.details.users[*].signatures` — every UID self-cert and
   third-party certification's hash.
5. `cert.details.user_attributes[*].signatures` — every
   user-attribute (image) signature's hash.
6. `cert.public_subkeys[*]` — gate the subkey's `algorithm()` and
   bit length, then walk every binding/back-sig hash.

Any banned algorithm at any point in this walk causes the entire
key load to fail with `Error::PolicyViolation`. **There is no
soft-fail / per-component "skip the bad UID, keep the rest" mode.**
This is a deliberate choice (see *Strict vs lenient*).

### Outbound enforcement

- Caller-supplied algorithm parameters
  (`encrypt_bytes_to_multiple_with_algo`,
  `encrypt_bytes_to_multiple_seipd_v2`,
  `sign_bytes_detached_with_hash`) are gated at function entry and
  return `Error::PolicyViolation` if the caller picked a banned
  algo. Hard reject — no silent substitution.
- Default-algo paths (`encrypt_bytes`, `sign_bytes`,
  `sign_bytes_cleartext`, `sign_and_encrypt_to_multiple`) gate the
  algorithms they internally pick. Under every shipping Fedora
  policy (DEFAULT/LEGACY/FUTURE/FIPS), the rpgp defaults
  (AES-256, OCB, SHA-256) are on the allow-list; the gate is
  defence-in-depth against future policy templates that might tighten.
- `CleartextSignedMessage::sign` hash selection happens inside
  rpgp; we cannot gate it from this layer. Documented as out of
  scope.

### Public API surface

Minimal. `crypto_policy::*` types — `Policy` trait,
`StandardPolicy`, `NullPolicy`, `Disposition` — are all
`pub(crate)`. No public callable to install a custom policy at
runtime. Two test-only escape hatches exposed under
`#[cfg(any(test, feature = "test-helpers"))]`:

- `wecanencrypt::__test_disable_policy()` — install `NullPolicy`,
  equivalent to `WECANENCRYPT_CRYPTO_POLICY=off`.
- `wecanencrypt::__test_install_policy_from_toml(toml: &str)` —
  parse + install a hand-built strict policy.

Both are `#[doc(hidden)]` and gated behind the `test-helpers`
Cargo feature so production builds cannot reach them. Run
integration tests with `cargo test --features test-helpers`. Three
integration test binaries (`fixture_tests`, `keystore_tests`,
`policy_tests`) carry `required-features = ["test-helpers"]` and
silently skip without the feature.

### Error reporting

A new variant `Error::PolicyViolation { what: String }` carries a
human-readable description of the rejected algorithm. Helper
constructors:

- `Error::policy_hash(HashAlgorithm)`
- `Error::policy_sym(SymmetricKeyAlgorithm)`
- `Error::policy_aead(AeadAlgorithm, SymmetricKeyAlgorithm)`
  *(reserved for future call sites)*
- `Error::policy_pubkey(PublicKeyAlgorithm, Option<u32>)`

Callers that want to give an end-user-friendly message can match
the variant; tumpa-cli's CLI surface translates "hash algorithm
Sha1 blocked by system crypto policy" into a one-line error.

## Why these specific design choices

### Hand-written TOML parser, not `sequoia-policy-config`

`sequoia-policy-config 0.8.1` (the version Fedora ships) depends
on `sequoia-openpgp 2.1`. Pulling that in transitively brings the
entire Sequoia stack — `nettle`/`openssl` native deps, ~100+
transitive crates, multi-minute clean builds. `wecanencrypt`
intentionally has zero Sequoia deps because rpgp is positioned as
a lean independent alternative; we keep that property here.

The trade-off: a ~150 LoC TOML walker (`StandardPolicy::from_toml_str`
plus name mappers) instead of bug-for-bug parity with rpm-sequoia.
The two parsers should converge on every config Fedora's
`update-crypto-policies` produces today; if a future template uses
TOML features we don't handle, the parser falls through to the
section's `default_disposition` (typically `"never"` for hash and
symmetric, `"always"` for aead) — fail-secure for the security-
sensitive sections.

### Implicit + global, not explicit `&dyn Policy` threading

A `Policy` trait threaded through every verify/decrypt/sign call
(the Sequoia pattern) was rejected in favour of an implicit global
because:

1. tumpa-cli, Tumpa Mail XPC, and other consumers already exist
   and use the current API. An explicit threading change is a
   breaking change for every caller.
2. The user (admin) configures the policy once, system-wide, via
   `update-crypto-policies`. Per-call overrides are not a
   real-world need.
3. The audit cost of "look at the global init" is one site
   (`crypto_policy::load_from_environment`) rather than dozens of
   `&policy` parameters.

The trade-off: callers cannot install a custom policy from
production code. They can only override via env vars or via
`update-crypto-policies --set <profile>`. Test-only override goes
through the feature-gated escape hatches.

### `RwLock<Option<Arc<dyn Policy>>>`, not `OnceLock`

`OnceLock` would be the obvious choice for a one-shot lazy init,
but the integration tests need to *replace* the policy mid-process
to exercise different denial paths. `RwLock` allows tests to swap
the value via `__test_install_policy_from_toml`, while production
read-side performance is identical (a single read-lock acquire +
`Arc::clone`).

The double-checked locking pattern in `current()` is correct:
two threads hitting first-call simultaneously may both attempt
`load_from_environment()`, but only one wins the write lock and
the other observes the cached value on its second check. No
data race; one extra parse on cold-start in the worst case.

### Strict cert-walk, not lenient per-component filter

When the active policy bans SHA-1, a fresh modern-key load
under DEFAULT succeeds (Curve25519 self-signs use SHA-256). A
legacy key whose primary's UID self-signature is SHA-1 fails to
load entirely.

The lenient alternative — load the cert but mark UIDs / subkeys
whose binding signatures use a banned hash as "unusable" — was
considered and rejected. Tumpa-cli's expected use case is freshly
minted modern keys generated by the application itself, not
historical SHA-1-self-signed keys imported from older PGP
ecosystems. The simplicity of strict mode (one parse → either ok
or error, no per-component validity tracking propagating through
every API surface) outweighs the cost of refusing legacy keys.

Users who genuinely need to load a legacy key have two documented
escape hatches:

```bash
sudo update-crypto-policies --set LEGACY  # SHA-1 allowed system-wide
WECANENCRYPT_CRYPTO_POLICY=off cargo run  # process-local opt-out
```

### Hard reject on outbound, not silent substitution

Calling `encrypt_bytes_to_multiple_with_algo(..., IDEA)` under a
policy that bans IDEA returns `Error::PolicyViolation`, not a
silent fallback to AES-256. The caller chose the algorithm
explicitly; honouring that signal by failing loudly avoids the
class of bug where caller-pinned cryptography silently changes
under their feet.

Default-algo paths (`encrypt_bytes`) don't take an algorithm
parameter, so there's no pinning to honour. They internally pick a
default and gate it.

### NullPolicy fallback on no-config hosts

Hosts without `/etc/crypto-policies/back-ends/sequoia.config`
(macOS, BSD, dev containers) load `NullPolicy` rather than failing
or applying a hard-coded baseline. Rationale: the library should
be usable cross-platform without any setup, and applying a
unilateral "modern baseline" would silently redefine
non-Fedora-host behaviour in a way the user didn't ask for.

## Self-review findings

Four issues fell out of the post-implementation security review,
all addressed before this ADR was finalised.

### F1 (HIGH) RSA bit-floor was order-dependent

The original `apply_asym_entry` ratcheted `min_rsa_bits` upward on
every `Never` bit-suffix entry AND tracked the lowest `Always`
entry separately. In `toml::Table` iteration order (alphabetical:
`rsa1024` before `rsa2048` before `rsa4096`), processing
`rsa1024 = "never"` first set `min_rsa_bits = 1025`; processing
`rsa2048 = "always"` later only updated min if the new value was
*lower*, so min stayed at 1025. A 1500-bit RSA key passed the
gate under Fedora DEFAULT despite being intended-banned.

**Fix.** Bit-suffix `Never` entries are now no-ops. The floor is
exclusively the lowest `Always` entry. This matches the semantics
of every shipping Fedora template
(DEFAULT/LEGACY/FIPS/FUTURE) and removes the order dependency.

Regression test
`rsa_bits_between_never_and_always_rejected` asserts RSA-1500 and
RSA-2047 are rejected under `rsa1024 = "never", rsa2048 = "always"`.
The test fails against the pre-fix implementation.

### F2 (MEDIUM) Silent fallthrough on env-var-pointed parse failure

If an admin set `WECANENCRYPT_CRYPTO_POLICY=/etc/strict.toml`
and that file became unreadable (ENOSPC, ACL change, container
volume issue), `load_from_environment` silently fell through to
the next priority — eventually landing on `NullPolicy`. The
admin's explicit policy-strict signal got silently overridden by
a fail-open default.

**Fix.** Both env-var paths emit
`log::warn!(target: "wecanencrypt::crypto_policy", ...)` with the
configured path and the parse error before falling through.
Operators running with `RUST_LOG=warn` (or any level above) see
the downgrade in their logs.

The library is still safe to ship cross-platform: hosts without
the file present produce no warning (unlike "fail closed", which
would break tests on macOS / BSD).

### F3 (MEDIUM) Test escape hatches reachable from production

`__test_disable_policy` and `__test_install_policy_from_toml` were
originally `#[doc(hidden)] pub` — reachable from any consumer's
code, including a transitive dep. A malicious or buggy crate in
the build tree could call `wecanencrypt::__test_disable_policy()`
at startup and silently disable enforcement library-wide.

**Fix.** Both functions are now gated `#[cfg(any(test, feature =
"test-helpers"))]`. The `test-helpers` feature is opt-in (off by
default). Three integration test binaries (`fixture_tests`,
`keystore_tests`, `policy_tests`) carry `required-features =
["test-helpers"]` and silently skip without the flag. Production
builds (`cargo build`, `cargo test --lib`, every downstream
consumer's default build) cannot reach the bypass.

### F4 (LOW) Default-algo sign paths picked unchecked hashes

`sign_bytes_internal` and `sign_bytes_detached_impl` selected a
hash via `select_hash_for_params(public_params)` and then signed
without consulting the policy on the resulting hash. Under
hypothetical FUTURE policies that ban SHA-256 in favour of
SHA-384/512, these paths would silently produce SHA-256
signatures the same host's verify path would reject.

**Fix.** All five default-algo sign sites
(`sign_bytes_detached_impl` × 3, `sign_bytes_internal` × 2,
`sign_and_encrypt_to_multiple` × 1) now call
`crypto_policy::current().hash_algorithm(hash_alg)?;` after
selection and before signing. `CleartextSignedMessage::sign`
remains uncovered (rpgp picks the hash internally; documented).

## Consequences

### Positive

- `update-crypto-policies --set DEFAULT/LEGACY/FUTURE/FIPS` now
  has the expected effect on every wecanencrypt-using application.
- Fresh Curve25519 / Ed25519 keys minted by `create_key_simple`
  load and operate cleanly under all four shipping Fedora profiles.
- Outbound `_with_algo` paths fail closed if a caller pins a
  banned algorithm — no silent downgrade.
- The escape hatches (`WECANENCRYPT_CRYPTO_POLICY=off`, the
  `test-helpers` Cargo feature) provide explicit, auditable
  bypass for tests and emergency mitigation.
- Cross-platform behaviour preserved: hosts without
  `/etc/crypto-policies` see no behavioural change.
- Zero new Sequoia transitive deps. Lean dep graph preserved.

### Negative

- Legacy SHA-1-self-signed keys imported from older PGP
  ecosystems do not load under DEFAULT. Documented; opt-out via
  `WECANENCRYPT_CRYPTO_POLICY=off` or
  `update-crypto-policies --set LEGACY`.
- `cargo test` without `--features test-helpers` silently skips
  three integration test binaries. Documented in CHANGELOG and
  README; `cargo test --features test-helpers` is the canonical
  invocation for full local runs.
- Perimeter-only enforcement leaves a number of paths uncovered
  (see *Out of scope*). Defence-in-depth requires future upstream
  rpgp work.
- The TOML parser is hand-written and may diverge from
  `sequoia-policy-config` on TOML features we don't model. Real-
  world Fedora templates use only `"always"` / `"never"` strings
  and section-level `default_disposition`, all of which are
  covered.

### Out of scope (perimeter limitations)

These gaps are accepted, not bugs:

1. **Inner crypto inside rpgp.** When `Message::decrypt` traverses
   the secret key to find the right subkey, it re-verifies subkey
   binding signatures internally. If a binding signature uses a
   banned hash, our `parse_secret_key` cert-walk catches it; if
   the cert was loaded under `NullPolicy` and the policy was
   later tightened, those internal verifications still proceed.
   In normal operation (policy set once at startup) this is not
   reachable.

2. **PKESK session-key symmetric algorithm.** A PKESK packet
   carries an encrypted session key whose symmetric algorithm is
   embedded in the encrypted payload. The algorithm is only
   visible *after* the recipient's secret key decrypts the PKESK.
   Our gate at the decrypt site checks the PKESK's public-key
   algorithm but not the eventual session-key symmetric algorithm.
   A SKESK by contrast carries the symmetric algorithm in plain;
   it is gated.

3. **AEAD packet-body algorithm.** SEIPDv2 messages declare their
   AEAD algorithm in the encrypted-data packet header. Reaching
   that field requires consuming the `Edata` reader before
   `Message::decrypt` runs, which is awkward. Fedora's
   `[aead_algorithms]` section is empty under all current
   profiles, so this is not a real-world concern. Reopen if a
   future template populates it with `"never"` entries.

4. **Public-key bit-size enforcement at sign/verify call sites.**
   `min_rsa_bits` / `min_dsa_bits` are checked at parse time
   (where the bit length is reachable from `public_params`) but
   not re-checked at every sign/verify call. A key that passed
   parse under a permissive policy would still be usable if the
   policy was later tightened.

5. **`CleartextSignedMessage::sign` hash selection.** rpgp picks
   the hash internally; the hash isn't visible to the wecanencrypt
   layer until after signing. Default is SHA-256 which every
   shipping Fedora policy permits.

6. **`create_key_*` outbound algorithm choice.** Fresh-key
   generation doesn't consult the policy on the algorithms it
   picks. Currently `Cv25519` (the default cipher suite) uses
   EdDSALegacy + ECDH, which DEFAULT permits. Generating a key
   that would later fail to parse under the same policy is
   self-correcting (parse fails at load-time) but suboptimal.
   Track separately if this becomes a real issue.

## Implementation summary

```
src/crypto_policy.rs              new (~700 LoC)
src/error.rs                      +PolicyViolation variant + helpers
src/lib.rs                        +mod crypto_policy + gated re-exports
src/internal/helpers.rs           +cert-walk on parse_secret_key/public_key
src/verify.rs                     +signature-hash gates on every verify path
src/decrypt.rs                    +PKESK/SKESK walk + inner-sig gate
src/encrypt.rs                    validate_sym_algo consults policy +
                                  sign_and_encrypt hash gate
src/sign.rs                       +hash gates on every default-hash path
tests/policy_tests.rs             new — 6 integration tests
tests/fixture_tests.rs            +__test_disable_policy at legacy fixtures
tests/keystore_tests.rs           +__test_disable_policy at legacy fixtures
Cargo.toml                        version 0.16.0, toml = "1",
                                  test-helpers feature, [[test]] gates
CHANGELOG.md, README.md           release notes + Configuration section
```

## Verification

Tested against `cargo test` under the developer's Fedora 44 host
(active policy: DEFAULT) on 2026-05-09:

| Mode | Result |
|---|---|
| `cargo test` (production-default; escape hatches not compiled) | 202 passed, 9 ignored, 0 failed across 9 binaries; 3 binaries silently skipped via `required-features` |
| `cargo test --features test-helpers` | 334 passed, 9 ignored, 0 failed across 12 binaries |
| `cargo build` (production default) | clean, 0 warnings |

The new module-level unit test
`rsa_bits_between_never_and_always_rejected` is the F1 regression
guard. `tests/policy_tests.rs` covers the six high-value scenarios:
modern-key load under strict, sign-with-SHA1 outbound rejection,
default-hash verify under strict, IDEA-encrypt outbound rejection,
AES-256 round-trip under strict, NullPolicy regression baseline.

## Related

- ADR 0001 — Latest self-signature wins. Orthogonal: that ADR is
  about ordering self-sigs; this one gates the algorithms those
  sigs use.
- ADR 0004 — Verified revocation signatures. Orthogonal: that ADR
  cryptographically validates revocation packets before honouring
  them; this one gates the hash they use.
- Reverted approach: rpgp Phase A patch
  (`fedora-crypto-policy-phase-a` branch in `/home/kdas/code/rpgp`,
  deleted 2026-05-09). Documented in
  `~/.claude/plans/wecanencrypt-crypto-policy.md`.
- Future upstream rpgp work: a `Policy` trait threaded through
  every verify/decrypt path. Tracked in
  `~/.claude/plans/make-a-plan-to-bright-penguin.md`. Lands at
  rpgp 0.20+; would let wecanencrypt close the inner-crypto blind
  spot without carrying any rpgp-side patch.
