# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.16.0] — 2026-05-10

Fedora `crypto-policies` integration. Verify, decrypt, encrypt,
sign, and key-parse paths now consult
`/etc/crypto-policies/back-ends/sequoia.config` (or an override
config file) and refuse algorithms that
`update-crypto-policies --set DEFAULT/LEGACY/FUTURE/FIPS` disallows.

### Added

- New `Error::PolicyViolation { what: String }` variant returned when
  an operation hits an algorithm the active policy bans.
- Lookup precedence for the active policy:
  1. `WECANENCRYPT_CRYPTO_POLICY` env var
     - Value `off` (case-insensitive) → no enforcement.
     - Otherwise → file path to a sequoia.config-style TOML file.
  2. `SEQUOIA_CRYPTO_POLICY` env var → file path.
  3. `/etc/crypto-policies/back-ends/sequoia.config` (Fedora default
     location).
  4. None of the above parse → accept-everything fallback.
- Perimeter-only enforcement: gates message-level signature hashes,
  PKESK and SKESK packet algorithms (symmetric + S2K hash), and
  every signature attached to a parsed certificate (UID self-sigs,
  subkey bindings, third-party certs). Crypto operations entirely
  inside rpgp's internals (e.g. self-cert verification during a
  decrypt-with-key flow) are not gated.

### Changed

- `parse_key_bytes` / `parse_key_file` and the internal
  `parse_secret_key` / `parse_public_key` helpers now reject any
  certificate whose primary key, subkey, or any attached signature
  uses an algorithm the active policy bans. Under Fedora DEFAULT
  this means **legacy keys with SHA-1 self-signatures or 1024-bit
  RSA primaries fail to load**. The supported escape hatches are
  `WECANENCRYPT_CRYPTO_POLICY=off` or
  `update-crypto-policies --set LEGACY`.
- `encrypt_bytes_to_multiple_with_algo` /
  `encrypt_bytes_to_multiple_seipd_v2` and
  `sign_bytes_detached_with_hash` reject caller-supplied banned
  algorithms with `Error::PolicyViolation`. Default-algo paths
  (`encrypt_bytes`, `sign_bytes`, ...) keep working — rpgp's
  defaults (AES-256, OCB, SHA-256) are on every Fedora policy's
  allow-list.

### Dependencies

- Added `toml = "1"` for parsing the system policy file. Fedora
  ships `rust-toml-1.1.0`, so the `rust-wecanencrypt` RPM gains no
  new BuildRequires it doesn't already cover.

### Testing

- New Cargo feature `test-helpers` (off by default) gates the
  `__test_disable_policy` and `__test_install_policy_from_toml`
  escape hatches. Production builds cannot accidentally flip the
  active policy from any caller. Run the integration tests with
  `cargo test --features test-helpers`. The lib's own unit tests
  (`cargo test --lib`) work without the feature because they're
  compiled with `cfg(test)`.

## [0.15.0] — 2026-05-02

Pre-op passphrase verification primitive for daemons that broker
secrets into `wecanencrypt` (the tumpa-cli agent and Tumpa Mail XPC
service): a way to confirm a freshly-typed passphrase before
broadcasting it as cached, without spending a real sign or decrypt
round-trip.

### Added

- `verify_software_passphrase(secret_key, password)` — parses the
  secret-key bytes and runs `SignedSecretKey::primary_key.unlock`
  with a no-op closure. Returns `Ok(())` when the passphrase decrypts
  the primary secret packet; `Error::Parse` for non-OpenPGP input,
  `Error::Crypto` for a wrong passphrase or a corrupted key. The S2K
  KDF and secret-packet decryption do run — they're what proves the
  passphrase correct — but no signature is produced and no message
  data is decrypted.

## [0.14.2] — 2026-04-27

Mail-extension Phase 0: primitives the upcoming `Tumpa Mail.app` macOS
extension needs to handle PGP/MIME outgoing and incoming mail.

### Added

- `decrypt_and_verify(secret_key, ciphertext, password, resolve_signer)`
  — single-pass decrypt + inner-signature verify for sign-then-encrypt
  payloads. The `resolve_signer` closure receives uppercase-hex issuer
  ids (40-char fingerprints and/or 16-char key ids) and returns
  optional signer cert bytes. Result variants
  (`DecryptVerifySignature::Unsigned / Good / Bad / UnknownKey`) map
  cleanly to PGP/MIME UI states.
- `sign_bytes_detached_with_hash(secret_key, data, password, hash_algo)`
  — detached sign with optional hash override. Returns
  `DetachedSignOutput { armored, hash_algorithm }`. Callers building
  `multipart/signed` parts use `hash_algorithm` to fill the `micalg`
  parameter (RFC 3156).
- `sign_and_encrypt_to_multiple(signer_secret, signer_password,
  recipient_keys, plaintext, armor)` — single-pass sign-then-encrypt
  to one or more recipients. Auto-routes to SEIPDv1 (V4) or SEIPDv2
  (V6) recipients, matching `encrypt_bytes_to_multiple`.
- `HashAlgorithm` re-exported at the crate root.

### Notes

- `sign_bytes_detached` and `sign_bytes_detached_with_primary_key`
  delegate to `sign_bytes_detached_with_hash` with `hash_algo = None`;
  behavior unchanged.
- Detached signing does not normalize line endings — CRLF input is
  signed verbatim, as required by RFC 3156. Regression test added.

## [0.10.0] — 2026-04-16

First release since `0.9.0`. Major theme: make terminology unambiguous
and harden the key-merge logic so re-importing secret keys no longer
drops secret material.

Throughout this release, "certificate" as a synonym for an OpenPGP
key bundle has been replaced with "key". The term "certification" is
now reserved exclusively for the RFC 4880 signature type that certifies
a UID or subkey.

### Changed (breaking)

- Renamed public types and functions that used `certificate` / `cert`
  as a synonym for an OpenPGP key bundle:
  - `CertificateInfo` → `KeyInfo`.
  - `parse_cert_bytes` → `parse_key_bytes`; `parse_cert_file` →
    `parse_key_file`.
  - `KeyStore` methods: `import_cert` → `import_key`,
    `import_cert_file` → `import_key_file`, `export_cert` →
    `export_key`, `export_cert_armored` → `export_key_armored`,
    `get_cert_info` → `get_key_info`, `get_cert` → `get_key`,
    `delete_cert` → `delete_key`, `list_certs` → `list_keys`,
    `update_cert` → `update_key`.
  - Parameter names standardised: `cert_data` → `key_data`,
    `signer_cert` → `signer_key`, `recipient_cert(s)` →
    `recipient_key(s)`, `secret_cert` → `secret_key`, `public_cert`
    → `public_key`.
  - `Error::Parse` messages and `Error::MissingSecretKey` now say
    "Key" instead of "Certificate".
- `merge_keys` signature change:
  - Dropped the `force: bool` parameter; fingerprint mismatch is now
    always an `Error::InvalidInput`.
  - Return type changed from `Result<Vec<u8>>` to
    `Result<Zeroizing<Vec<u8>>>` so serialized secret bytes are
    scrubbed on drop. `Zeroizing<Vec<u8>>` derefs to `&[u8]`, so
    most existing callers work unchanged.
- Keystore SQLite schema bumped to **v3** (version code `20260416`):
  - Table `certificates` is renamed to `keys`.
  - Column `cert_data` is renamed to `key_data`.
  - Index `idx_certificates_is_secret` is replaced by
    `idx_keys_is_secret`.
  - Existing v1 / v2 keystores auto-migrate on open. Downgrade is
    one-way and requires manual SQL. Any legacy johnnycanencrypt
    `keys` table (and its `uid*` helpers) is dropped during
    migration — nothing in this codebase read it.

### Fixed

- `merge_keys` no longer drops secret key material when merging a
  secret key onto a stored public key, or when absorbing a new
  secret subkey whose public form was already present
  (commits `d791aa2`, `7a40d2b`).
- Preserve public-side subkey signatures (binding signatures,
  revocations, third-party certifications) during secret-subkey
  promotion, so revoked subkeys stay revoked after a merge.

### Security

- Unknown / tampered secret subkeys in an incoming secret-key update
  are rejected at merge time via
  `SignedSecretSubKey::verify_bindings` instead of being silently
  absorbed. A crafted update can no longer inject an arbitrary
  "secret subkey" under a primary fingerprint the victim already
  trusts.
- Secret-bearing output from `merge_keys` is zeroized on drop.

### Changed

- Bumped `rusqlite` from 0.32 → 0.39.
- Bumped `reqwest` from 0.12 → 0.13.

### Docs

- New ADR 0002 describing the secret-aware merge semantics
  (dispatch matrix, binding-verification policy, signature
  preservation splice, worked examples).
- README, features.md, tests.md, plan.md, SECURITY_AUDIT.md, and the
  internal differential-review documents updated to use "key"
  consistently; "certification" is reserved for the signature type.

## [0.9.0]

Prior release. See the git tag `v0.9.0` for history prior to this
changelog.
