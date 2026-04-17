# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
