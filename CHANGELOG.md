# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]


## [0.16.2] — 2026-06-22

A single data-integrity fix: re-importing an already-stored key no
longer destroys that key's hardware-card associations.

### Fixed

- `KeyStore::import_key` now updates an existing `keys` row in place
  (SQLite UPSERT, `ON CONFLICT(fingerprint) DO UPDATE`) instead of
  `INSERT OR REPLACE`. REPLACE deletes the conflicting row before
  re-inserting it, and with `PRAGMA foreign_keys = ON` that implicit
  delete fired `card_keys`' `ON DELETE CASCADE`, silently wiping a
  key's card linkage on every re-import. `user_ids` and `subkeys`
  were unaffected only because `import_key` explicitly rebuilds them;
  `card_keys` has no such rebuild and was the casualty. Reported as
  tumpa-cli#32 — `tcli card link` followed by
  `gpg --export | tcli import -` (even on the "Unchanged — no new
  data" path) lost the association and forced a re-link. Pinned with
  `test_reimport_preserves_card_keys`. See ADR 0005.

## [0.16.1] — 2026-05-25

Two outgoing-mail primitives the Tumpa Mail extension needs (Autocrypt
minimised public-key export + throw-keyid recipients for Bcc), plus a
new admin-authorized user-PIN reset for OpenPGP cards that works even
when PW1 is blocked.

### Added

- `export_public_for_autocrypt(key_data, addr)` -- minimised
  transferable-public-key export per the Autocrypt Level 1 spec
  (https://autocrypt.org/level1.html#openpgp-based-key-data). Returns
  binary OpenPGP bytes the caller base64-encodes into the `keydata=`
  attribute of the outbound `Autocrypt:` header. Accepts either public
  or secret key input. Output contains the primary key packet, exactly
  one User ID matching `addr` (case-insensitive on local and domain
  parts), the subkey packets with only their self-signatures, and the
  primary's own revocation/direct signatures. User Attribute packets,
  non-matching UIDs, and third-party certifications are stripped --
  Autocrypt is per-address and the header rides on every outbound mail,
  so size discipline matters and the social graph from third-party
  certs would leak otherwise. Errors with `Error::InvalidInput` if no
  UID matches `addr`. Round-trip, multi-UID strip, case-insensitive
  match, secret-to-public extraction, and third-party-cert strip
  pinned with unit tests.

- `sign_and_encrypt_to_multiple_with_hidden(signer_secret,
  signer_password, visible_recipients, hidden_recipients, plaintext,
  armor)` -- single-pass sign-then-encrypt where hidden recipients get
  a PKESK with the recipient key id blanked to the all-zero wildcard
  (RFC 4880 throw-keyid via rpgp's `encrypt_to_key_anonymous`).
  Visible recipients get a normal PKESK. All recipients receive the
  same ciphertext and decrypt to the same plaintext.
- `encrypt_bytes_to_multiple_with_hidden(visible_recipients,
  hidden_recipients, plaintext, armor)` -- the no-signer variant of
  the same primitive.
- `card::sign_and_encrypt_to_multiple_on_card_with_hidden(...)` --
  card-backed variant for OpenPGP smartcards (Nitrokey 3, YubiKey).

- `card::reset_user_pin(admin_pin, new_pin, ident)` -- admin-authorized
  user-PIN reset for OpenPGP cards. Issues `RESET RETRY COUNTER` (PW1,
  P1=02) after verifying the admin PIN in the same transaction, which
  both sets a new user PIN and resets the user-PIN error counter back
  to its limit. Use this whenever the user PIN is forgotten or blocked
  (retry counter == 0); unlike `change_user_pin`, it does not need the
  old user PIN and works even when PW1 is fully blocked. Implemented
  via openpgp-card's `to_admin_card(...).reset_user_pin(new)` so the
  admin verification and reset happen in a single APDU sequence, and
  available to both PCSC (`card-pcsc`) and external (`card-external`)
  card transports.

### Fixed

- `card::sign_and_encrypt_to_multiple_on_card_with_hidden` validates
  the recipient lists BEFORE any card I/O, so an empty-empty call or a
  V4/V6 cross-list split returns `Error::InvalidInput` /
  `Error::KeyVersionMismatch` cleanly instead of an opaque card-comm
  error when no card is plugged in.

### Notes

- At least one recipient (visible OR hidden) must be supplied to the
  `*_with_hidden` calls; empty-empty is rejected. V4/V6 version-mix is
  validated across the combined recipient set, matching the rule for
  `encrypt_bytes_to_multiple`.
- `change_user_pin(old_user_pin, new_pin, ident)` is unchanged; it
  still issues `CHANGE REFERENCE DATA` (PW1), which requires the
  current user PIN and decrements PW1's retry counter on failure.
  Callers exposing an admin-authorized "Change User PIN" flow should
  use `reset_user_pin` instead -- routing such a flow through
  `change_user_pin` with the admin PIN as `old_pin` quietly blocks
  PW1 after three attempts.

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
