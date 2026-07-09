# V6 (RFC 9580) test fixtures

Static, committed V6 key material used by `tests/v6_fixture_tests.rs` for
regression and interop testing.

## Files

| File | Contents |
|------|----------|
| `alice_v6_cv25519modern_sec.asc` | Alice's armored V6 secret key (Ed25519 + X25519) |
| `alice_v6_cv25519modern_pub.asc` | Alice's armored V6 public key |
| `bob_v6_cv448modern_sec.asc` | Bob's armored V6 secret key (Ed448 + X448) |
| `bob_v6_cv448modern_pub.asc` | Bob's armored V6 public key |
| `alice_v6_signed_inline.pgp` | Inline V6 signature over `signed_payload.txt`, signed by Alice |
| `alice_v6_signed_detached.asc` | Detached V6 signature over `signed_payload.txt`, signed by Alice |
| `signed_payload.txt` | Plaintext signed by the two files above |
| `alice_v6_encrypted_seipdv2.asc` | SEIPDv2 message encrypted to Alice (auto-selected because Alice is V6) |
| `encrypted_payload.txt` | Plaintext corresponding to the encrypted message |

## Password

All secret keys use the password `v6-fixture-password`.

## Regeneration

Run `cargo run --example gen_v6_fixtures` from the repository root. The
example writes the files deterministically to this directory; commit the
result. Regenerate only when the fixture contract (filenames, UIDs, password,
or plaintext payloads) changes - otherwise the committed files are stable
test inputs.

## Why commit these?

- Interop / regression coverage independent of the current build's RNG.
- Allows quick sanity checks against external tools (e.g., GnuPG 2.5+) without
  needing the host to generate keys first.
