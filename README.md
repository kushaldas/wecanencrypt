# wecanencrypt

Simple Rust OpenPGP library for encryption, signing, and key management, built
on top of [rpgp](https://github.com/rpgp/rpgp) (pgp v0.19).

## Features

- **Key Generation**: Create OpenPGP keys with multiple cipher suites (Cv25519, Cv25519Modern, Cv448Modern, NIST P-256/P-384/P-521, RSA-2048/4096)
- **Encryption/Decryption**: Encrypt to one or multiple recipients (SEIPD v1 default, SEIPD v2 AEAD available), reject legacy SED by default
- **Signing/Verification**: Inline, cleartext, and detached signatures with subkey preference; verification filters to signing-capable subkeys only
- **Certificate Merging**: Proper packet-level merge with signature deduplication, following the rpgpie/rsop algorithm
- **Key Management**: Update expiration (primary and per-subkey), add/revoke UIDs, revoke keys, change passwords, third-party certification (4 levels)
- **Key Parsing**: Parse certificates, extract subkey info, query available subkeys by capability
- **Keyring Support**: Parse and export GPG keyrings with multiple certificates
- **SSH Key Export**: Convert OpenPGP authentication keys to SSH public key format (Ed25519, RSA, ECDSA)
- **Network Operations**: Fetch keys via WKD (Web Key Directory) and VKS keyservers
- **DNS DANE**: Fetch keys via OPENPGPKEY DNS records (RFC 7929)
- **KeyStore**: SQLite-backed key storage with search, card-key associations, and management capabilities
- **Smart Card Support**: Upload keys to YubiKey/OpenPGP cards, sign and decrypt on-card, discover which cards hold keys for a certificate, configure touch policies

## Cipher Suites

| Suite | Primary Key | Encryption Subkey | Speed |
|-------|-------------|-------------------|-------|
| `Cv25519` (default) | EdDSA Legacy | ECDH Curve25519 | Fast |
| `Cv25519Modern` | Ed25519 (RFC 9580) | X25519 | Fast |
| `Cv448Modern` | Ed448 (RFC 9580) | X448 | Fast |
| `NistP256` | ECDSA P-256 | ECDH P-256 | Fast |
| `NistP384` | ECDSA P-384 | ECDH P-384 | Fast |
| `NistP521` | ECDSA P-521 | ECDH P-521 | Fast |
| `Rsa2k` | RSA 2048-bit | RSA 2048-bit | Slow |
| `Rsa4k` | RSA 4096-bit | RSA 4096-bit | Very Slow |

## Usage

```rust
use wecanencrypt::{create_key_simple, encrypt_bytes, decrypt_bytes, get_pub_key};

// Generate a new key
let key = create_key_simple("passphrase", &["Alice <alice@example.com>"])?;
let public_key = get_pub_key(&key.secret_key)?;

// Encrypt data
let plaintext = b"Hello, World!";
let encrypted = encrypt_bytes(public_key.as_bytes(), plaintext, true)?;

// Decrypt data
let decrypted = decrypt_bytes(&key.secret_key, &encrypted, "passphrase")?;
assert_eq!(decrypted, plaintext);
```

## SEIPD v2 (AEAD) Encryption

The default `encrypt_bytes` uses SEIPD v1 (RFC 4880, integrity-protected with
MDC). For AEAD-based encryption with V6 key support, use the v2 variants:

```rust
use wecanencrypt::encrypt_bytes_v2;

let encrypted = encrypt_bytes_v2(public_key.as_bytes(), plaintext, true)?;
```

## Certificate Merging

Merge updated certificates (e.g., after fetching from a keyserver) with proper
signature deduplication:

```rust
use wecanencrypt::merge_keys;

let merged = merge_keys(&original_cert, &updated_cert, false)?;
```

The merge handles direct key signatures, revocation signatures, subkeys,
user IDs, user attributes, and their associated signatures. Deduplication
is based on cryptographic signature bytes, with unhashed subpacket merging
for signatures that differ only in advisory data.

## Smart Card Usage

```rust
use wecanencrypt::card::{
    is_card_connected, get_card_details, find_cards_for_key,
    upload_key_to_card, set_touch_mode, KeySlot, TouchMode, CardKeySlot,
};

// Check for connected card
if is_card_connected() {
    let info = get_card_details(None)?;
    println!("Card serial: {}", info.serial_number);

    // Upload a key to the signing slot
    let secret_key = std::fs::read("secret.asc")?;
    upload_key_to_card(&secret_key, b"password", CardKeySlot::Signing, b"12345678")?;

    // Find which cards hold keys for a certificate
    let public_key = std::fs::read("pubkey.asc")?;
    let matches = find_cards_for_key(&public_key)?;
    for m in &matches {
        println!("Card {} has {} matching slots", m.card.ident, m.matching_slots.len());
    }

    // Configure touch policy (YubiKey 4.2+)
    // Warning: TouchMode::Fixed is permanent and cannot be changed!
    set_touch_mode(KeySlot::Signature, TouchMode::Fixed, b"12345678", None)?;
    set_touch_mode(KeySlot::Encryption, TouchMode::Fixed, b"12345678", None)?;
    set_touch_mode(KeySlot::Authentication, TouchMode::On, b"12345678", None)?;
}
```

## DNS DANE Key Discovery

Fetch OpenPGP keys published in DNS via OPENPGPKEY records ([RFC 7929](https://datatracker.ietf.org/doc/html/rfc7929)):

```rust
use wecanencrypt::fetch_key_by_email_from_dane;

// Uses the system DNS resolver by default
let cert = fetch_key_by_email_from_dane("user@example.com", None)?;

// Or specify a resolver explicitly
let cert = fetch_key_by_email_from_dane("user@example.com", Some("8.8.8.8:53"))?;
```

## Security Policy

The library enforces RFC 4880 section 5.2.3.3: when multiple self-signatures
exist on a component (User ID or subkey), only the most recent one (by creation
timestamp) is authoritative for key flags, expiration, and preferences. This
matters after certificate merges where old and new self-signatures coexist.

See [docs/adr/0001-rfc4880-latest-self-signature-wins.md](docs/adr/0001-rfc4880-latest-self-signature-wins.md) for details.

Other policy decisions:
- Symmetric algorithm allowlist per RFC 9580 section 9.3 (AES, Twofish, Camellia only)
- Legacy SED packets (no integrity protection) rejected by default; opt-in via `decrypt_bytes_legacy`
- Revoked keys rejected for signing and verification; expired keys can still verify old signatures
- Secret key material wrapped in `Zeroizing<Vec<u8>>` for secure memory erasure

## Running Tests

### Run all tests in the tests/ directory

```bash
cargo test --features card --test '*'
```

Or run specific test files:

```bash
# Individual test files
cargo test --features card --test integration_tests
cargo test --features card --test keystore_tests
cargo test --features card --test fixture_tests
```

Or combine them:

```bash
cargo test --features card --test integration_tests --test keystore_tests --test fixture_tests
```

### Smart Card Tests

Smart card tests require a physical YubiKey or compatible OpenPGP smart card. These tests are ignored by default:

```bash
cargo test --features card --test card_tests -- --ignored --test-threads=1
```

Note: Card tests automatically reset the card to factory defaults before each test.

## Optional Features

- `keystore` (default): SQLite-backed key storage with card-key associations
- `network` (default): WKD and VKS key fetching
- `card`: Smart card support (requires `libpcsclite-dev` on Linux)
- `dane`: DNS DANE OPENPGPKEY key discovery (RFC 7929)
- `draft-pqc`: Post-quantum cryptography support (experimental)

## Release

GitHub publishing is wired through the tag-driven workflow in `.github/workflows/publish.yml`.

Before tagging a release, run:

```bash
cargo fmt --check
cargo clippy --all-targets --features card -- -D warnings
cargo test --features card --test '*'
cargo test --features dane --lib
cargo publish --dry-run
```

Then:

1. Update `version` in `Cargo.toml`.
2. Push the version commit.
3. Create and push a tag (e.g. `v0.9.0`).

The publish workflow verifies that the tag matches the crate version, runs `cargo publish --dry-run`, and then publishes via crates.io trusted publishing.
The repository must be configured as a trusted publisher in crates.io before the first tagged release, with the GitHub Actions environment set to `release` to match `.github/workflows/publish.yml`.

The docs.rs build is configured to document `keystore`, `network`, `card`, and `dane`, while leaving `draft-pqc` out of the default published docs because it is experimental.

## License

MIT
