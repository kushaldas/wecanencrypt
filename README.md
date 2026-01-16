# wecanencrypt

Simple Rust OpenPGP library for encryption, signing, and key management, built on top of [rpgp](https://github.com/rpgp/rpgp).

## Features

- **Key Generation**: Create OpenPGP keys with various cipher suites (Cv25519, RSA2k, RSA4k, NIST P-256/P-384/P-521)
- **Encryption/Decryption**: Encrypt and decrypt files and byte streams
- **Signing/Verification**: Sign messages (inline, cleartext, detached) and verify signatures
- **Key Parsing**: Parse certificates from files or bytes, extract key information
- **Keyring Support**: Parse and export GPG keyrings
- **SSH Key Export**: Convert OpenPGP authentication keys to SSH public key format
- **Network Operations**: Fetch keys via WKD (Web Key Directory) and HKP keyservers
- **KeyStore**: SQLite-backed key storage with search and management capabilities

## Usage

```rust
use wecanencrypt::{create_key, encrypt_bytes, decrypt_bytes, CipherSuite, SubkeyFlags};

// Generate a new key
let key = create_key(
    "passphrase",
    &["Alice <alice@example.com>"],
    CipherSuite::Cv25519,
    None, None, None,
    SubkeyFlags::default(),
    false,
    true,
)?;

// Encrypt data
let plaintext = b"Hello, World!";
let encrypted = encrypt_bytes(plaintext, &[&key.public_key.as_bytes()])?;

// Decrypt data
let decrypted = decrypt_bytes(&encrypted, &key.secret_key.as_bytes(), "passphrase")?;
```

## Running Tests

Run the standard test suite:

```bash
cargo test
```

Run tests with all default features:

```bash
cargo test --all-features
```

### Smart Card Tests

Smart card tests require a physical YubiKey or compatible OpenPGP smart card. These tests are ignored by default:

```bash
cargo test --features card --test card_tests -- --ignored --test-threads=1
```

Note: Card tests automatically reset the card to factory defaults before each test.

## Optional Features

- `keystore` (default): SQLite-backed key storage
- `network` (default): WKD and HKP key fetching
- `card`: Smart card support (requires hardware)
- `draft-pqc`: Post-quantum cryptography support

## License

MIT
