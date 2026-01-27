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
- **Smart Card Support**: Upload keys to YubiKey/OpenPGP cards, sign and decrypt on-card, configure touch policies

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

## Smart Card Usage

```rust
use wecanencrypt::card::{
    is_card_connected, get_card_details, upload_key_to_card,
    set_touch_mode, KeySlot, TouchMode, CardKeySlot,
};

// Check for connected card
if is_card_connected() {
    let info = get_card_details()?;
    println!("Card serial: {}", info.serial_number);

    // Upload a key to the signing slot
    let secret_key = std::fs::read("secret.asc")?;
    upload_key_to_card(&secret_key, b"password", CardKeySlot::Signing, b"12345678")?;

    // Configure touch policy (YubiKey 4.2+)
    // Warning: TouchMode::Fixed is permanent and cannot be changed!
    set_touch_mode(KeySlot::Signature, TouchMode::Fixed, b"12345678")?;
    set_touch_mode(KeySlot::Encryption, TouchMode::Fixed, b"12345678")?;
    set_touch_mode(KeySlot::Authentication, TouchMode::On, b"12345678")?;
}
```

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

- `keystore` (default): SQLite-backed key storage
- `network` (default): WKD and HKP key fetching
- `card`: Smart card support (requires hardware)
- `draft-pqc`: Post-quantum cryptography support

## License

MIT
