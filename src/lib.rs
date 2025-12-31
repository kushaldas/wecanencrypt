//! # WeCanEncrypt
//!
//! A simple Rust OpenPGP library for encryption, signing, and key management using [rpgp](https://docs.rs/pgp).
//!
//! This library provides a functional API for common OpenPGP operations,
//! including:
//!
//! - **Key Generation**: Create RSA, Curve25519, or NIST curve keys
//! - **Encryption/Decryption**: Encrypt to one or multiple recipients
//! - **Signing/Verification**: Create and verify signatures
//! - **Certificate Management**: Parse, modify, and export certificates
//! - **Key Storage**: SQLite-backed keystore (optional feature)
//!
//! ## Quick Start
//!
//! ```no_run
//! use wecanencrypt::*;
//!
//! // Generate a new Curve25519 key (fast)
//! let key = create_key_simple("password", &["Alice <alice@example.com>"]).unwrap();
//!
//! // Encrypt a message
//! let ciphertext = encrypt_bytes(key.public_key.as_bytes(), b"Hello!", true).unwrap();
//!
//! // Decrypt it
//! let plaintext = decrypt_bytes(&key.secret_key, &ciphertext, "password").unwrap();
//! assert_eq!(plaintext, b"Hello!");
//! ```
//!
//! ## Cipher Suites
//!
//! The library supports multiple cipher suites:
//!
//! | Suite | Primary Key | Encryption Subkey | Speed |
//! |-------|-------------|-------------------|-------|
//! | `Cv25519` (default) | EdDSA Legacy | ECDH Curve25519 | Fast |
//! | `Cv25519Modern` | Ed25519 (RFC 9580) | X25519 | Fast |
//! | `NistP256` | ECDSA P-256 | ECDH P-256 | Fast |
//! | `NistP384` | ECDSA P-384 | ECDH P-384 | Fast |
//! | `NistP521` | ECDSA P-521 | ECDH P-521 | Fast |
//! | `Rsa2k` | RSA 2048-bit | RSA 2048-bit | Slow |
//! | `Rsa4k` | RSA 4096-bit | RSA 4096-bit | Very Slow |
//!
//! ## Features
//!
//! - `keystore`: Enable SQLite-backed key storage (requires `rusqlite`)
//! - `network`: Enable network operations for fetching keys from keyservers
//!
//! ## Design
//!
//! This library uses a functional API - all operations are standalone functions
//! that take certificate data as `&[u8]`. This provides maximum flexibility
//! and avoids the overhead of wrapper types.

// Internal OpenPGP implementation (rpgp)
pub mod pgp;

// Modules
mod error;
mod types;
mod internal;

mod parse;
mod encrypt;
mod decrypt;
mod sign;
mod verify;
mod key;
mod keyring;
mod ssh;

#[cfg(feature = "network")]
mod network;

pub mod keystore;

// Re-export error types
pub use error::{Error, Result};

// Re-export all public types
pub use types::{
    CipherSuite,
    SubkeyFlags,
    KeyType,
    SubkeyInfo,
    CertificateInfo,
    KeyCipherDetails,
    GeneratedKey,
    CertificationType,
    RsaPublicKey,
    SigningPublicKey,
    AvailableSubkey,
};

// Re-export parsing functions
pub use parse::{
    parse_cert_bytes,
    parse_cert_file,
    get_key_cipher_details,
    get_available_encryption_subkeys,
    get_available_signing_subkeys,
    get_available_authentication_subkeys,
    get_all_available_subkeys,
    has_available_encryption_subkey,
    has_available_signing_subkey,
};

// Re-export encryption functions
pub use encrypt::{
    encrypt_bytes,
    encrypt_bytes_to_multiple,
    encrypt_file,
    encrypt_file_to_multiple,
    encrypt_reader_to_file,
    bytes_encrypted_for,
    file_encrypted_for,
};

// Re-export decryption functions
pub use decrypt::{
    decrypt_bytes,
    decrypt_file,
    decrypt_reader_to_file,
};

// Re-export signing functions
pub use sign::{
    sign_bytes,
    sign_bytes_cleartext,
    sign_bytes_detached,
    sign_file,
    sign_file_cleartext,
    sign_file_detached,
};

// Re-export verification functions
pub use verify::{
    verify_bytes,
    verify_and_extract_bytes,
    verify_bytes_detached,
    verify_file,
    verify_and_extract_file,
    verify_file_detached,
};

// Re-export key generation and management functions
pub use key::{
    create_key,
    create_key_simple,
    update_subkeys_expiry,
    update_primary_expiry,
    add_uid,
    revoke_uid,
    update_password,
    certify_key,
    get_pub_key,
};

// Re-export keyring functions
pub use keyring::{
    parse_keyring_file,
    parse_keyring_bytes,
    export_keyring_file,
    export_keyring_armored,
    merge_keys,
};

// Re-export SSH functions
pub use ssh::{
    get_ssh_pubkey,
    get_signing_pubkey,
};

// Re-export keystore types when feature is enabled
#[cfg(feature = "keystore")]
pub use keystore::{
    KeyStore,
    // Bytes-based store operations
    encrypt_bytes_from_store,
    encrypt_bytes_to_multiple_from_store,
    decrypt_bytes_from_store,
    sign_bytes_from_store,
    sign_bytes_detached_from_store,
    verify_bytes_from_store,
    verify_bytes_detached_from_store,
    // File-based store operations
    encrypt_file_from_store,
    encrypt_file_to_multiple_from_store,
    decrypt_file_from_store,
    sign_file_from_store,
    sign_file_detached_from_store,
    verify_file_from_store,
    verify_file_detached_from_store,
};

// Re-export network functions when feature is enabled
#[cfg(feature = "network")]
pub use network::{
    fetch_key_by_email,
    fetch_key_by_fingerprint,
    fetch_key_by_keyid,
};
