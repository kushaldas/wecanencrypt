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
//! - **Key Management**: Parse, modify, and export OpenPGP keys
//! - **Key Storage**: SQLite-backed keystore (optional feature)
//!
//! ## Migrating to 0.6.0
//!
//! ### Breaking changes
//!
//! - **`GeneratedKey.secret_key`** is now `Zeroizing<Vec<u8>>` (was `Vec<u8>`).
//!   Secret key bytes are securely erased from memory on drop. `Zeroizing`
//!   implements `Deref<Target = Vec<u8>>`, so most code works unchanged.
//!   If you need a `Vec<u8>`, call `.to_vec()`.
//!
//! - **`KeyInfo.user_ids`** is now `Vec<UserIDInfo>` (was `Vec<String>`).
//!   Each UID now includes `value` (the string), `revoked` (bool), and
//!   `certifications` (third-party signatures). Access the UID string via
//!   `.value` (e.g., `info.user_ids[0].value`).
//!
//! - **`decrypt_with_key()`** now takes an `allow_legacy: bool` parameter.
//!   Pass `false` to reject integrity-unprotected SED packets (recommended).
//!   Pass `true` only for historical pre-2007 data.
//!
//! - **`decrypt_bytes()`** no longer decrypts legacy SED packets by default.
//!   Use [`decrypt_bytes_legacy()`] for messages without integrity protection.
//!
//! - **Verification now rejects revoked keys.** Signatures from revoked
//!   keys or subkeys return `false`. Expired keys can still verify old
//!   signatures (by design, per OpenPGP semantics).
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
//! | `Cv448Modern` | Ed448 (RFC 9580) | X448 | Fast |
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
//! that take key data as `&[u8]`. This provides maximum flexibility
//! and avoids the overhead of wrapper types.

// Re-export rpgp crate
pub use pgp;

// Modules
mod error;
mod internal;
mod types;

mod decrypt;
mod encrypt;
mod key;
mod keyring;
mod parse;
mod sign;
mod ssh;
mod verify;

#[cfg(any(feature = "network", feature = "dane"))]
mod network;

#[cfg(feature = "card")]
pub mod card;

pub mod keystore;

// Re-export error types
pub use error::{Error, Result};

// Re-export all public types
pub use types::{
    AvailableSubkey, CertificationType, CipherSuite, GeneratedKey, KeyAlgorithm, KeyCipherDetails,
    KeyInfo, KeySummary, KeyType, RsaPublicKey, SigningPublicKey, SubkeyFlags, SubkeyInfo,
    SubkeySummary, UIDCertification, UserIDInfo, UserIdSummary,
};

// Re-export parsing functions
pub use parse::{
    get_all_available_subkeys, get_available_authentication_subkeys,
    get_available_encryption_subkeys, get_available_signing_subkeys, get_key_cipher_details,
    has_available_encryption_subkey, has_available_signing_subkey, parse_key_bytes, parse_key_file,
};

// Re-export encryption functions
pub use encrypt::{
    bytes_encrypted_for, encrypt_bytes, encrypt_bytes_to_multiple,
    encrypt_bytes_to_multiple_seipd_v2, encrypt_bytes_to_multiple_v2,
    encrypt_bytes_to_multiple_with_algo, encrypt_bytes_v2, encrypt_file, encrypt_file_to_multiple,
    encrypt_reader_to_file, file_encrypted_for, sign_and_encrypt_to_multiple,
};

// Re-export symmetric algorithm type for use with encrypt_bytes_to_multiple_with_algo
pub use pgp::crypto::sym::SymmetricKeyAlgorithm;

// Re-export the OpenPGP key packet version so callers can pick V4 (default) or
// V6 (RFC 9580) without importing from the underlying `pgp` crate directly.
pub use pgp::types::KeyVersion;

// Re-export decryption functions
pub use decrypt::{
    decrypt_and_verify, decrypt_bytes, decrypt_bytes_legacy, decrypt_file, decrypt_reader_to_file,
    DecryptVerifyResult, DecryptVerifySignature,
};

// Re-export signing functions
pub use sign::{
    sign_bytes, sign_bytes_cleartext, sign_bytes_cleartext_with_primary_key, sign_bytes_detached,
    sign_bytes_detached_with_hash, sign_bytes_detached_with_primary_key,
    sign_bytes_with_primary_key, sign_file, sign_file_cleartext, sign_file_detached,
    DetachedSignOutput,
};

// Re-export the rpgp HashAlgorithm so callers can request a specific hash
// without importing the underlying `pgp` crate directly. Used by
// `sign_bytes_detached_with_hash`.
pub use pgp::crypto::hash::HashAlgorithm;

// Re-export verification functions
pub use verify::{
    verify_and_extract_bytes, verify_and_extract_file, verify_bytes, verify_bytes_detached,
    verify_file, verify_file_detached,
};

// Re-export key generation and management functions
pub use key::{
    add_uid, certify_key, create_key, create_key_simple, create_key_v6, create_key_v6_simple,
    get_pub_key, revoke_key, revoke_uid, update_password, update_primary_expiry,
    update_subkeys_expiry,
};

// Re-export keyring functions
pub use keyring::{
    export_keyring_armored, export_keyring_file, merge_keys, parse_keyring_bytes,
    parse_keyring_file,
};

// Re-export SSH functions
pub use ssh::{get_signing_pubkey, get_ssh_pubkey, ssh_sign_raw, SshHashAlgorithm, SshSignResult};

// Re-export keystore types when feature is enabled
#[cfg(feature = "keystore")]
pub use keystore::{
    decrypt_bytes_from_store,
    decrypt_file_from_store,
    // Bytes-based store operations
    encrypt_bytes_from_store,
    encrypt_bytes_to_multiple_from_store,
    // File-based store operations
    encrypt_file_from_store,
    encrypt_file_to_multiple_from_store,
    sign_bytes_detached_from_store,
    sign_bytes_from_store,
    sign_file_detached_from_store,
    sign_file_from_store,
    verify_bytes_detached_from_store,
    verify_bytes_from_store,
    verify_file_detached_from_store,
    verify_file_from_store,
    KeyStore,
};

// Re-export network functions when feature is enabled
#[cfg(feature = "network")]
pub use network::{
    fetch_key_by_email, fetch_key_by_email_from_keyserver, fetch_key_by_fingerprint,
    fetch_key_by_keyid,
};

// Re-export DANE function when feature is enabled
#[cfg(feature = "dane")]
pub use network::fetch_key_by_email_from_dane;
