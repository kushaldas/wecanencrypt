//! # WeCanEncrypt
//!
//! A compact OpenPGP API for applications that want to pass armored or binary
//! key/message bytes around without owning rPGP's lower-level packet model.
//!
//! The crate exposes functional entry points for the common workflows:
//!
//! - key generation with V4 and V6 packet formats
//! - encryption and decryption for one or more recipients
//! - inline, cleartext, and detached signatures
//! - key parsing, UID management, expiry updates, revocation, and merging
//! - optional SQLite storage, network lookup, DANE lookup, and smart-card I/O
//!
//! Most functions accept `&[u8]` containing either ASCII armor or binary
//! OpenPGP data. Generated secret-key bytes are wrapped in `Zeroizing<Vec<u8>>`
//! through [`GeneratedKey::secret_key`], so temporary secret material is cleared
//! when dropped.
//!
//! ## Quick Start
//!
//! ```no_run
//! use wecanencrypt::{create_key_simple, decrypt_bytes, encrypt_bytes};
//!
//! // Generate a V4 certificate using the default Cv25519 suite.
//! let key = create_key_simple("password", &["Alice <alice@example.com>"]).unwrap();
//!
//! // Encrypt to the public certificate bytes returned by key generation.
//! let ciphertext = encrypt_bytes(key.public_key.as_bytes(), b"Hello!", true).unwrap();
//!
//! // Decrypt with the matching secret certificate bytes.
//! let plaintext = decrypt_bytes(&key.secret_key, &ciphertext, "password").unwrap();
//! assert_eq!(plaintext, b"Hello!");
//! ```
//!
//! ## Key Versions
//!
//! [`create_key_simple`] and [`create_key`] produce broadly compatible V4
//! certificates. [`create_key_v6_simple`] and [`create_key_v6`] produce RFC
//! 9580 V6 certificates, which use the modern Ed25519/X25519 or Ed448/X448 key
//! encodings for the Curve25519/Curve448 suites.
//!
//! Encryption helpers such as [`encrypt_bytes`] and
//! [`encrypt_bytes_to_multiple`] inspect recipient certificates and pick the
//! correct encrypted-data packet format automatically: SEIPD v1 for V4
//! recipients, SEIPD v2 with AEAD for V6 recipients. A mixed V4/V6 recipient
//! list returns [`Error::KeyVersionMismatch`].
//!
//! ## Cipher Suites
//!
//! The library supports multiple cipher suites:
//!
//! | Suite | Primary Key | Encryption Subkey | Speed |
//! |-------|-------------|-------------------|-------|
//! | `Cv25519` (default) | EdDSA Legacy | ECDH Curve25519Legacy | Fast |
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
//! - `keystore` (default): SQLite-backed key storage.
//! - `network` (default): WKD and keyserver lookup via blocking `reqwest`.
//! - `dane`: DNS OPENPGPKEY lookup.
//! - `card`: transport-agnostic OpenPGP-card operations.
//! - `card-pcsc`: desktop PC/SC transport; implies `card`.
//! - `card-external`: mobile or custom transport provider; implies `card`.
//! - `draft-pqc`: exposes rPGP's experimental post-quantum draft support.
//!
//! ## Security Defaults
//!
//! Decryption rejects legacy SED packets without integrity protection unless
//! you explicitly call [`decrypt_bytes_legacy`]. Verification and signing
//! helpers ignore revoked signing keys, and signing refuses expired or revoked
//! key material. Expired keys may still verify old signatures.

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
    encrypt_bytes_to_multiple_with_algo, encrypt_bytes_to_multiple_with_hidden, encrypt_bytes_v2,
    encrypt_file, encrypt_file_to_multiple, encrypt_reader_to_file, file_encrypted_for,
    sign_and_encrypt_to_multiple, sign_and_encrypt_to_multiple_with_hidden,
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
    verify_software_passphrase, DetachedSignOutput,
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
    export_public_for_autocrypt, get_pub_key, revoke_key, revoke_uid, update_password,
    update_primary_expiry, update_subkeys_expiry,
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
