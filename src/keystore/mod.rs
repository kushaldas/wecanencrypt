//! SQLite-backed key storage.
//!
//! This module provides persistent storage for OpenPGP certificates
//! using SQLite. Keys are stored with their fingerprints, user IDs,
//! and subkey information for efficient lookup.
//!
//! # Features
//!
//! - **Persistent storage**: Keys survive application restarts
//! - **Search**: Find keys by fingerprint, email, or user ID
//! - **Separate secret/public**: Track which keys have secret material
//! - **Crypto operations**: Encrypt, decrypt, sign, verify using stored keys
//!
//! # Basic Usage
//!
//! ```no_run
//! use wecanencrypt::{KeyStore, create_key_simple};
//!
//! // Open or create a keystore
//! let store = KeyStore::open("~/.myapp/keys.db").unwrap();
//!
//! // Generate and import a key
//! let key = create_key_simple("password", &["Alice <alice@example.com>"]).unwrap();
//! let fingerprint = store.import_cert(&key.secret_key).unwrap();
//!
//! println!("Imported key: {}", fingerprint);
//!
//! // List all keys
//! for cert in store.list_certs().unwrap() {
//!     println!("  {} - {:?}", cert.fingerprint, cert.user_ids);
//! }
//! ```
//!
//! # Encryption with KeyStore
//!
//! ```no_run
//! use wecanencrypt::{KeyStore, encrypt_bytes_from_store, decrypt_bytes_from_store};
//!
//! let store = KeyStore::open("keys.db").unwrap();
//!
//! // Encrypt to a recipient by fingerprint
//! let recipient_fp = "ABCD1234...";
//! let ciphertext = encrypt_bytes_from_store(
//!     &store,
//!     recipient_fp,
//!     b"Secret message",
//!     true,  // armor
//! ).unwrap();
//!
//! // Decrypt using your secret key
//! let my_fp = "1234ABCD...";
//! let plaintext = decrypt_bytes_from_store(
//!     &store,
//!     my_fp,
//!     &ciphertext,
//!     "my_password",
//! ).unwrap();
//! ```
//!
//! # Signing with KeyStore
//!
//! ```no_run
//! use wecanencrypt::{KeyStore, sign_bytes_from_store, verify_bytes_from_store};
//!
//! let store = KeyStore::open("keys.db").unwrap();
//! let my_fp = "1234ABCD...";
//!
//! // Sign a message
//! let signed = sign_bytes_from_store(
//!     &store,
//!     my_fp,
//!     b"Important announcement",
//!     "my_password",
//! ).unwrap();
//!
//! // Verify the signature
//! let valid = verify_bytes_from_store(&store, my_fp, &signed).unwrap();
//! assert!(valid);
//! ```
//!
//! # Searching for Keys
//!
//! ```no_run
//! use wecanencrypt::KeyStore;
//!
//! let store = KeyStore::open("keys.db").unwrap();
//!
//! // Search by email
//! let results = store.search_by_email("alice@example.com").unwrap();
//!
//! // Search by name or partial UID
//! let results = store.search_by_uid("Alice").unwrap();
//!
//! // List only secret keys (keys you own)
//! let my_keys = store.list_secret_keys().unwrap();
//!
//! // List only public keys (other people's keys)
//! let their_keys = store.list_public_keys().unwrap();
//! ```
//!
//! # In-Memory Store for Testing
//!
//! ```
//! use wecanencrypt::KeyStore;
//!
//! // Create an in-memory store (no file, for testing)
//! let store = KeyStore::open_in_memory().unwrap();
//! assert_eq!(store.count().unwrap(), 0);
//! ```

#[cfg(feature = "keystore")]
mod store;
#[cfg(feature = "keystore")]
mod schema;

#[cfg(feature = "keystore")]
pub use store::*;
