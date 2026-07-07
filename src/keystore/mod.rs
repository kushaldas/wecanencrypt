//! SQLite-backed key storage.
//!
//! Enabled by the `keystore` feature, this module stores OpenPGP public and
//! secret certificates in SQLite and indexes their fingerprints, key IDs, user
//! IDs, email addresses, subkeys, key versions, and revocation state. It is a
//! convenience layer over the functional API: stored keys are exported and then
//! passed to the same encrypt/decrypt/sign/verify helpers used elsewhere.
//!
//! Public certificates and secret certificates are tracked separately, so an
//! application can distinguish keys it owns from keys it only encrypts to or
//! verifies against.
//!
//! # Basic Usage
//!
//! ```no_run
//! use wecanencrypt::{create_key_simple, KeyStore};
//!
//! let store = KeyStore::open("keys.db").unwrap();
//!
//! let key = create_key_simple("password", &["Alice <alice@example.com>"]).unwrap();
//! let fingerprint = store.import_key(&key.secret_key).unwrap();
//!
//! for key in store.list_keys().unwrap() {
//!     println!("{} {:?}", key.fingerprint, key.user_ids);
//! }
//! ```
//!
//! # Encryption with KeyStore
//!
//! ```no_run
//! use wecanencrypt::{
//!     create_key_simple, decrypt_bytes_from_store, encrypt_bytes_from_store, KeyStore,
//! };
//!
//! let store = KeyStore::open_in_memory().unwrap();
//! let alice = create_key_simple("password", &["Alice <alice@example.com>"]).unwrap();
//! let alice_fp = store.import_key(&alice.secret_key).unwrap();
//!
//! let ciphertext = encrypt_bytes_from_store(
//!     &store,
//!     &alice_fp,
//!     b"Secret message",
//!     true,
//! ).unwrap();
//!
//! let plaintext = decrypt_bytes_from_store(
//!     &store,
//!     &alice_fp,
//!     &ciphertext,
//!     "password",
//! ).unwrap();
//! assert_eq!(plaintext, b"Secret message");
//! ```
//!
//! # Signing with KeyStore
//!
//! ```no_run
//! use wecanencrypt::{
//!     create_key_simple, sign_bytes_from_store, verify_bytes_from_store, KeyStore,
//! };
//!
//! let store = KeyStore::open_in_memory().unwrap();
//! let alice = create_key_simple("password", &["Alice <alice@example.com>"]).unwrap();
//! let alice_fp = store.import_key(&alice.secret_key).unwrap();
//!
//! let signed = sign_bytes_from_store(
//!     &store,
//!     &alice_fp,
//!     b"Important announcement",
//!     "password",
//! ).unwrap();
//!
//! let valid = verify_bytes_from_store(&store, &alice_fp, &signed).unwrap();
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
mod schema;
#[cfg(feature = "keystore")]
mod store;

#[cfg(feature = "keystore")]
pub use store::*;
