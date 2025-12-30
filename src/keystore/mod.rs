//! SQLite-backed key storage.
//!
//! This module provides persistent storage for OpenPGP certificates
//! using SQLite. It requires the `keystore` feature to be enabled.
//!
//! # Example
//! ```ignore
//! use wecanencrypt::keystore::KeyStore;
//!
//! let store = KeyStore::open("keys.db")?;
//! store.import_cert(&cert_bytes)?;
//!
//! let certs = store.list_certs()?;
//! ```

#[cfg(feature = "keystore")]
mod store;
#[cfg(feature = "keystore")]
mod schema;

#[cfg(feature = "keystore")]
pub use store::*;
