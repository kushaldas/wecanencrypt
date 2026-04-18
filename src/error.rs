//! Error types for the wecanencrypt library.
//!
//! This module provides a comprehensive error type that covers all possible
//! failure modes in OpenPGP operations.

use pgp::types::KeyVersion;
use thiserror::Error;

/// The main error type for wecanencrypt operations.
#[derive(Error, Debug)]
pub enum Error {
    /// Cryptographic operation failed
    #[error("Cryptographic operation failed: {0}")]
    Crypto(String),

    /// Key parsing failed
    #[error("Key parsing failed: {0}")]
    Parse(String),

    /// Invalid password or unable to decrypt secret key
    #[error("Invalid password or key")]
    InvalidPassword,

    /// Requested key was not found
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    /// Signature verification failed
    #[error("Signature verification failed")]
    VerificationFailed,

    /// Attempted to merge identical keys
    #[error("Cannot merge identical keys")]
    SameKeyError,

    /// File I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Invalid input provided
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Algorithm not supported
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Key has expired
    #[error("Key has expired")]
    KeyExpired,

    /// Key has been revoked
    #[error("Key has been revoked")]
    KeyRevoked,

    /// No suitable encryption subkey found
    #[error("No suitable encryption subkey found")]
    NoEncryptionSubkey,

    /// No suitable signing subkey found
    #[error("No suitable signing subkey found")]
    NoSigningSubkey,

    /// No suitable authentication subkey found
    #[error("No suitable authentication subkey found")]
    NoAuthenticationSubkey,

    /// Key does not contain secret key material
    #[error("Key does not contain secret key material")]
    NoSecretKey,

    /// Armored data is malformed
    #[error("Malformed armored data: {0}")]
    MalformedArmor(String),

    /// User ID not found in key
    #[error("User ID not found: {0}")]
    UidNotFound(String),

    /// Operation would mix keys or key material of different OpenPGP versions
    #[error("Key version mismatch: existing {existing:?}, incoming {incoming:?}")]
    KeyVersionMismatch {
        /// The key version already present / expected.
        existing: KeyVersion,
        /// The key version that was supplied and conflicts.
        incoming: KeyVersion,
    },

    /// Database error (keystore feature)
    #[cfg(feature = "keystore")]
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    /// Network error (network feature)
    #[error("Network error: {0}")]
    Network(String),

    /// rpgp OpenPGP error
    #[error("OpenPGP error: {0}")]
    OpenPgp(#[from] pgp::errors::Error),

    /// Generic error from anyhow
    #[error("Error: {0}")]
    Generic(#[from] anyhow::Error),

    /// Smart card error (card feature)
    #[cfg(feature = "card")]
    #[error("Smart card error: {0}")]
    Card(#[from] crate::card::CardError),
}

/// A specialized Result type for wecanencrypt operations.
pub type Result<T> = std::result::Result<T, Error>;

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::Crypto(s)
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::Crypto(s.to_string())
    }
}
