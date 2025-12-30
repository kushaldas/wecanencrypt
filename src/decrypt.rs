//! Decryption functions.
//!
//! This module provides functions for decrypting OpenPGP encrypted messages
//! using secret key material.

use std::io::{Cursor, Read};
use std::path::Path;

use pgp::composed::{Deserializable, Message, SignedSecretKey};
use pgp::types::Password;

use crate::error::{Error, Result};
use crate::internal::parse_secret_key;

/// Decrypt bytes using a secret key.
///
/// Decrypts an OpenPGP encrypted message using the recipient's secret key.
/// The message must have been encrypted to this key.
///
/// # Arguments
/// * `secret_cert` - The recipient's secret key (armored or binary)
/// * `ciphertext` - The encrypted data (armored or binary)
/// * `password` - Password to unlock the secret key
///
/// # Returns
/// The decrypted plaintext bytes.
///
/// # Errors
/// * [`Error::InvalidPassword`] - If the password is incorrect
/// * [`Error::Crypto`] - If the message wasn't encrypted to this key
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{create_key_simple, encrypt_bytes, decrypt_bytes, get_pub_key};
///
/// let key = create_key_simple("password", &["Alice <alice@example.com>"]).unwrap();
/// let public_key = get_pub_key(&key.secret_key).unwrap();
///
/// // Encrypt
/// let ciphertext = encrypt_bytes(public_key.as_bytes(), b"Hello!", true).unwrap();
///
/// // Decrypt
/// let plaintext = decrypt_bytes(&key.secret_key, &ciphertext, "password").unwrap();
/// assert_eq!(plaintext, b"Hello!");
/// ```
pub fn decrypt_bytes(secret_cert: &[u8], ciphertext: &[u8], password: &str) -> Result<Vec<u8>> {
    let secret_key = parse_secret_key(secret_cert)?;
    decrypt_with_key(&secret_key, ciphertext, password)
}

/// Decrypt bytes using an already-parsed secret key.
///
/// # Arguments
/// * `secret_key` - The parsed secret key
/// * `ciphertext` - The encrypted data
/// * `password` - Password to unlock the secret key
///
/// # Returns
/// The decrypted plaintext.
pub fn decrypt_with_key(
    secret_key: &SignedSecretKey,
    ciphertext: &[u8],
    password: &str,
) -> Result<Vec<u8>> {
    let password: Password = password.into();

    // Parse the encrypted message (try armored first, then binary)
    let message = match Message::from_armor(Cursor::new(ciphertext)) {
        Ok((msg, _headers)) => msg,
        Err(_) => Message::from_bytes(ciphertext)
            .map_err(|e| Error::Parse(e.to_string()))?,
    };

    // Try standard decrypt first, then legacy mode
    let decrypted = message.decrypt(&password, secret_key)
        .or_else(|_| {
            // Try parsing again for legacy decrypt
            let msg = match Message::from_armor(Cursor::new(ciphertext)) {
                Ok((m, _headers)) => m,
                Err(_) => Message::from_bytes(ciphertext)
                    .map_err(|e| Error::Parse(e.to_string()))?,
            };
            msg.decrypt_legacy(&password, secret_key)
                .map_err(|e| Error::Crypto(e.to_string()))
        })
        .map_err(|e: Error| {
            // Check if it's a password issue
            if e.to_string().contains("password") || e.to_string().contains("decrypt") {
                Error::InvalidPassword
            } else {
                e
            }
        })?;

    // Handle compression if present
    let mut decompressed = if decrypted.is_compressed() {
        decrypted.decompress()
            .map_err(|e| Error::Crypto(e.to_string()))?
    } else {
        decrypted
    };

    // Extract the plaintext data
    decompressed.as_data_vec()
        .map_err(|e| Error::Crypto(e.to_string()))
}

/// Decrypt a file using a secret key.
///
/// # Arguments
/// * `secret_cert` - The recipient's secret key
/// * `input` - Path to the encrypted file
/// * `output` - Path to write the decrypted file
/// * `password` - Password to unlock the secret key
pub fn decrypt_file(
    secret_cert: &[u8],
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    password: &str,
) -> Result<()> {
    let ciphertext = std::fs::read(input.as_ref())?;
    let plaintext = decrypt_bytes(secret_cert, &ciphertext, password)?;
    std::fs::write(output.as_ref(), plaintext)?;
    Ok(())
}

/// Decrypt data from a reader to a file.
///
/// # Arguments
/// * `secret_cert` - The recipient's secret key
/// * `reader` - Source of encrypted data
/// * `output` - Path to write the decrypted file
/// * `password` - Password to unlock the secret key
pub fn decrypt_reader_to_file<R: Read>(
    secret_cert: &[u8],
    mut reader: R,
    output: impl AsRef<Path>,
    password: &str,
) -> Result<()> {
    let mut ciphertext = Vec::new();
    reader.read_to_end(&mut ciphertext)?;
    let plaintext = decrypt_bytes(secret_cert, &ciphertext, password)?;
    std::fs::write(output.as_ref(), plaintext)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests would require key fixtures
}
