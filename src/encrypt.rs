//! Encryption functions.
//!
//! This module provides functions for encrypting data to one or more
//! OpenPGP recipients.

use std::io::{BufReader, Cursor, Read};
use std::path::Path;

use crate::pgp::armor::Dearmor;
use crate::pgp::composed::{MessageBuilder, SignedPublicKey};
use crate::pgp::crypto::sym::SymmetricKeyAlgorithm;
use crate::pgp::packet::{Packet, PacketParser, PublicKeyEncryptedSessionKey};
use crate::pgp::types::KeyDetails;
use rand::thread_rng;

use crate::error::{Error, Result};
use crate::internal::{is_subkey_valid, parse_public_key};

/// Encrypt bytes to a single recipient.
///
/// Encrypts the plaintext to the recipient's public key. The message can only
/// be decrypted by someone with the corresponding secret key.
///
/// # Arguments
/// * `recipient_cert` - The recipient's public key (armored or binary)
/// * `plaintext` - The data to encrypt
/// * `armor` - If true, output ASCII-armored; otherwise binary
///
/// # Returns
/// The encrypted message.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{create_key_simple, encrypt_bytes, decrypt_bytes, get_pub_key};
///
/// // Create a key pair
/// let key = create_key_simple("password", &["Alice <alice@example.com>"]).unwrap();
/// let public_key = get_pub_key(&key.secret_key).unwrap();
///
/// // Encrypt a message
/// let ciphertext = encrypt_bytes(public_key.as_bytes(), b"Secret message", true).unwrap();
///
/// // Decrypt it
/// let plaintext = decrypt_bytes(&key.secret_key, &ciphertext, "password").unwrap();
/// assert_eq!(plaintext, b"Secret message");
/// ```
pub fn encrypt_bytes(recipient_cert: &[u8], plaintext: &[u8], armor: bool) -> Result<Vec<u8>> {
    encrypt_bytes_to_multiple(&[recipient_cert], plaintext, armor)
}

/// Encrypt bytes to multiple recipients.
///
/// Encrypts the plaintext so that any of the recipients can decrypt it.
/// Each recipient only needs their own secret key to decrypt.
///
/// # Arguments
/// * `recipient_certs` - Slice of recipient public keys (armored or binary)
/// * `plaintext` - The data to encrypt
/// * `armor` - If true, output ASCII-armored; otherwise binary
///
/// # Returns
/// The encrypted message that can be decrypted by any of the recipients.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{create_key_simple, encrypt_bytes_to_multiple, decrypt_bytes, get_pub_key};
///
/// // Create two recipients
/// let alice = create_key_simple("alice_pw", &["Alice <alice@example.com>"]).unwrap();
/// let bob = create_key_simple("bob_pw", &["Bob <bob@example.com>"]).unwrap();
///
/// let alice_pub = get_pub_key(&alice.secret_key).unwrap();
/// let bob_pub = get_pub_key(&bob.secret_key).unwrap();
///
/// // Encrypt to both
/// let ciphertext = encrypt_bytes_to_multiple(
///     &[alice_pub.as_bytes(), bob_pub.as_bytes()],
///     b"Group message",
///     true,
/// ).unwrap();
///
/// // Either can decrypt
/// let plain_alice = decrypt_bytes(&alice.secret_key, &ciphertext, "alice_pw").unwrap();
/// let plain_bob = decrypt_bytes(&bob.secret_key, &ciphertext, "bob_pw").unwrap();
/// assert_eq!(plain_alice, plain_bob);
/// ```
pub fn encrypt_bytes_to_multiple(
    recipient_certs: &[&[u8]],
    plaintext: &[u8],
    armor: bool,
) -> Result<Vec<u8>> {
    if recipient_certs.is_empty() {
        return Err(Error::InvalidInput("No recipients specified".to_string()));
    }

    let mut rng = thread_rng();

    // Parse all recipient certificates and find encryption keys
    let mut encryption_keys = Vec::new();
    for cert_data in recipient_certs {
        let public_key = parse_public_key(cert_data)?;
        let subkeys = find_valid_encryption_subkeys(&public_key)?;
        encryption_keys.extend(subkeys);
    }

    if encryption_keys.is_empty() {
        return Err(Error::NoEncryptionSubkey);
    }

    // Build the encrypted message
    let mut builder = MessageBuilder::from_bytes("", plaintext.to_vec())
        .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);

    // Add all encryption keys as recipients
    for key in &encryption_keys {
        builder.encrypt_to_key(&mut rng, key)
            .map_err(|e| Error::Crypto(e.to_string()))?;
    }

    // Produce the output
    if armor {
        let armored = builder.to_armored_string(&mut rng, None.into())
            .map_err(|e| Error::Crypto(e.to_string()))?;
        Ok(armored.into_bytes())
    } else {
        builder.to_vec(&mut rng)
            .map_err(|e| Error::Crypto(e.to_string()))
    }
}

/// Encrypt a file to a single recipient.
///
/// Reads the input file, encrypts it, and writes the result to the output file.
///
/// # Arguments
/// * `recipient_cert` - The recipient's public key (armored or binary)
/// * `input` - Path to the input file
/// * `output` - Path to the output file
/// * `armor` - If true, output ASCII-armored; otherwise binary
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::encrypt_file;
///
/// let public_key = std::fs::read("recipient.asc").unwrap();
/// encrypt_file(&public_key, "document.pdf", "document.pdf.gpg", true).unwrap();
/// ```
pub fn encrypt_file(
    recipient_cert: &[u8],
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    armor: bool,
) -> Result<()> {
    encrypt_file_to_multiple(&[recipient_cert], input, output, armor)
}

/// Encrypt a file to multiple recipients.
///
/// # Arguments
/// * `recipient_certs` - Slice of recipient public keys (armored or binary)
/// * `input` - Path to the input file
/// * `output` - Path to the output file
/// * `armor` - If true, output ASCII-armored; otherwise binary
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::encrypt_file_to_multiple;
///
/// let alice_key = std::fs::read("alice.asc").unwrap();
/// let bob_key = std::fs::read("bob.asc").unwrap();
///
/// encrypt_file_to_multiple(
///     &[&alice_key, &bob_key],
///     "document.pdf",
///     "document.pdf.gpg",
///     true,
/// ).unwrap();
/// ```
pub fn encrypt_file_to_multiple(
    recipient_certs: &[&[u8]],
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    armor: bool,
) -> Result<()> {
    let plaintext = std::fs::read(input.as_ref())?;
    let ciphertext = encrypt_bytes_to_multiple(recipient_certs, &plaintext, armor)?;
    std::fs::write(output.as_ref(), ciphertext)?;
    Ok(())
}

/// Encrypt data from a reader to a file.
///
/// # Arguments
/// * `recipient_certs` - Slice of recipient public keys
/// * `reader` - Source of plaintext data
/// * `output` - Path to the output file
/// * `armor` - If true, output ASCII-armored
pub fn encrypt_reader_to_file<R: Read>(
    recipient_certs: &[&[u8]],
    mut reader: R,
    output: impl AsRef<Path>,
    armor: bool,
) -> Result<()> {
    let mut plaintext = Vec::new();
    reader.read_to_end(&mut plaintext)?;
    let ciphertext = encrypt_bytes_to_multiple(recipient_certs, &plaintext, armor)?;
    std::fs::write(output.as_ref(), ciphertext)?;
    Ok(())
}

/// Get the key IDs that a message was encrypted for.
///
/// # Arguments
/// * `ciphertext` - The encrypted message (armored or binary)
///
/// # Returns
/// A list of key IDs (hex strings) that can decrypt this message.
pub fn bytes_encrypted_for(ciphertext: &[u8]) -> Result<Vec<String>> {
    let mut key_ids = Vec::new();

    // Try to dearmor if it looks armored
    let data = if ciphertext.starts_with(b"-----BEGIN PGP") {
        let cursor = Cursor::new(ciphertext);
        let dearmor = Dearmor::new(cursor);
        let mut buf = Vec::new();
        let mut reader = BufReader::new(dearmor);
        reader.read_to_end(&mut buf)?;
        buf
    } else {
        ciphertext.to_vec()
    };

    // Parse packets and look for PKESK
    let parser = PacketParser::new(Cursor::new(&data));

    for packet_result in parser {
        match packet_result {
            Ok(packet) => {
                if let Packet::PublicKeyEncryptedSessionKey(pkesk) = packet {
                    let key_id = match pkesk {
                        PublicKeyEncryptedSessionKey::V3 { id, .. } => {
                            // KeyId uses Display with lowercase hex, convert to uppercase
                            format!("{}", id).to_uppercase()
                        }
                        PublicKeyEncryptedSessionKey::V6 { fingerprint, .. } => {
                            // V6 PKESK uses fingerprint
                            if let Some(fp) = fingerprint {
                                format!("{}", fp).to_uppercase()
                            } else {
                                // Anonymous recipient
                                continue;
                            }
                        }
                        PublicKeyEncryptedSessionKey::Other { .. } => {
                            // Unknown version, skip
                            continue;
                        }
                    };
                    key_ids.push(key_id);
                }
            }
            Err(_) => {
                // Stop on parsing error (we've probably hit encrypted data)
                break;
            }
        }
    }

    Ok(key_ids)
}

/// Get the key IDs that a file was encrypted for.
///
/// # Arguments
/// * `path` - Path to the encrypted file
///
/// # Returns
/// A list of key IDs (hex strings) that can decrypt this file.
pub fn file_encrypted_for(path: impl AsRef<Path>) -> Result<Vec<String>> {
    let ciphertext = std::fs::read(path.as_ref())?;
    bytes_encrypted_for(&ciphertext)
}

/// Helper to find valid encryption subkeys from a public key.
fn find_valid_encryption_subkeys(key: &SignedPublicKey) -> Result<Vec<crate::pgp::composed::SignedPublicSubKey>> {
    let mut valid_keys = Vec::new();

    for subkey in &key.public_subkeys {
        // Check if the subkey can encrypt
        if !subkey.key.algorithm().can_encrypt() {
            continue;
        }

        // Check key flags in binding signature
        let has_encryption_flag = subkey.signatures.iter().any(|sig| {
            let flags = sig.key_flags();
            flags.encrypt_comms() || flags.encrypt_storage()
        });

        if !has_encryption_flag {
            continue;
        }

        // Check if subkey is valid (not revoked, not expired)
        if !is_subkey_valid(subkey, false) {
            continue;
        }

        valid_keys.push(subkey.clone());
    }

    if valid_keys.is_empty() {
        return Err(Error::NoEncryptionSubkey);
    }

    Ok(valid_keys)
}

#[cfg(test)]
mod tests {
    // Tests would require key fixtures
}
