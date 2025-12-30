//! Verification functions.
//!
//! This module provides functions for verifying OpenPGP signatures
//! on messages and files.

use std::io::Cursor;
use std::path::Path;

use pgp::composed::{
    CleartextSignedMessage, Deserializable, DetachedSignature, Message, SignedPublicKey,
};

use crate::error::{Error, Result};
use crate::internal::parse_public_key;

/// Verify a signed message (inline or cleartext signature).
///
/// # Arguments
/// * `signer_cert` - The signer's public key (armored or binary)
/// * `signed_message` - The signed message data
///
/// # Returns
/// `true` if the signature is valid, `false` otherwise.
///
/// # Example
/// ```ignore
/// let public_key = std::fs::read("signer.asc")?;
/// let signed_msg = std::fs::read("message.asc")?;
/// let valid = verify_bytes(&public_key, &signed_msg)?;
/// ```
pub fn verify_bytes(signer_cert: &[u8], signed_message: &[u8]) -> Result<bool> {
    let public_key = parse_public_key(signer_cert)?;

    // Try cleartext signature first
    if let Ok(result) = verify_cleartext(&public_key, signed_message) {
        return Ok(result);
    }

    // Try inline signed message
    verify_inline_signed(&public_key, signed_message)
}

/// Verify and extract the original message from signed bytes.
///
/// # Arguments
/// * `signer_cert` - The signer's public key
/// * `signed_message` - The signed message data
///
/// # Returns
/// The original message content if the signature is valid.
pub fn verify_and_extract_bytes(signer_cert: &[u8], signed_message: &[u8]) -> Result<Vec<u8>> {
    let public_key = parse_public_key(signer_cert)?;

    // Try cleartext signature first
    if let Some(content) = extract_cleartext(&public_key, signed_message)? {
        return Ok(content);
    }

    // Try inline signed message
    extract_inline_signed(&public_key, signed_message)
}

/// Verify a detached signature on bytes.
///
/// # Arguments
/// * `signer_cert` - The signer's public key
/// * `data` - The original data that was signed
/// * `signature` - The detached signature (armored or binary)
///
/// # Returns
/// `true` if the signature is valid.
pub fn verify_bytes_detached(
    signer_cert: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<bool> {
    let public_key = parse_public_key(signer_cert)?;

    // Parse the detached signature
    let sig = match DetachedSignature::from_armor_single(Cursor::new(signature)) {
        Ok((result, _headers)) => result,
        Err(_) => {
            // Try binary format
            match DetachedSignature::from_bytes(Cursor::new(signature)) {
                Ok(result) => result,
                Err(_) => return Ok(false),
            }
        }
    };

    // Try verifying against primary key
    if sig.verify(&public_key.primary_key, data).is_ok() {
        return Ok(true);
    }

    // Try verifying against subkeys
    for subkey in &public_key.public_subkeys {
        if sig.verify(&subkey.key, data).is_ok() {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Verify a signed file.
///
/// # Arguments
/// * `signer_cert` - The signer's public key
/// * `signed_file` - Path to the signed file
///
/// # Returns
/// `true` if the signature is valid.
pub fn verify_file(signer_cert: &[u8], signed_file: impl AsRef<Path>) -> Result<bool> {
    let signed_message = std::fs::read(signed_file.as_ref())?;
    verify_bytes(signer_cert, &signed_message)
}

/// Verify and extract a signed file to an output path.
///
/// # Arguments
/// * `signer_cert` - The signer's public key
/// * `signed_file` - Path to the signed file
/// * `output` - Path to write the extracted content
pub fn verify_and_extract_file(
    signer_cert: &[u8],
    signed_file: impl AsRef<Path>,
    output: impl AsRef<Path>,
) -> Result<()> {
    let signed_message = std::fs::read(signed_file.as_ref())?;
    let content = verify_and_extract_bytes(signer_cert, &signed_message)?;
    std::fs::write(output.as_ref(), content)?;
    Ok(())
}

/// Verify a detached signature on a file.
///
/// # Arguments
/// * `signer_cert` - The signer's public key
/// * `file` - Path to the original file
/// * `signature` - The detached signature (armored or binary)
///
/// # Returns
/// `true` if the signature is valid.
pub fn verify_file_detached(
    signer_cert: &[u8],
    file: impl AsRef<Path>,
    signature: &[u8],
) -> Result<bool> {
    let data = std::fs::read(file.as_ref())?;
    verify_bytes_detached(signer_cert, &data, signature)
}

/// Verify a cleartext signed message.
fn verify_cleartext(public_key: &SignedPublicKey, signed_message: &[u8]) -> Result<bool> {
    // Try to parse as cleartext signed message
    let text = String::from_utf8_lossy(signed_message);
    let (msg, _) = CleartextSignedMessage::from_string(&text)
        .map_err(|e| Error::Parse(e.to_string()))?;

    // Try verifying against primary key
    if msg.verify(&public_key.primary_key).is_ok() {
        return Ok(true);
    }

    // Try verifying against subkeys
    for subkey in &public_key.public_subkeys {
        if msg.verify(&subkey.key).is_ok() {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Extract content from a cleartext signed message after verification.
fn extract_cleartext(public_key: &SignedPublicKey, signed_message: &[u8]) -> Result<Option<Vec<u8>>> {
    // Try to parse as cleartext signed message
    let text = match String::from_utf8(signed_message.to_vec()) {
        Ok(t) => t,
        Err(_) => return Ok(None),
    };

    let (msg, _) = match CleartextSignedMessage::from_string(&text) {
        Ok(result) => result,
        Err(_) => return Ok(None),
    };

    // Try verifying against primary key
    if msg.verify(&public_key.primary_key).is_ok() {
        // Normalize CRLF to LF (OpenPGP cleartext signatures use CRLF internally)
        let content = normalize_line_endings(&msg.signed_text());
        return Ok(Some(content));
    }

    // Try verifying against subkeys
    for subkey in &public_key.public_subkeys {
        if msg.verify(&subkey.key).is_ok() {
            let content = normalize_line_endings(&msg.signed_text());
            return Ok(Some(content));
        }
    }

    Ok(None)
}

/// Normalize CRLF line endings to LF.
fn normalize_line_endings(text: &str) -> Vec<u8> {
    text.replace("\r\n", "\n").into_bytes()
}

/// Verify an inline signed message.
fn verify_inline_signed(public_key: &SignedPublicKey, signed_message: &[u8]) -> Result<bool> {
    // Try armored first, then binary
    let mut message = match Message::from_armor(Cursor::new(signed_message)) {
        Ok((msg, _headers)) => msg,
        Err(_) => Message::from_bytes(signed_message)
            .map_err(|e| Error::Parse(e.to_string()))?,
    };

    // Handle compression if needed
    if message.is_compressed() {
        message = message.decompress()
            .map_err(|e| Error::Parse(e.to_string()))?;
    }

    // Read the message content (required before verification)
    let _ = message.as_data_vec()
        .map_err(|e| Error::Parse(e.to_string()))?;

    // Try verifying against primary key
    if message.verify(&public_key.primary_key).is_ok() {
        return Ok(true);
    }

    // Try verifying against subkeys
    for subkey in &public_key.public_subkeys {
        if message.verify(&subkey.key).is_ok() {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Extract content from an inline signed message after verification.
fn extract_inline_signed(public_key: &SignedPublicKey, signed_message: &[u8]) -> Result<Vec<u8>> {
    // Try armored first, then binary
    let mut message = match Message::from_armor(Cursor::new(signed_message)) {
        Ok((msg, _headers)) => msg,
        Err(_) => Message::from_bytes(signed_message)
            .map_err(|e| Error::Parse(e.to_string()))?,
    };

    // Handle compression if needed
    if message.is_compressed() {
        message = message.decompress()
            .map_err(|e| Error::Parse(e.to_string()))?;
    }

    // Read the message content
    let content = message.as_data_vec()
        .map_err(|e| Error::Parse(e.to_string()))?;

    // Try verifying against primary key
    if message.verify(&public_key.primary_key).is_ok() {
        return Ok(content);
    }

    // Try verifying against subkeys
    for subkey in &public_key.public_subkeys {
        if message.verify(&subkey.key).is_ok() {
            return Ok(content);
        }
    }

    Err(Error::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests would require key fixtures
}
