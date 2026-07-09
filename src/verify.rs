//! OpenPGP signature verification helpers.
//!
//! The verification functions accept armored or binary public certificate bytes
//! and verify inline, cleartext, detached, and file signatures. Revoked primary
//! certificates and revoked signing subkeys are ignored. Expired keys may still
//! verify signatures made while the key was valid, matching OpenPGP's usual
//! semantics.

use std::io::Cursor;
use std::path::Path;

use pgp::composed::{
    CleartextSignedMessage, Deserializable, DetachedSignature, Message, SignedPublicKey,
};

use crate::error::{Error, Result};
use crate::internal::{
    can_subkey_sign, is_primary_key_valid_for_verification, is_subkey_revoked, parse_public_key,
};

/// Verify a signed message (inline or cleartext signature).
///
/// Checks key revocation before verifying the signature.
/// Returns `false` if the signing key is revoked. Expired keys can
/// still verify old signatures — expiry only prevents new signatures.
///
/// # Arguments
/// * `signer_key` - The signer's public key (armored or binary)
/// * `signed_message` - The signed message data
///
/// # Returns
/// `true` if the signature is valid, `false` otherwise.
///
/// # Example
/// ```no_run
/// use wecanencrypt::verify_bytes;
///
/// let public_key = std::fs::read("signer.asc").unwrap();
/// let signed_msg = std::fs::read("message.asc").unwrap();
/// let valid = verify_bytes(&public_key, &signed_msg).unwrap();
/// assert!(valid);
/// ```
pub fn verify_bytes(signer_key: &[u8], signed_message: &[u8]) -> Result<bool> {
    let public_key = parse_public_key(signer_key)?;

    // Try cleartext signature first
    if let Ok(result) = verify_cleartext(&public_key, signed_message) {
        return Ok(result);
    }

    // Try inline signed message
    verify_inline_signed(&public_key, signed_message)
}

/// Verify and extract the original message from signed bytes.
///
/// Checks key revocation before verifying the signature.
///
/// # Arguments
/// * `signer_key` - The signer's public key
/// * `signed_message` - The signed message data
///
/// # Returns
/// The original message content if the signature is valid.
pub fn verify_and_extract_bytes(signer_key: &[u8], signed_message: &[u8]) -> Result<Vec<u8>> {
    let public_key = parse_public_key(signer_key)?;

    // Try cleartext signature first
    if let Some(content) = extract_cleartext(&public_key, signed_message)? {
        return Ok(content);
    }

    // Try inline signed message
    extract_inline_signed(&public_key, signed_message)
}

/// Verify a detached signature on bytes.
///
/// Checks key revocation before verifying the signature.
/// Returns `false` if the signing key is revoked. Expired keys can
/// still verify old signatures.
///
/// # Arguments
/// * `signer_key` - The signer's public key
/// * `data` - The original data that was signed
/// * `signature` - The detached signature (armored or binary)
///
/// # Returns
/// `true` if the signature is valid.
pub fn verify_bytes_detached(signer_key: &[u8], data: &[u8], signature: &[u8]) -> Result<bool> {
    let public_key = parse_public_key(signer_key)?;

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

    if !is_primary_key_valid_for_verification(&public_key) {
        return Ok(false);
    }

    // Try verifying against primary key
    if sig.verify(&public_key.primary_key, data).is_ok() {
        return Ok(true);
    }

    // Try verifying against non-revoked subkeys only. The primary certificate
    // revocation check above applies to these subkey signatures too.
    for subkey in &public_key.public_subkeys {
        if can_subkey_sign(&public_key.primary_key, subkey)
            && !is_subkey_revoked(&public_key.primary_key, subkey)
            && sig.verify(&subkey.key, data).is_ok()
        {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Verify a signed file.
///
/// # Arguments
/// * `signer_key` - The signer's public key
/// * `signed_file` - Path to the signed file
///
/// # Returns
/// `true` if the signature is valid.
pub fn verify_file(signer_key: &[u8], signed_file: impl AsRef<Path>) -> Result<bool> {
    let signed_message = std::fs::read(signed_file.as_ref())?;
    verify_bytes(signer_key, &signed_message)
}

/// Verify and extract a signed file to an output path.
///
/// # Arguments
/// * `signer_key` - The signer's public key
/// * `signed_file` - Path to the signed file
/// * `output` - Path to write the extracted content
pub fn verify_and_extract_file(
    signer_key: &[u8],
    signed_file: impl AsRef<Path>,
    output: impl AsRef<Path>,
) -> Result<()> {
    let signed_message = std::fs::read(signed_file.as_ref())?;
    let content = verify_and_extract_bytes(signer_key, &signed_message)?;
    std::fs::write(output.as_ref(), content)?;
    Ok(())
}

/// Verify a detached signature on a file.
///
/// # Arguments
/// * `signer_key` - The signer's public key
/// * `file` - Path to the original file
/// * `signature` - The detached signature (armored or binary)
///
/// # Returns
/// `true` if the signature is valid.
pub fn verify_file_detached(
    signer_key: &[u8],
    file: impl AsRef<Path>,
    signature: &[u8],
) -> Result<bool> {
    let data = std::fs::read(file.as_ref())?;
    verify_bytes_detached(signer_key, &data, signature)
}

/// Verify a cleartext signed message.
fn verify_cleartext(public_key: &SignedPublicKey, signed_message: &[u8]) -> Result<bool> {
    // Try to parse as cleartext signed message
    let text = String::from_utf8_lossy(signed_message);
    let (msg, _) =
        CleartextSignedMessage::from_string(&text).map_err(|e| Error::Parse(e.to_string()))?;

    if !is_primary_key_valid_for_verification(public_key) {
        return Ok(false);
    }

    // Try verifying against primary key
    if msg.verify(&public_key.primary_key).is_ok() {
        return Ok(true);
    }

    // Try verifying against non-revoked subkeys only. The primary certificate
    // revocation check above applies to these subkey signatures too.
    for subkey in &public_key.public_subkeys {
        if can_subkey_sign(&public_key.primary_key, subkey)
            && !is_subkey_revoked(&public_key.primary_key, subkey)
            && msg.verify(&subkey.key).is_ok()
        {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Extract content from a cleartext signed message after verification.
fn extract_cleartext(
    public_key: &SignedPublicKey,
    signed_message: &[u8],
) -> Result<Option<Vec<u8>>> {
    // Try to parse as cleartext signed message
    let text = match String::from_utf8(signed_message.to_vec()) {
        Ok(t) => t,
        Err(_) => return Ok(None),
    };

    let (msg, _) = match CleartextSignedMessage::from_string(&text) {
        Ok(result) => result,
        Err(_) => return Ok(None),
    };

    if !is_primary_key_valid_for_verification(public_key) {
        return Ok(None);
    }

    // Try verifying against primary key
    if msg.verify(&public_key.primary_key).is_ok() {
        let content = normalize_line_endings(&msg.signed_text());
        return Ok(Some(content));
    }

    // Try verifying against non-revoked subkeys only. The primary certificate
    // revocation check above applies to these subkey signatures too.
    for subkey in &public_key.public_subkeys {
        if can_subkey_sign(&public_key.primary_key, subkey)
            && !is_subkey_revoked(&public_key.primary_key, subkey)
            && msg.verify(&subkey.key).is_ok()
        {
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
        Err(_) => Message::from_bytes(signed_message).map_err(|e| Error::Parse(e.to_string()))?,
    };

    // Handle compression if needed
    if message.is_compressed() {
        message = message
            .decompress()
            .map_err(|e| Error::Parse(e.to_string()))?;
    }

    // Read the message content (required before verification)
    let _ = message
        .as_data_vec()
        .map_err(|e| Error::Parse(e.to_string()))?;

    if !is_primary_key_valid_for_verification(public_key) {
        return Ok(false);
    }

    // Try verifying against primary key
    if message.verify(&public_key.primary_key).is_ok() {
        return Ok(true);
    }

    // Try verifying against non-revoked subkeys only. The primary certificate
    // revocation check above applies to these subkey signatures too.
    for subkey in &public_key.public_subkeys {
        if can_subkey_sign(&public_key.primary_key, subkey)
            && !is_subkey_revoked(&public_key.primary_key, subkey)
            && message.verify(&subkey.key).is_ok()
        {
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
        Err(_) => Message::from_bytes(signed_message).map_err(|e| Error::Parse(e.to_string()))?,
    };

    // Handle compression if needed
    if message.is_compressed() {
        message = message
            .decompress()
            .map_err(|e| Error::Parse(e.to_string()))?;
    }

    // Read the message content
    let content = message
        .as_data_vec()
        .map_err(|e| Error::Parse(e.to_string()))?;

    if !is_primary_key_valid_for_verification(public_key) {
        return Err(Error::VerificationFailed);
    }

    // Try verifying against primary key
    if message.verify(&public_key.primary_key).is_ok() {
        return Ok(content);
    }

    // Try verifying against non-revoked subkeys only. The primary certificate
    // revocation check above applies to these subkey signatures too.
    for subkey in &public_key.public_subkeys {
        if can_subkey_sign(&public_key.primary_key, subkey)
            && !is_subkey_revoked(&public_key.primary_key, subkey)
            && message.verify(&subkey.key).is_ok()
        {
            return Ok(content);
        }
    }

    Err(Error::VerificationFailed)
}

#[cfg(test)]
mod tests {
    // Tests would require key fixtures
}
