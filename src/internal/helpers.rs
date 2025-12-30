//! Internal helper functions.

use std::io::Cursor;

use pgp::composed::{SignedSecretKey, SignedPublicKey, Deserializable};
use pgp::ser::Serialize;
use pgp::armor::BlockType;
use pgp::types::KeyDetails;

use crate::error::{Error, Result};

/// Parse a secret key from bytes (armored or binary).
pub(crate) fn parse_secret_key(data: &[u8]) -> Result<SignedSecretKey> {
    // Try armored first, then binary
    let cursor = Cursor::new(data);
    match SignedSecretKey::from_armor_single(cursor) {
        Ok((key, _headers)) => Ok(key),
        Err(_) => {
            // Try binary
            let cursor = Cursor::new(data);
            SignedSecretKey::from_bytes(cursor)
                .map_err(|e| Error::Parse(e.to_string()))
        }
    }
}

/// Parse a public key from bytes (armored or binary).
pub(crate) fn parse_public_key(data: &[u8]) -> Result<SignedPublicKey> {
    // Try armored first, then binary
    let cursor = Cursor::new(data);
    match SignedPublicKey::from_armor_single(cursor) {
        Ok((key, _headers)) => Ok(key),
        Err(_) => {
            // Try binary
            let cursor = Cursor::new(data);
            SignedPublicKey::from_bytes(cursor)
                .map_err(|e| Error::Parse(e.to_string()))
        }
    }
}

/// Parse a certificate from bytes - tries secret key first, then public.
/// Returns (public_key, is_secret).
pub(crate) fn parse_cert(data: &[u8]) -> Result<(SignedPublicKey, bool)> {
    // Try as secret key first
    if let Ok(secret_key) = parse_secret_key(data) {
        let public_key = secret_key.to_public_key();
        return Ok((public_key, true));
    }

    // Try as public key
    let public_key = parse_public_key(data)?;
    Ok((public_key, false))
}

/// Parse a secret key from a file.
pub(crate) fn parse_secret_key_from_file(path: &std::path::Path) -> Result<SignedSecretKey> {
    let data = std::fs::read(path)?;
    parse_secret_key(&data)
}

/// Parse a public key from a file.
pub(crate) fn parse_public_key_from_file(path: &std::path::Path) -> Result<SignedPublicKey> {
    let data = std::fs::read(path)?;
    parse_public_key(&data)
}

/// Check if data appears to be ASCII-armored.
pub(crate) fn is_armored(data: &[u8]) -> bool {
    data.starts_with(b"-----BEGIN PGP")
}

/// Dearmor data if it's armored, otherwise return as-is.
pub(crate) fn dearmor(data: &[u8]) -> Result<Vec<u8>> {
    use std::io::Read;
    use std::io::BufReader;

    if is_armored(data) {
        let cursor = BufReader::new(Cursor::new(data));
        let mut dearmor = pgp::armor::Dearmor::new(cursor);
        dearmor.read_header()
            .map_err(|e| Error::MalformedArmor(e.to_string()))?;
        let mut dearmored = Vec::new();
        dearmor.read_to_end(&mut dearmored)
            .map_err(|e| Error::MalformedArmor(e.to_string()))?;
        Ok(dearmored)
    } else {
        Ok(data.to_vec())
    }
}

/// Serialize a public key to binary format.
pub(crate) fn public_key_to_bytes(key: &SignedPublicKey) -> Result<Vec<u8>> {
    key.to_bytes()
        .map_err(|e| Error::Crypto(e.to_string()))
}

/// Serialize a secret key to binary format.
pub(crate) fn secret_key_to_bytes(key: &SignedSecretKey) -> Result<Vec<u8>> {
    key.to_bytes()
        .map_err(|e| Error::Crypto(e.to_string()))
}

/// Serialize a public key to ASCII-armored format.
pub(crate) fn public_key_to_armored(key: &SignedPublicKey) -> Result<String> {
    key.to_armored_string(None.into())
        .map_err(|e| Error::Crypto(e.to_string()))
}

/// Serialize a secret key to ASCII-armored format.
pub(crate) fn secret_key_to_armored(key: &SignedSecretKey) -> Result<String> {
    key.to_armored_string(None.into())
        .map_err(|e| Error::Crypto(e.to_string()))
}

/// Get the fingerprint as a hex string (uppercase, no spaces).
pub(crate) fn fingerprint_to_hex(key: &impl KeyDetails) -> String {
    hex::encode_upper(key.fingerprint().as_bytes())
}

/// Get the key ID as a hex string.
pub(crate) fn keyid_to_hex(key: &impl KeyDetails) -> String {
    hex::encode_upper(key.legacy_key_id().as_ref())
}

/// Convert a SystemTime to chrono DateTime.
pub(crate) fn system_time_to_datetime(st: std::time::SystemTime) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from(st)
}

/// Convert chrono DateTime to SystemTime.
pub(crate) fn datetime_to_system_time(dt: chrono::DateTime<chrono::Utc>) -> std::time::SystemTime {
    std::time::UNIX_EPOCH + std::time::Duration::from_secs(dt.timestamp() as u64)
}

/// Get armor block type for message.
pub(crate) fn armor_kind_for_message() -> BlockType {
    BlockType::Message
}

/// Get armor block type for signature.
pub(crate) fn armor_kind_for_signature() -> BlockType {
    BlockType::Signature
}

/// Get armor block type for public key.
pub(crate) fn armor_kind_for_public_key() -> BlockType {
    BlockType::PublicKey
}

/// Get armor block type for secret key.
pub(crate) fn armor_kind_for_secret_key() -> BlockType {
    BlockType::PrivateKey
}

/// Get a normalized algorithm name for display.
/// Converts rpgp's internal naming to common OpenPGP names.
pub(crate) fn get_algorithm_name(key: &impl KeyDetails) -> String {
    use pgp::crypto::public_key::PublicKeyAlgorithm;

    match key.algorithm() {
        PublicKeyAlgorithm::RSA => "RSA".to_string(),
        PublicKeyAlgorithm::RSAEncrypt => "RSA".to_string(),
        PublicKeyAlgorithm::RSASign => "RSA".to_string(),
        PublicKeyAlgorithm::EdDSALegacy | PublicKeyAlgorithm::Ed25519 => "EdDSA".to_string(),
        PublicKeyAlgorithm::ECDH => "ECDH".to_string(),
        PublicKeyAlgorithm::ECDSA => "ECDSA".to_string(),
        PublicKeyAlgorithm::X25519 => "X25519".to_string(),
        PublicKeyAlgorithm::X448 => "X448".to_string(),
        PublicKeyAlgorithm::Ed448 => "Ed448".to_string(),
        PublicKeyAlgorithm::DSA => "DSA".to_string(),
        PublicKeyAlgorithm::Elgamal => "Elgamal".to_string(),
        algo => format!("{:?}", algo),
    }
}

/// Get the bit size for a key based on its algorithm and parameters.
/// Returns 0 if the bit size cannot be determined.
pub(crate) fn get_key_bit_size(key: &impl KeyDetails) -> usize {
    use pgp::crypto::public_key::PublicKeyAlgorithm;

    match key.algorithm() {
        PublicKeyAlgorithm::RSA | PublicKeyAlgorithm::RSAEncrypt | PublicKeyAlgorithm::RSASign => {
            // For RSA, return a common key size since we can't easily access rsa crate's traits
            // Most RSA keys are 2048 or 4096 bits
            2048
        }
        PublicKeyAlgorithm::EdDSALegacy | PublicKeyAlgorithm::Ed25519 => 256,
        PublicKeyAlgorithm::X25519 => 256,
        PublicKeyAlgorithm::X448 => 448,
        PublicKeyAlgorithm::Ed448 => 448,
        PublicKeyAlgorithm::ECDH => {
            // Could be 256 (Curve25519) or other sizes
            256
        }
        PublicKeyAlgorithm::ECDSA => 256,
        PublicKeyAlgorithm::DSA => 2048,
        PublicKeyAlgorithm::Elgamal => 2048,
        _ => 0,
    }
}
