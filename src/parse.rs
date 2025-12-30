//! Certificate parsing functions.
//!
//! This module provides functions for parsing OpenPGP certificates from
//! various sources and extracting information from them.

use std::path::Path;

use pgp::composed::SignedPublicKey;
use pgp::types::KeyDetails;

use crate::error::Result;
use crate::internal::{
    fingerprint_to_hex, get_algorithm_name, get_key_bit_size, is_subkey_revoked, is_subkey_valid,
    keyid_to_hex, parse_cert, system_time_to_datetime,
};
use crate::types::{AvailableSubkey, CertificateInfo, KeyCipherDetails, KeyType, SubkeyInfo};

/// Parse a certificate from bytes and extract its information.
///
/// # Arguments
/// * `data` - Certificate data (armored or binary)
/// * `allow_expired` - If true, allows parsing of expired certificates
///
/// # Returns
/// Certificate information including user IDs, fingerprint, and subkey details.
///
/// # Example
/// ```ignore
/// let cert_data = std::fs::read("key.asc")?;
/// let info = parse_cert_bytes(&cert_data, false)?;
/// println!("Fingerprint: {}", info.fingerprint);
/// ```
pub fn parse_cert_bytes(data: &[u8], allow_expired: bool) -> Result<CertificateInfo> {
    let (public_key, is_secret) = parse_cert(data)?;
    extract_cert_info(&public_key, is_secret, allow_expired)
}

/// Parse a certificate from a file and extract its information.
///
/// # Arguments
/// * `path` - Path to the certificate file
/// * `allow_expired` - If true, allows parsing of expired certificates
///
/// # Returns
/// Certificate information including user IDs, fingerprint, and subkey details.
pub fn parse_cert_file(path: impl AsRef<Path>, allow_expired: bool) -> Result<CertificateInfo> {
    let data = std::fs::read(path.as_ref())?;
    parse_cert_bytes(&data, allow_expired)
}

/// Get cipher details for all keys in a certificate.
///
/// # Arguments
/// * `data` - Certificate data (armored or binary)
///
/// # Returns
/// A list of cipher details for the primary key and all subkeys.
pub fn get_key_cipher_details(data: &[u8]) -> Result<Vec<KeyCipherDetails>> {
    let (public_key, _) = parse_cert(data)?;
    let mut details = Vec::new();

    // Primary key
    details.push(KeyCipherDetails {
        fingerprint: fingerprint_to_hex(&public_key.primary_key),
        algorithm: get_algorithm_name(&public_key.primary_key),
        bit_length: get_key_bit_size(&public_key.primary_key),
    });

    // Subkeys
    for subkey in &public_key.public_subkeys {
        details.push(KeyCipherDetails {
            fingerprint: fingerprint_to_hex(&subkey.key),
            algorithm: get_algorithm_name(&subkey.key),
            bit_length: get_key_bit_size(&subkey.key),
        });
    }

    Ok(details)
}

/// Extract certificate information from a parsed cert.
fn extract_cert_info(
    public_key: &SignedPublicKey,
    is_secret: bool,
    allow_expired: bool,
) -> Result<CertificateInfo> {
    // Get user IDs
    let user_ids: Vec<String> = public_key
        .details
        .users
        .iter()
        .map(|u| String::from_utf8_lossy(u.id.id()).to_string())
        .collect();

    // Primary key info
    let fingerprint = fingerprint_to_hex(&public_key.primary_key);
    let key_id = keyid_to_hex(&public_key.primary_key);
    let creation_time = system_time_to_datetime(public_key.primary_key.created_at().into());

    // Get expiration time from user signatures
    let expiration_time = crate::internal::get_key_expiration(public_key).map(system_time_to_datetime);

    // Check if primary can sign
    let can_primary_sign = crate::internal::can_primary_sign(public_key);

    // Get subkey info
    let subkeys = extract_subkey_info(public_key, allow_expired);

    Ok(CertificateInfo {
        user_ids,
        fingerprint,
        key_id,
        is_secret,
        creation_time,
        expiration_time,
        can_primary_sign,
        subkeys,
    })
}

/// Extract information about all subkeys.
fn extract_subkey_info(public_key: &SignedPublicKey, allow_expired: bool) -> Vec<SubkeyInfo> {
    let mut subkeys = Vec::new();

    for subkey in &public_key.public_subkeys {
        let key_id = keyid_to_hex(&subkey.key);
        let fingerprint = fingerprint_to_hex(&subkey.key);
        let creation_time = system_time_to_datetime(subkey.key.created_at().into());

        // Get expiration from binding signature
        let expiration_time = subkey.signatures.first().and_then(|sig| {
            sig.key_expiration_time().map(|validity| {
                let creation: std::time::SystemTime = subkey.key.created_at().into();
                system_time_to_datetime(creation + validity.into())
            })
        });

        let is_revoked = is_subkey_revoked(subkey);
        let algorithm = get_algorithm_name(&subkey.key);
        let bit_length = get_key_bit_size(&subkey.key);

        // Determine key type based on key flags
        let key_type = determine_key_type(subkey);

        // Only include if valid or allowing expired
        if allow_expired || is_subkey_valid(subkey, false) {
            subkeys.push(SubkeyInfo {
                key_id,
                fingerprint,
                creation_time,
                expiration_time,
                key_type,
                is_revoked,
                algorithm,
                bit_length,
            });
        }
    }

    subkeys
}

/// Determine the key type from subkey binding signature.
fn determine_key_type(subkey: &pgp::composed::SignedPublicSubKey) -> KeyType {
    for sig in &subkey.signatures {
        let flags = sig.key_flags();
        if flags.encrypt_comms() || flags.encrypt_storage() {
            return KeyType::Encryption;
        } else if flags.sign() {
            return KeyType::Signing;
        } else if flags.authentication() {
            return KeyType::Authentication;
        } else if flags.certify() {
            return KeyType::Certification;
        }
    }
    KeyType::Unknown
}

/// Get available encryption subkeys (valid, not expired, not revoked).
///
/// # Arguments
/// * `data` - Certificate data (armored or binary)
///
/// # Returns
/// List of available encryption subkeys.
pub fn get_available_encryption_subkeys(data: &[u8]) -> Result<Vec<AvailableSubkey>> {
    get_available_subkeys_by_type(data, |flags| {
        flags.encrypt_comms() || flags.encrypt_storage()
    })
}

/// Get available signing subkeys (valid, not expired, not revoked).
///
/// # Arguments
/// * `data` - Certificate data (armored or binary)
///
/// # Returns
/// List of available signing subkeys.
pub fn get_available_signing_subkeys(data: &[u8]) -> Result<Vec<AvailableSubkey>> {
    get_available_subkeys_by_type(data, |flags| flags.sign())
}

/// Get available authentication subkeys (valid, not expired, not revoked).
///
/// # Arguments
/// * `data` - Certificate data (armored or binary)
///
/// # Returns
/// List of available authentication subkeys.
pub fn get_available_authentication_subkeys(data: &[u8]) -> Result<Vec<AvailableSubkey>> {
    get_available_subkeys_by_type(data, |flags| flags.authentication())
}

/// Get all available subkeys (valid, not expired, not revoked).
///
/// # Arguments
/// * `data` - Certificate data (armored or binary)
///
/// # Returns
/// List of all available subkeys.
pub fn get_all_available_subkeys(data: &[u8]) -> Result<Vec<AvailableSubkey>> {
    get_available_subkeys_by_type(data, |_| true)
}

/// Internal function to get available subkeys matching a predicate.
fn get_available_subkeys_by_type<F>(data: &[u8], predicate: F) -> Result<Vec<AvailableSubkey>>
where
    F: Fn(&pgp::packet::KeyFlags) -> bool,
{
    let (public_key, _) = parse_cert(data)?;
    let mut available = Vec::new();

    for subkey in &public_key.public_subkeys {
        // Skip revoked keys
        if is_subkey_revoked(subkey) {
            continue;
        }

        // Skip invalid/expired keys
        if !is_subkey_valid(subkey, false) {
            continue;
        }

        // Check key flags
        let matches_predicate = subkey.signatures.iter().any(|sig| {
            let flags = sig.key_flags();
            predicate(&flags)
        });

        if !matches_predicate {
            continue;
        }

        let key_type = determine_key_type(subkey);

        let expiration_time = subkey.signatures.first().and_then(|sig| {
            sig.key_expiration_time().map(|validity| {
                let creation: std::time::SystemTime = subkey.key.created_at().into();
                system_time_to_datetime(creation + validity.into())
            })
        });

        available.push(AvailableSubkey {
            fingerprint: fingerprint_to_hex(&subkey.key),
            key_id: keyid_to_hex(&subkey.key),
            creation_time: system_time_to_datetime(subkey.key.created_at().into()),
            expiration_time,
            key_type,
            algorithm: get_algorithm_name(&subkey.key),
            bit_length: get_key_bit_size(&subkey.key),
        });
    }

    Ok(available)
}

/// Check if a certificate has any available encryption subkeys.
///
/// # Arguments
/// * `data` - Certificate data (armored or binary)
///
/// # Returns
/// True if at least one valid encryption subkey is available.
pub fn has_available_encryption_subkey(data: &[u8]) -> Result<bool> {
    Ok(!get_available_encryption_subkeys(data)?.is_empty())
}

/// Check if a certificate has any available signing subkeys.
///
/// # Arguments
/// * `data` - Certificate data (armored or binary)
///
/// # Returns
/// True if at least one valid signing subkey is available.
pub fn has_available_signing_subkey(data: &[u8]) -> Result<bool> {
    Ok(!get_available_signing_subkeys(data)?.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests would require key fixtures
}
