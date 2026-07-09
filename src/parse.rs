//! OpenPGP key parsing and inspection helpers.
//!
//! Parsing functions accept a public or secret certificate in ASCII armor or
//! binary form and return stable, application-facing summaries such as
//! [`KeyInfo`], [`SubkeyInfo`], and [`KeyCipherDetails`]. The summaries
//! distinguish public-only material from secret material, expose V4/V6 key
//! versions, report revoked user IDs/subkeys, and include third-party UID
//! certifications when present.

use std::path::Path;

use pgp::composed::SignedPublicKey;
use pgp::types::KeyDetails;

use crate::error::Result;
use crate::internal::{
    classify_key_algorithm, fingerprint_to_hex, get_algorithm_name, get_key_bit_size,
    is_subkey_revoked, keyid_to_hex, most_recent_verified_binding_sig, parse_key,
    subkey_binding_expiration_time, system_time_to_datetime, verified_primary_revocation,
    verified_usable_subkey_binding, verified_user_id_revocation,
};
use crate::types::{
    AvailableSubkey, KeyCipherDetails, KeyInfo, KeyType, SubkeyInfo, UIDCertification, UserIDInfo,
};

/// Parse an OpenPGP key from bytes and extract its information.
///
/// # Arguments
/// * `data` - Key data (armored or binary)
/// * `allow_expired` - If true, allows parsing of expired keys
///
/// # Returns
/// Key information including user IDs, fingerprint, and subkey details.
///
/// # Example
/// ```no_run
/// use wecanencrypt::parse_key_bytes;
///
/// let key_data = std::fs::read("key.asc").unwrap();
/// let info = parse_key_bytes(&key_data, false).unwrap();
/// println!("Fingerprint: {}", info.fingerprint);
/// ```
pub fn parse_key_bytes(data: &[u8], allow_expired: bool) -> Result<KeyInfo> {
    let (public_key, is_secret) = parse_key(data)?;
    extract_key_info(&public_key, is_secret, allow_expired)
}

/// Parse an OpenPGP key from a file and extract its information.
///
/// # Arguments
/// * `path` - Path to the key file
/// * `allow_expired` - If true, allows parsing of expired keys
///
/// # Returns
/// Key information including user IDs, fingerprint, and subkey details.
///
/// # Example
/// ```no_run
/// use wecanencrypt::parse_key_file;
///
/// let info = parse_key_file("alice.asc", false).unwrap();
/// println!("{} has {} subkeys", info.fingerprint, info.subkeys.len());
/// ```
pub fn parse_key_file(path: impl AsRef<Path>, allow_expired: bool) -> Result<KeyInfo> {
    let data = std::fs::read(path.as_ref())?;
    parse_key_bytes(&data, allow_expired)
}

/// Get cipher details for all keys in an OpenPGP key bundle.
///
/// # Arguments
/// * `data` - Key data (armored or binary)
///
/// # Returns
/// A list of cipher details for the primary key and all subkeys.
///
/// # Example
/// ```no_run
/// use wecanencrypt::get_key_cipher_details;
///
/// let key = std::fs::read("alice.asc").unwrap();
/// for part in get_key_cipher_details(&key).unwrap() {
///     println!("{}: {} ({} bits)", part.fingerprint, part.algorithm, part.bit_length);
/// }
/// ```
pub fn get_key_cipher_details(data: &[u8]) -> Result<Vec<KeyCipherDetails>> {
    let (public_key, _) = parse_key(data)?;
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

/// Extract OpenPGP key information from a parsed key.
fn extract_key_info(
    public_key: &SignedPublicKey,
    is_secret: bool,
    allow_expired: bool,
) -> Result<KeyInfo> {
    // Get user IDs with certification details
    let primary_fp = fingerprint_to_hex(&public_key.primary_key);
    let user_ids: Vec<UserIDInfo> = public_key
        .details
        .users
        .iter()
        .map(|u| {
            let value = String::from_utf8_lossy(u.id.id()).to_string();

            // Check revocation: any CertRevocation signature on this UID
            // that cryptographically verifies as signed by the primary key.
            let revocation_sig = verified_user_id_revocation(&public_key.primary_key, u);
            let revoked = revocation_sig.is_some();
            let revocation_time = revocation_sig.and_then(|sig| sig.created()).map(|ts| {
                let st: std::time::SystemTime = ts.into();
                system_time_to_datetime(st)
            });

            // Collect third-party certifications (exclude self-signatures)
            let certifications = u
                .signatures
                .iter()
                .filter_map(|sig| {
                    let sig_type = sig.typ()?;
                    let cert_type_str = match sig_type {
                        pgp::packet::SignatureType::CertGeneric => "generic",
                        pgp::packet::SignatureType::CertPersona => "persona",
                        pgp::packet::SignatureType::CertCasual => "casual",
                        pgp::packet::SignatureType::CertPositive => "positive",
                        _ => return None,
                    };

                    // Collect issuer info
                    let mut issuers: Vec<(String, String)> = Vec::new();
                    for fp in sig.issuer_fingerprint() {
                        let fp_hex = hex::encode_upper(fp.as_bytes());
                        // Skip self-signatures (issuer == primary key)
                        if fp_hex == primary_fp {
                            return None;
                        }
                        issuers.push(("fingerprint".to_string(), fp_hex));
                    }
                    for kid in sig.issuer_key_id() {
                        issuers.push(("keyid".to_string(), hex::encode_upper(kid.as_ref())));
                    }

                    // If no issuers found, it might still be a self-sig without fingerprint subpacket
                    if issuers.is_empty() {
                        return None;
                    }

                    let creation_time = sig.created().map(|ts| {
                        let st: std::time::SystemTime = ts.into();
                        system_time_to_datetime(st)
                    });

                    Some(UIDCertification {
                        certification_type: cert_type_str.to_string(),
                        creation_time,
                        issuers,
                    })
                })
                .collect();

            // Check if this UID is marked as primary via the PrimaryUserId subpacket
            let is_primary = u.is_primary();

            UserIDInfo {
                value,
                revoked,
                is_primary,
                revocation_time,
                certifications,
            }
        })
        .collect();

    // Primary key info
    let fingerprint = fingerprint_to_hex(&public_key.primary_key);
    let key_id = keyid_to_hex(&public_key.primary_key);
    let creation_time = system_time_to_datetime(public_key.primary_key.created_at().into());

    // Get expiration time from user signatures
    let expiration_time =
        crate::internal::get_key_expiration(public_key).map(system_time_to_datetime);

    // Check if primary can sign
    let can_primary_sign = crate::internal::can_primary_sign(public_key);

    // Check key revocation: any KeyRevocation signature that
    // cryptographically verifies as signed by the primary key.
    let revocation_sig = verified_primary_revocation(public_key);
    let is_revoked = revocation_sig.is_some();
    let revocation_time = revocation_sig.and_then(|sig| sig.created()).map(|ts| {
        let st: std::time::SystemTime = ts.into();
        system_time_to_datetime(st)
    });

    // Get subkey info
    let subkeys = extract_subkey_info(public_key, allow_expired);

    let key_version = public_key.primary_key.version();

    let primary_algorithm_detail = classify_key_algorithm(&public_key.primary_key);

    Ok(KeyInfo {
        user_ids,
        fingerprint,
        key_id,
        is_secret,
        creation_time,
        expiration_time,
        can_primary_sign,
        is_revoked,
        revocation_time,
        subkeys,
        key_version,
        primary_algorithm_detail,
    })
}

/// Extract information about all subkeys.
fn extract_subkey_info(public_key: &SignedPublicKey, allow_expired: bool) -> Vec<SubkeyInfo> {
    let mut subkeys = Vec::new();

    for subkey in &public_key.public_subkeys {
        let key_id = keyid_to_hex(&subkey.key);
        let fingerprint = fingerprint_to_hex(&subkey.key);
        let creation_time = system_time_to_datetime(subkey.key.created_at().into());

        // Read metadata from the most recent verified subkey-binding signature
        // (RFC 4880 §11.1: the latest binding sig is authoritative for
        // the binding's properties). `signatures.first()` returns
        // whatever happens to be first in the packet stream, which after
        // a `merge_signatures` re-import is the OLDEST binding (existing
        // sigs are kept first, new sigs appended) - making a renewed key
        // look as if its original (long-since-expired) binding still
        // governs the subkey. Aligns with `verified_usable_subkey_binding`
        // which already uses the most-recent-binding rule.
        let binding = if allow_expired {
            most_recent_verified_binding_sig(&public_key.primary_key, subkey)
        } else {
            verified_usable_subkey_binding(&public_key.primary_key, subkey, false)
        };

        // Only include if valid or allowing expired.
        if !allow_expired && binding.is_none() {
            continue;
        }

        let expiration_time = binding
            .and_then(|sig| subkey_binding_expiration_time(sig, subkey))
            .map(system_time_to_datetime);

        let is_revoked = is_subkey_revoked(&public_key.primary_key, subkey);
        let algorithm = get_algorithm_name(&subkey.key);
        let algorithm_detail = classify_key_algorithm(&subkey.key);
        let bit_length = get_key_bit_size(&subkey.key);

        // Determine key type based on key flags
        let key_type = determine_key_type(binding);

        let key_version = subkey.key.version();

        subkeys.push(SubkeyInfo {
            key_id,
            fingerprint,
            creation_time,
            expiration_time,
            key_type,
            is_revoked,
            algorithm,
            algorithm_detail,
            bit_length,
            key_version,
        });
    }

    subkeys
}

/// Determine the key type from subkey binding signature.
fn determine_key_type(binding: Option<&pgp::packet::Signature>) -> KeyType {
    // RFC 4880 §11.1: the most recent binding signature is authoritative
    // for subkey key flags. Iterating every sig and returning on the
    // first match accepts capabilities that may have been stripped by
    // a re-binding.
    if let Some(sig) = binding {
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
/// * `data` - Key data (armored or binary)
///
/// # Returns
/// List of available encryption subkeys.
///
/// # Example
/// ```no_run
/// use wecanencrypt::get_available_encryption_subkeys;
///
/// let key = std::fs::read("recipient.asc").unwrap();
/// let encryption_subkeys = get_available_encryption_subkeys(&key).unwrap();
/// assert!(!encryption_subkeys.is_empty());
/// ```
pub fn get_available_encryption_subkeys(data: &[u8]) -> Result<Vec<AvailableSubkey>> {
    get_available_subkeys_by_type(data, |flags| {
        flags.encrypt_comms() || flags.encrypt_storage()
    })
}

/// Get available signing subkeys (valid, not expired, not revoked).
///
/// # Arguments
/// * `data` - Key data (armored or binary)
///
/// # Returns
/// List of available signing subkeys.
///
/// # Example
/// ```no_run
/// use wecanencrypt::get_available_signing_subkeys;
///
/// let key = std::fs::read("signer.asc").unwrap();
/// for subkey in get_available_signing_subkeys(&key).unwrap() {
///     println!("signing subkey {}", subkey.fingerprint);
/// }
/// ```
pub fn get_available_signing_subkeys(data: &[u8]) -> Result<Vec<AvailableSubkey>> {
    get_available_subkeys_by_type(data, |flags| flags.sign())
}

/// Get available authentication subkeys (valid, not expired, not revoked).
///
/// # Arguments
/// * `data` - Key data (armored or binary)
///
/// # Returns
/// List of available authentication subkeys.
///
/// # Example
/// ```no_run
/// use wecanencrypt::get_available_authentication_subkeys;
///
/// let key = std::fs::read("ssh-key.asc").unwrap();
/// let auth_subkeys = get_available_authentication_subkeys(&key).unwrap();
/// println!("{} authentication-capable subkeys", auth_subkeys.len());
/// ```
pub fn get_available_authentication_subkeys(data: &[u8]) -> Result<Vec<AvailableSubkey>> {
    get_available_subkeys_by_type(data, |flags| flags.authentication())
}

/// Get all available subkeys (valid, not expired, not revoked).
///
/// # Arguments
/// * `data` - Key data (armored or binary)
///
/// # Returns
/// List of all available subkeys.
///
/// # Example
/// ```no_run
/// use wecanencrypt::get_all_available_subkeys;
///
/// let key = std::fs::read("alice.asc").unwrap();
/// let usable = get_all_available_subkeys(&key).unwrap();
/// for subkey in usable {
///     println!("{:?}: {}", subkey.key_type, subkey.fingerprint);
/// }
/// ```
pub fn get_all_available_subkeys(data: &[u8]) -> Result<Vec<AvailableSubkey>> {
    get_available_subkeys_by_type(data, |_| true)
}

/// Internal function to get available subkeys matching a predicate.
fn get_available_subkeys_by_type<F>(data: &[u8], predicate: F) -> Result<Vec<AvailableSubkey>>
where
    F: Fn(&pgp::packet::KeyFlags) -> bool,
{
    let (public_key, _) = parse_key(data)?;
    let mut available = Vec::new();

    for subkey in &public_key.public_subkeys {
        // Verify the binding once. It is then reused for validity, key flags,
        // and expiration instead of repeating the public-key operation.
        let Some(binding) = verified_usable_subkey_binding(&public_key.primary_key, subkey, false)
        else {
            continue;
        };

        let flags = binding.key_flags();
        let matches_predicate = predicate(&flags);

        if !matches_predicate {
            continue;
        }

        let key_type = determine_key_type(Some(binding));

        // Same most-recent-binding rule for the expiration. See
        // `extract_subkey_info` for the reasoning.
        let expiration_time =
            subkey_binding_expiration_time(binding, subkey).map(system_time_to_datetime);

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

/// Check if an OpenPGP key has any available encryption subkeys.
///
/// # Arguments
/// * `data` - Key data (armored or binary)
///
/// # Returns
/// True if at least one valid encryption subkey is available.
///
/// # Example
/// ```no_run
/// use wecanencrypt::has_available_encryption_subkey;
///
/// let key = std::fs::read("recipient.asc").unwrap();
/// if has_available_encryption_subkey(&key).unwrap() {
///     println!("key can receive encrypted messages");
/// }
/// ```
pub fn has_available_encryption_subkey(data: &[u8]) -> Result<bool> {
    Ok(!get_available_encryption_subkeys(data)?.is_empty())
}

/// Check if an OpenPGP key has any available signing subkeys.
///
/// # Arguments
/// * `data` - Key data (armored or binary)
///
/// # Returns
/// True if at least one valid signing subkey is available.
///
/// # Example
/// ```no_run
/// use wecanencrypt::has_available_signing_subkey;
///
/// let key = std::fs::read("signer.asc").unwrap();
/// assert!(has_available_signing_subkey(&key).unwrap());
/// ```
pub fn has_available_signing_subkey(data: &[u8]) -> Result<bool> {
    Ok(!get_available_signing_subkeys(data)?.is_empty())
}

#[cfg(test)]
mod tests {
    // Tests would require key fixtures
}
