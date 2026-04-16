//! Keyring file operations.
//!
//! This module provides functions for reading and writing OpenPGP
//! keyring files that contain multiple certificates.

use std::io::Cursor;
use std::path::Path;

use pgp::composed::{Deserializable, SignedPublicKey};
use pgp::packet::Signature;
use pgp::ser::Serialize;
use pgp::types::KeyDetails;

use crate::error::{Error, Result};
use crate::internal::{fingerprint_to_hex, parse_cert, public_key_to_armored};
use crate::parse::parse_cert_bytes;
use crate::types::CertificateInfo;

/// Parse a keyring file containing multiple certificates.
///
/// # Arguments
/// * `path` - Path to the keyring file
///
/// # Returns
/// A list of (CertificateInfo, raw_bytes) for each certificate in the keyring.
///
/// # Example
/// ```ignore
/// // Ignored: illustrative example with placeholder file path
/// let certs = parse_keyring_file("pubring.gpg")?;
/// for (info, bytes) in certs {
///     println!("Key: {} - {}", info.fingerprint, info.user_ids.first().unwrap_or(&"".to_string()));
/// }
/// ```
pub fn parse_keyring_file(path: impl AsRef<Path>) -> Result<Vec<(CertificateInfo, Vec<u8>)>> {
    let keyring_data = std::fs::read(path.as_ref())?;
    parse_keyring_bytes(&keyring_data)
}

/// Parse keyring data containing multiple certificates.
///
/// # Arguments
/// * `data` - Keyring data (armored or binary)
///
/// # Returns
/// A list of (CertificateInfo, raw_bytes) for each certificate.
pub fn parse_keyring_bytes(data: &[u8]) -> Result<Vec<(CertificateInfo, Vec<u8>)>> {
    let mut results = Vec::new();

    // Try to parse as multiple public keys
    let cursor = Cursor::new(data);
    let (keys_iter, _headers) =
        SignedPublicKey::from_reader_many(cursor).map_err(|e| Error::Parse(e.to_string()))?;

    for key_result in keys_iter {
        match key_result {
            Ok(key) => {
                let bytes = key.to_bytes().map_err(|e| Error::Crypto(e.to_string()))?;
                let info = parse_cert_bytes(&bytes, true)?;
                results.push((info, bytes));
            }
            Err(e) => {
                // Log error but continue parsing other certs
                eprintln!("Warning: failed to parse certificate: {}", e);
            }
        }
    }

    Ok(results)
}

/// Export multiple certificates to a keyring file.
///
/// # Arguments
/// * `certs` - Slice of certificate data
/// * `output` - Path to write the keyring file
///
/// # Example
/// ```ignore
/// // Ignored: illustrative example with placeholder file paths
/// let cert1 = std::fs::read("key1.asc")?;
/// let cert2 = std::fs::read("key2.asc")?;
/// export_keyring_file(&[&cert1, &cert2], "combined.gpg")?;
/// ```
pub fn export_keyring_file(certs: &[&[u8]], output: impl AsRef<Path>) -> Result<()> {
    let mut keyring_data = Vec::new();

    for cert_data in certs {
        let (public_key, _is_secret) = parse_cert(cert_data)?;
        let bytes = public_key
            .to_bytes()
            .map_err(|e| Error::Crypto(e.to_string()))?;
        keyring_data.extend_from_slice(&bytes);
    }

    std::fs::write(output.as_ref(), keyring_data)?;
    Ok(())
}

/// Export multiple certificates to an armored keyring.
///
/// # Arguments
/// * `certs` - Slice of certificate data
///
/// # Returns
/// ASCII-armored keyring containing all certificates.
pub fn export_keyring_armored(certs: &[&[u8]]) -> Result<String> {
    let mut all_armored = String::new();

    for cert_data in certs {
        let (public_key, _is_secret) = parse_cert(cert_data)?;
        let armored = public_key_to_armored(&public_key)?;
        all_armored.push_str(&armored);
        all_armored.push('\n');
    }

    Ok(all_armored)
}

/// Merge two certificates with the same primary key fingerprint.
///
/// Merges new information (signatures, user IDs, subkeys, user attributes)
/// from `update_data` into `cert_data`. This follows the same approach as
/// rsop/rpgpie: deduplication of components and signatures, with new
/// components added and new signatures merged into existing components.
///
/// # Arguments
/// * `cert_data` - The original certificate (armored or binary)
/// * `update_data` - The certificate with new data to merge (armored or binary)
/// * `force` - If true, merge even if the keys have different fingerprints
///
/// # Returns
/// The merged certificate as binary bytes.
///
/// # Errors
/// * [`Error::InvalidInput`] if fingerprints don't match and `force` is false
pub fn merge_keys(cert_data: &[u8], update_data: &[u8], force: bool) -> Result<Vec<u8>> {
    let (mut orig, _) = parse_cert(cert_data)?;
    let (update, _) = parse_cert(update_data)?;

    let fp1 = fingerprint_to_hex(&orig.primary_key);
    let fp2 = fingerprint_to_hex(&update.primary_key);

    if fp1 != fp2 && !force {
        return Err(Error::InvalidInput(format!(
            "Certificate fingerprints do not match: {} vs {}",
            fp1, fp2
        )));
    }

    merge_cert(&mut orig, update);

    orig.to_bytes().map_err(|e| Error::Crypto(e.to_string()))
}

/// Merge the contents of `update` into `orig` in place.
///
/// Merges:
/// - Direct key signatures
/// - Revocation signatures
/// - Subkeys (and their binding/revocation signatures)
/// - User IDs (and their certification/revocation signatures)
/// - User attributes (and their signatures)
fn merge_cert(orig: &mut SignedPublicKey, update: SignedPublicKey) {
    // Direct key signatures
    merge_signatures(&mut orig.details.direct_signatures, update.details.direct_signatures);

    // Revocation signatures
    merge_signatures(
        &mut orig.details.revocation_signatures,
        update.details.revocation_signatures,
    );

    // Subkeys: match by fingerprint, merge sigs for existing, add new ones
    for sk_update in update.public_subkeys {
        if let Some(existing) = orig
            .public_subkeys
            .iter_mut()
            .find(|sk| sk.fingerprint() == sk_update.fingerprint())
        {
            merge_signatures(&mut existing.signatures, sk_update.signatures);
        } else {
            orig.public_subkeys.push(sk_update);
        }
    }

    // User IDs: match by raw ID bytes, merge sigs for existing, add new ones
    for uid_update in update.details.users {
        if let Some(existing) = orig
            .details
            .users
            .iter_mut()
            .find(|u| u.id.id() == uid_update.id.id())
        {
            merge_signatures(&mut existing.signatures, uid_update.signatures);
        } else {
            orig.details.users.push(uid_update);
        }
    }

    // User attributes: match by attribute content, merge sigs for existing, add new ones
    for attr_update in update.details.user_attributes {
        if let Some(existing) = orig
            .details
            .user_attributes
            .iter_mut()
            .find(|a| a.attr == attr_update.attr)
        {
            merge_signatures(&mut existing.signatures, attr_update.signatures);
        } else {
            orig.details.user_attributes.push(attr_update);
        }
    }
}

/// Checks if two signatures contain the same cryptographic signature bytes.
///
/// Two signature packets are considered equal if they produce the same
/// signature bytes, even if they differ in packet framing or unhashed
/// subpackets.
fn signature_bytes_eq(a: &Signature, b: &Signature) -> bool {
    if let (Some(sb1), Some(sb2)) = (a.signature(), b.signature()) {
        sb1 == sb2
    } else {
        a == b
    }
}

/// Merge signatures from `updates` into `target`, deduplicating by signature bytes.
///
/// For signatures already present in `target` (matched by cryptographic signature
/// bytes), any additional unhashed subpackets from the update are merged in.
/// Entirely new signatures are appended.
fn merge_signatures(target: &mut Vec<Signature>, updates: Vec<Signature>) {
    for upd in updates {
        if let Some(existing) = target.iter_mut().find(|s| signature_bytes_eq(s, &upd)) {
            // Signature already present - merge any new unhashed subpackets
            merge_unhashed(existing, &upd);
        } else {
            target.push(upd);
        }
    }
}

/// Merge additional unhashed subpackets from `source` into `target`.
fn merge_unhashed(target: &mut Signature, source: &Signature) {
    let mut inserts = Vec::new();

    if let (Some(c1), Some(c2)) = (target.config(), source.config()) {
        for (pos, sub) in c2.unhashed_subpackets.iter().enumerate() {
            if !c1.unhashed_subpackets.contains(sub) {
                inserts.push((pos, sub.clone()));
            }
        }
    }

    for (pos, sp) in inserts {
        let _ = target.unhashed_subpacket_insert(pos, sp);
    }
}

#[cfg(test)]
mod tests {
    // Tests would require key fixtures
}
