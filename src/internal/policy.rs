//! Key validation and algorithm policy functions.
//!
//! rpgp doesn't have a policy system like sequoia, so we implement
//! manual validation of key properties here. This includes:
//! - Key expiration and revocation checks
//! - Key flag validation

use std::time::SystemTime;

use pgp::composed::{SignedPublicKey, SignedPublicSubKey};
use pgp::packet::SignatureType;
use pgp::types::KeyDetails;

/// Check if a key has expired based on its creation time and validity period.
pub(crate) fn is_key_expired(creation_time: SystemTime, validity_seconds: Option<u64>) -> bool {
    if let Some(validity) = validity_seconds {
        if validity == 0 {
            return false; // No expiration
        }
        let expiration = creation_time + std::time::Duration::from_secs(validity);
        expiration < SystemTime::now()
    } else {
        false // No expiration set
    }
}

/// Check if a subkey is revoked.
pub(crate) fn is_subkey_revoked(subkey: &SignedPublicSubKey) -> bool {
    subkey
        .signatures
        .iter()
        .any(|sig| sig.typ() == Some(SignatureType::SubkeyRevocation))
}

/// Check if a key is valid for use (not expired, not revoked).
pub(crate) fn is_subkey_valid(subkey: &SignedPublicSubKey, allow_expired: bool) -> bool {
    // Check revocation
    if is_subkey_revoked(subkey) {
        return false;
    }

    // Check expiration if not allowing expired
    if !allow_expired {
        // Get expiration from the LAST (most recent) binding signature
        if let Some(sig) = subkey.signatures.last() {
            if let Some(validity) = sig.key_expiration_time() {
                let creation_time: SystemTime = subkey.key.created_at().into();
                if is_key_expired(creation_time, Some(validity.as_secs() as u64)) {
                    return false;
                }
            }
        }
    }

    true
}

/// Check if primary key can sign (has signing flag).
pub(crate) fn can_primary_sign(key: &SignedPublicKey) -> bool {
    // Check user binding signatures for key flags
    for user in &key.details.users {
        for sig in &user.signatures {
            let flags = sig.key_flags();
            if flags.sign() {
                return true;
            }
        }
    }
    false
}

/// Check if the primary key is revoked.
pub(crate) fn is_primary_key_revoked(key: &SignedPublicKey) -> bool {
    key.details
        .revocation_signatures
        .iter()
        .any(|sig| sig.typ() == Some(SignatureType::KeyRevocation))
}

/// Check if the primary key is valid for verification (not revoked).
///
/// Note: Expiry is NOT checked here because expired keys should still
/// verify old signatures — expiry means "don't create new signatures",
/// not "existing signatures are invalid".
pub(crate) fn is_primary_key_valid_for_verification(key: &SignedPublicKey) -> bool {
    !is_primary_key_revoked(key)
}

/// Get the expiration time for a key from the most recent self-signature.
///
/// Per RFC 4880, newer self-signatures supersede older ones. We find
/// the self-signature with the latest creation timestamp that contains
/// a key expiration subpacket.
pub(crate) fn get_key_expiration(key: &SignedPublicKey) -> Option<SystemTime> {
    let creation_time: SystemTime = key.primary_key.created_at().into();
    let mut newest_created: Option<SystemTime> = None;
    let mut newest_expiration = None;

    for user in &key.details.users {
        for sig in &user.signatures {
            if let Some(validity) = sig.key_expiration_time() {
                let sig_created: Option<SystemTime> = sig.created().map(|ts| ts.into());
                // Pick the signature with the latest creation timestamp
                let is_newer = match (&newest_created, &sig_created) {
                    (Some(prev), Some(cur)) => cur > prev,
                    (None, Some(_)) => true,
                    (None, None) => newest_expiration.is_none(),
                    _ => false,
                };
                if is_newer {
                    newest_created = sig_created;
                    newest_expiration = Some(creation_time + validity.into());
                }
            }
        }
    }

    newest_expiration
}
