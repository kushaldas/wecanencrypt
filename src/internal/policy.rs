//! Key validation and algorithm policy functions.
//!
//! rpgp doesn't have a policy system like sequoia, so we implement
//! manual validation of key properties here. This includes:
//! - Key expiration and revocation checks
//! - Key flag validation

use std::time::SystemTime;

use pgp::composed::{SignedKeyDetails, SignedPublicKey, SignedPublicSubKey};
use pgp::packet::SignatureType;
use pgp::types::KeyDetails;

use crate::error::{Error, Result};

/// Purpose-specific policy for signing-capable keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)] // KeyMaintenance is used only with the `card` feature
pub(crate) enum SigningKeyUsage {
    /// Ordinary document, message, or detached signatures.
    DataSignature,
    /// Self-maintenance operations like extending the key's own expiry.
    KeyMaintenance,
}

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

    // Check expiration if not allowing expired.
    // Use the most recent binding signature by creation time (per RFC 4880 §5.2.3.3),
    // not the last one in packet order — renewed keys have multiple binding signatures
    // and older ones may have expired even though the latest renewal is still valid.
    if !allow_expired {
        let most_recent_sig = subkey
            .signatures
            .iter()
            .filter(|sig| sig.key_expiration_time().is_some())
            .max_by_key(|sig| sig.created().map(|t| t.as_secs()).unwrap_or(0));
        if let Some(sig) = most_recent_sig {
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

/// Check if key details have the signing flag set.
///
/// This is the single source of truth for primary-key signing-capability checks.
/// Both `SignedPublicKey` and `SignedSecretKey` share `details: SignedKeyDetails`,
/// so callers can pass `&key.details` regardless of key type.
pub(crate) fn can_details_sign(details: &SignedKeyDetails) -> bool {
    for user in &details.users {
        for sig in &user.signatures {
            if sig.key_flags().sign() {
                return true;
            }
        }
    }
    false
}

/// Check if primary key can sign (has signing flag).
///
/// Convenience wrapper over [`can_details_sign`] for `SignedPublicKey`.
pub(crate) fn can_primary_sign(key: &SignedPublicKey) -> bool {
    can_details_sign(&key.details)
}

/// Check if primary key has the certify flag.
///
/// Used by card operations: a Certify-capable primary key can produce
/// signatures when explicitly uploaded to the card's signing slot.
#[cfg(feature = "card")]
pub(crate) fn can_primary_certify(key: &SignedPublicKey) -> bool {
    key.details
        .users
        .iter()
        .any(|u| u.signatures.iter().any(|sig| sig.key_flags().certify()))
}

/// Check if key details indicate revocation.
///
/// This is the single source of truth for primary-key revocation checks.
/// Both `SignedPublicKey` and `SignedSecretKey` share `details: SignedKeyDetails`,
/// so callers can pass `&key.details` regardless of key type.
pub(crate) fn is_details_revoked(details: &SignedKeyDetails) -> bool {
    details
        .revocation_signatures
        .iter()
        .any(|sig| sig.typ() == Some(SignatureType::KeyRevocation))
}

/// Check if the primary key is revoked.
pub(crate) fn is_primary_key_revoked(key: &SignedPublicKey) -> bool {
    is_details_revoked(&key.details)
}

/// Check if the primary key is valid for verification (not revoked).
///
/// Note: Expiry is NOT checked here because expired keys should still
/// verify old signatures — expiry means "don't create new signatures",
/// not "existing signatures are invalid".
pub(crate) fn is_primary_key_valid_for_verification(key: &SignedPublicKey) -> bool {
    !is_primary_key_revoked(key)
}

/// Compute primary-key expiration from key details and creation time.
///
/// This is the single source of truth for primary-key expiry calculation.
/// Both `SignedPublicKey` and `SignedSecretKey` share `details: SignedKeyDetails`,
/// so callers can pass `&key.details` regardless of key type.
///
/// Per RFC 4880, newer self-signatures supersede older ones. We find
/// the self-signature with the latest creation timestamp that contains
/// a key expiration subpacket.
pub(crate) fn primary_expiration_from_details(
    creation_time: SystemTime,
    details: &SignedKeyDetails,
) -> Option<SystemTime> {
    let mut newest_created: Option<SystemTime> = None;
    let mut newest_expiration = None;

    for user in &details.users {
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

/// Validate whether a key may be used for a specific signing purpose.
///
/// Works with the shared `SignedKeyDetails` and creation time so it can be
/// called for both public and secret keys.
pub(crate) fn validate_signing_usage(
    creation_time: SystemTime,
    details: &SignedKeyDetails,
    usage: SigningKeyUsage,
) -> Result<()> {
    if is_details_revoked(details) {
        return Err(Error::KeyRevoked);
    }

    if matches!(usage, SigningKeyUsage::DataSignature) {
        if let Some(exp) = primary_expiration_from_details(creation_time, details) {
            if exp < SystemTime::now() {
                return Err(Error::KeyExpired);
            }
        }
    }

    Ok(())
}

/// Validate whether the primary key may be used for a specific signing purpose.
///
/// Convenience wrapper over [`validate_signing_usage`] for `SignedPublicKey`.
#[cfg(feature = "card")]
pub(crate) fn validate_primary_key_signing_usage(
    key: &SignedPublicKey,
    usage: SigningKeyUsage,
) -> Result<()> {
    validate_signing_usage(key.primary_key.created_at().into(), &key.details, usage)
}

/// Get the expiration time for a key from the most recent self-signature.
///
/// Convenience wrapper over [`primary_expiration_from_details`] for `SignedPublicKey`.
pub(crate) fn get_key_expiration(key: &SignedPublicKey) -> Option<SystemTime> {
    primary_expiration_from_details(key.primary_key.created_at().into(), &key.details)
}
