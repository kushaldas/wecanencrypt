//! Key validation and algorithm policy functions.
//!
//! rpgp doesn't have a policy system like sequoia, so we implement
//! manual validation of key properties here. This includes:
//! - Key expiration and revocation checks
//! - Key flag validation
//!
//! # Revocation-signature verification
//!
//! rpgp's parser admits any packet tagged `KeyRevocation` (type 0x20),
//! `SubkeyRevocation` (0x28), or `CertRevocation` (0x30) into the
//! parsed key without cryptographically verifying the signature on it.
//! Before this module, wecanencrypt trusted those packet-type tags at
//! face value, so an attacker who could inject packets into a cert
//! (keyserver poisoning, MITM on HKP fetch, tampered file) could forge
//! a revocation that wecanencrypt would honor. See ADR 0004.
//!
//! Every revocation check in this module now verifies the signature
//! against the primary key using rpgp's `Signature::verify_key`,
//! `verify_subkey_binding`, or `verify_certification` as appropriate.

use std::time::SystemTime;

use pgp::composed::{SignedPublicKey, SignedPublicSubKey, SignedSecretKey, SignedSecretSubKey};
use pgp::packet::{Signature, SignatureType};
use pgp::ser::Serialize;
use pgp::types::{KeyDetails, SignedUser, Tag, VerifyingKey};

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

/// Shared core: does any `SubkeyRevocation` packet on `signatures`
/// cryptographically verify as a binding-revocation signed by `primary`
/// over `subkey_key`?
///
/// Works for both `SignedPublicSubKey` and `SignedSecretSubKey` because
/// `verify_subkey_binding` only needs the subkey to implement
/// `KeyDetails + Serialize` — both `PublicSubkey` and `SecretSubkey` do.
fn any_verified_subkey_revocation<V, K>(
    primary: &V,
    signatures: &[Signature],
    subkey_key: &K,
) -> bool
where
    V: VerifyingKey + Serialize,
    K: KeyDetails + Serialize,
{
    signatures
        .iter()
        .filter(|sig| sig.typ() == Some(SignatureType::SubkeyRevocation))
        .any(|sig| sig.verify_subkey_binding(primary, subkey_key).is_ok())
}

/// Check if a public subkey carries a cryptographically valid
/// self-revocation from the primary key.
pub(crate) fn is_subkey_revoked(
    primary: &pgp::packet::PublicKey,
    subkey: &SignedPublicSubKey,
) -> bool {
    any_verified_subkey_revocation(primary, &subkey.signatures, &subkey.key)
}

/// Check if a secret subkey carries a cryptographically valid
/// self-revocation from the primary key.
///
/// The signature hash must be recomputed over the *public* subkey
/// packet (tag 14), never the secret subkey packet (tag 7). rpgp's
/// `Serialize` impls for `PublicSubkey` and `SecretSubkey` produce
/// different byte streams, so passing `&subkey.key` directly would
/// always fail verification against a signature computed by any
/// conforming implementation — including rpgp's own signing paths.
pub(crate) fn is_secret_subkey_revoked(
    primary: &pgp::packet::PublicKey,
    subkey: &SignedSecretSubKey,
) -> bool {
    any_verified_subkey_revocation(primary, &subkey.signatures, subkey.key.public_key())
}

/// Find the most recent cryptographically verified binding signature for a
/// public subkey.
pub(crate) fn most_recent_verified_binding_sig<'a>(
    primary: &pgp::packet::PublicKey,
    subkey: &'a SignedPublicSubKey,
) -> Option<&'a pgp::packet::Signature> {
    subkey
        .signatures
        .iter()
        .filter(|sig| sig.typ() == Some(SignatureType::SubkeyBinding))
        .filter(|sig| sig.verify_subkey_binding(primary, &subkey.key).is_ok())
        .max_by_key(|sig| sig.created().map(|t| t.as_secs()).unwrap_or(0))
}

/// Find the most recent cryptographically verified binding signature for a
/// secret subkey.
pub(crate) fn most_recent_verified_secret_binding_sig<'a>(
    primary: &pgp::packet::PublicKey,
    subkey: &'a SignedSecretSubKey,
) -> Option<&'a pgp::packet::Signature> {
    subkey
        .signatures
        .iter()
        .filter(|sig| sig.typ() == Some(SignatureType::SubkeyBinding))
        .filter(|sig| {
            sig.verify_subkey_binding(primary, subkey.key.public_key())
                .is_ok()
        })
        .max_by_key(|sig| sig.created().map(|t| t.as_secs()).unwrap_or(0))
}

/// Check whether a verified subkey binding signature grants signing use.
pub(crate) fn subkey_binding_can_sign(binding: &Signature) -> bool {
    binding.key_flags().sign()
}

/// Check whether a verified subkey binding signature grants encryption use.
pub(crate) fn subkey_binding_can_encrypt(binding: &Signature) -> bool {
    let flags = binding.key_flags();
    flags.encrypt_comms() || flags.encrypt_storage()
}

/// Check whether a verified subkey binding signature grants authentication use.
pub(crate) fn subkey_binding_can_authenticate(binding: &Signature) -> bool {
    binding.key_flags().authentication()
}

/// Compute the expiration time described by a verified subkey binding.
pub(crate) fn subkey_binding_expiration_time(
    binding: &Signature,
    subkey: &SignedPublicSubKey,
) -> Option<SystemTime> {
    let creation_time: SystemTime = subkey.key.created_at().into();
    subkey_binding_expiration_from_creation(binding, creation_time)
}

fn subkey_binding_expiration_from_creation(
    binding: &Signature,
    creation_time: SystemTime,
) -> Option<SystemTime> {
    binding.key_expiration_time().and_then(|validity| {
        if validity.as_secs() == 0 {
            None
        } else {
            Some(creation_time + validity.into())
        }
    })
}

fn subkey_binding_is_expired_from_creation(binding: &Signature, creation_time: SystemTime) -> bool {
    binding
        .key_expiration_time()
        .map(|validity| is_key_expired(creation_time, Some(validity.as_secs() as u64)))
        .unwrap_or(false)
}

/// Return the most recent verified binding only if the subkey is usable
/// under the current revocation and expiration policy.
pub(crate) fn verified_usable_subkey_binding<'a>(
    primary: &pgp::packet::PublicKey,
    subkey: &'a SignedPublicSubKey,
    allow_expired: bool,
) -> Option<&'a Signature> {
    let binding = most_recent_verified_binding_sig(primary, subkey)?;

    if is_subkey_revoked(primary, subkey) {
        return None;
    }

    let creation_time: SystemTime = subkey.key.created_at().into();
    if !allow_expired && subkey_binding_is_expired_from_creation(binding, creation_time) {
        return None;
    }

    Some(binding)
}

/// Return the most recent verified binding only if the secret subkey is usable
/// under the current revocation and expiration policy.
pub(crate) fn verified_usable_secret_subkey_binding<'a>(
    primary: &pgp::packet::PublicKey,
    subkey: &'a SignedSecretSubKey,
    allow_expired: bool,
) -> Option<&'a Signature> {
    let binding = most_recent_verified_secret_binding_sig(primary, subkey)?;

    if is_secret_subkey_revoked(primary, subkey) {
        return None;
    }

    let creation_time: SystemTime = subkey.key.created_at().into();
    if !allow_expired && subkey_binding_is_expired_from_creation(binding, creation_time) {
        return None;
    }

    Some(binding)
}

/// Check if a subkey has the signing capability flag in its most recent
/// verified binding signature.
///
/// Per RFC 4880 §5.2.3.3, the most recent binding signature is
/// authoritative for subkey key flags. The binding signature must verify
/// against the primary key before its flags are trusted.
pub(crate) fn can_subkey_sign(
    primary: &pgp::packet::PublicKey,
    subkey: &SignedPublicSubKey,
) -> bool {
    most_recent_verified_binding_sig(primary, subkey)
        .map(subkey_binding_can_sign)
        .unwrap_or(false)
}

fn is_uid_certification_signature(sig: &pgp::packet::Signature) -> bool {
    matches!(
        sig.typ(),
        Some(SignatureType::CertGeneric)
            | Some(SignatureType::CertPersona)
            | Some(SignatureType::CertCasual)
            | Some(SignatureType::CertPositive)
    )
}

/// Find the most recent cryptographically verified self-signature for a user ID.
///
/// Per RFC 4880 §5.2.3.3, newer self-signatures supersede older ones.
/// Only the self-signature with the latest creation timestamp is
/// authoritative for key flags, preferences, and other properties.
///
/// Returns `None` if the user has no verified self-certification.
fn most_recent_verified_self_sig<'a>(
    primary: &pgp::packet::PublicKey,
    user: &'a pgp::types::SignedUser,
) -> Option<&'a pgp::packet::Signature> {
    user.signatures
        .iter()
        .filter(|sig| is_uid_certification_signature(sig))
        .filter(|sig| {
            sig.verify_certification(primary, Tag::UserId, &user.id)
                .is_ok()
        })
        .max_by_key(|sig| sig.created().map(|t| t.as_secs()).unwrap_or(0))
}

/// Check if key details have the signing flag set on the most recent
/// self-signature.
///
/// Per RFC 4880 §5.2.3.3, only the most recent self-signature per UID
/// is authoritative. This checks whether any UID's most recent
/// self-signature grants the signing capability.
///
/// This is the single source of truth for primary-key signing-capability checks.
/// The self-signature must verify against `primary` before its key flags are
/// trusted.
pub(crate) fn can_details_sign(
    primary: &pgp::packet::PublicKey,
    details: &pgp::composed::SignedKeyDetails,
) -> bool {
    for user in &details.users {
        if let Some(sig) = most_recent_verified_self_sig(primary, user) {
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
    can_details_sign(&key.primary_key, &key.details)
}

/// Check if a secret primary key can sign (has signing flag).
pub(crate) fn can_secret_primary_sign(key: &SignedSecretKey) -> bool {
    can_details_sign(key.primary_key.public_key(), &key.details)
}

/// Check if primary key has the certify flag on the most recent
/// self-signature.
///
/// Per RFC 4880 §5.2.3.3, only the most recent self-signature is
/// authoritative for key flags.
///
/// Used by card operations: a Certify-capable primary key can produce
/// signatures when explicitly uploaded to the card's signing slot.
#[cfg(feature = "card")]
pub(crate) fn can_primary_certify(key: &SignedPublicKey) -> bool {
    key.details.users.iter().any(|u| {
        most_recent_verified_self_sig(&key.primary_key, u)
            .map(|sig| sig.key_flags().certify())
            .unwrap_or(false)
    })
}

/// Check if the primary key is revoked by a cryptographically valid
/// self-signature.
pub(crate) fn is_primary_key_revoked(key: &SignedPublicKey) -> bool {
    verified_primary_revocation(key).is_some()
}

/// Check if the primary key of a secret key is revoked by a
/// cryptographically valid self-signature.
pub(crate) fn is_primary_secret_key_revoked(key: &SignedSecretKey) -> bool {
    let primary_pub = key.primary_key.public_key();
    key.details
        .revocation_signatures
        .iter()
        .filter(|sig| sig.typ() == Some(SignatureType::KeyRevocation))
        .any(|sig| sig.verify_key(primary_pub).is_ok())
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
    details: &pgp::composed::SignedKeyDetails,
) -> Option<SystemTime> {
    let mut newest_created: Option<SystemTime> = None;
    let mut newest_expiration = None;

    for user in &details.users {
        // Only consider self-signatures (certifications), not third-party sigs.
        // Per RFC 4880 §5.2.3.3, the most recent self-signature is authoritative.
        let self_sigs = user.signatures.iter().filter(|sig| {
            matches!(
                sig.typ(),
                Some(SignatureType::CertGeneric)
                    | Some(SignatureType::CertPersona)
                    | Some(SignatureType::CertCasual)
                    | Some(SignatureType::CertPositive)
            )
        });
        for sig in self_sigs {
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

/// Validate whether the primary of a public key may be used for a
/// specific signing purpose.
#[cfg(feature = "card")]
pub(crate) fn validate_public_signing_usage(
    key: &SignedPublicKey,
    usage: SigningKeyUsage,
) -> Result<()> {
    if is_primary_key_revoked(key) {
        return Err(Error::KeyRevoked);
    }

    if matches!(usage, SigningKeyUsage::DataSignature) {
        let creation_time: SystemTime = key.primary_key.created_at().into();
        if let Some(exp) = primary_expiration_from_details(creation_time, &key.details) {
            if exp < SystemTime::now() {
                return Err(Error::KeyExpired);
            }
        }
    }

    Ok(())
}

/// Validate whether the primary of a secret key may be used for a
/// specific signing purpose.
pub(crate) fn validate_secret_signing_usage(
    key: &SignedSecretKey,
    usage: SigningKeyUsage,
) -> Result<()> {
    if is_primary_secret_key_revoked(key) {
        return Err(Error::KeyRevoked);
    }

    if matches!(usage, SigningKeyUsage::DataSignature) {
        let creation_time: SystemTime = key.primary_key.created_at().into();
        if let Some(exp) = primary_expiration_from_details(creation_time, &key.details) {
            if exp < SystemTime::now() {
                return Err(Error::KeyExpired);
            }
        }
    }

    Ok(())
}

/// Validate whether the primary key of a public key may be used for a
/// specific signing purpose.
#[cfg(feature = "card")]
pub(crate) fn validate_primary_key_signing_usage(
    key: &SignedPublicKey,
    usage: SigningKeyUsage,
) -> Result<()> {
    validate_public_signing_usage(key, usage)
}

/// Get the expiration time for a key from the most recent self-signature.
///
/// Convenience wrapper over [`primary_expiration_from_details`] for `SignedPublicKey`.
pub(crate) fn get_key_expiration(key: &SignedPublicKey) -> Option<SystemTime> {
    primary_expiration_from_details(key.primary_key.created_at().into(), &key.details)
}

/// Return the first primary-key revocation signature that cryptographically
/// verifies against the primary key, or `None` if no such signature exists.
///
/// rpgp's parser accepts any packet tagged `KeyRevocation` into
/// `SignedKeyDetails::revocation_signatures` without verifying it (see
/// `composed/signed_key/key_parser.rs`). Callers that need a trustworthy
/// revocation verdict must verify the signature themselves — which is what
/// this helper does: it filters `revocation_signatures` to `KeyRevocation`
/// packets, then calls `Signature::verify_key` against the primary key and
/// returns the first one that passes.
///
/// This only covers self-revocations (primary revoking itself). Designated-
/// revoker signatures are not consulted; supporting them would require
/// resolving the designated-revoker subpacket against an external keyring.
pub(crate) fn verified_primary_revocation(
    key: &SignedPublicKey,
) -> Option<&pgp::packet::Signature> {
    key.details
        .revocation_signatures
        .iter()
        .filter(|sig| sig.typ() == Some(SignatureType::KeyRevocation))
        .find(|sig| sig.verify_key(&key.primary_key).is_ok())
}

/// Return the first `CertRevocation` signature on `user` that
/// cryptographically verifies as a self-revocation of the UID by
/// `primary`.
///
/// Mirrors [`verified_primary_revocation`] for UID certifications. rpgp
/// parses any `CertRevocation` packet into `SignedUser::signatures`
/// without verifying it, so trusting the packet-type tag alone lets an
/// attacker with packet-injection capability forge a UID revocation.
pub(crate) fn verified_user_id_revocation<'a>(
    primary: &pgp::packet::PublicKey,
    user: &'a SignedUser,
) -> Option<&'a pgp::packet::Signature> {
    user.signatures
        .iter()
        .filter(|sig| sig.typ() == Some(SignatureType::CertRevocation))
        .find(|sig| {
            sig.verify_certification(primary, Tag::UserId, &user.id)
                .is_ok()
        })
}
