//! Key validation and algorithm policy functions.
//!
//! rpgp doesn't have a policy system like sequoia, so we implement
//! manual validation of key properties here. This includes:
//! - Key expiration and revocation checks
//! - Time-based algorithm acceptance policy
//! - Key flag validation

use std::time::SystemTime;

use chrono::{DateTime, Utc};
use pgp::composed::{SignedPublicKey, SignedPublicSubKey};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::packet::SignatureType;
use pgp::types::{KeyDetails, PublicParams};

// =============================================================================
// Algorithm Policy Constants
// =============================================================================

/// Cutoff timestamp for MD5: January 1, 2010 00:00:00 UTC
/// MD5 is considered broken for cryptographic use after this date.
const MD5_CUTOFF_TIMESTAMP: i64 = 1262304000;

/// Cutoff timestamp for SHA1 in data signatures: January 1, 2014 00:00:00 UTC
/// SHA1 for data signatures is rejected after 2013 per NIST guidance.
const SHA1_DATA_CUTOFF_TIMESTAMP: i64 = 1388534400;

/// Cutoff timestamp for SHA1 in structural signatures: February 1, 2023 00:00:00 UTC
/// SHA1 for key binding signatures is rejected after this date.
const SHA1_STRUCTURAL_CUTOFF_TIMESTAMP: i64 = 1675209600;

/// Cutoff timestamp for RSA keys under 2048 bits: January 1, 2014 00:00:00 UTC
/// RSA keys smaller than 2048 bits are rejected after 2013.
const RSA_WEAK_CUTOFF_TIMESTAMP: i64 = 1388534400;

/// Minimum acceptable RSA key size in bits.
const RSA_MINIMUM_BITS: usize = 2048;

/// Cutoff timestamp for DSA: February 3, 2023 00:00:00 UTC
/// DSA is deprecated per FIPS 186-5.
const DSA_CUTOFF_TIMESTAMP: i64 = 1675382400;

// =============================================================================
// Algorithm Policy Functions
// =============================================================================

/// Check if a hash algorithm is acceptable at the given reference time.
///
/// # Arguments
/// * `algo` - The hash algorithm to check
/// * `reference_time` - The signature creation time (used as reference)
/// * `is_data_signature` - True for data signatures, false for structural (key binding) signatures
///
/// # Returns
/// True if the algorithm is acceptable, false if it should be rejected.
///
/// # Policy
/// - MD5: Rejected after January 1, 2010
/// - SHA1 (data): Rejected after January 1, 2014
/// - SHA1 (structural): Rejected after February 1, 2023
/// - All other algorithms: Accepted
pub fn acceptable_hash_algorithm(
    algo: HashAlgorithm,
    reference_time: &DateTime<Utc>,
    is_data_signature: bool,
) -> bool {
    let timestamp = reference_time.timestamp();

    match algo {
        HashAlgorithm::Md5 => timestamp < MD5_CUTOFF_TIMESTAMP,
        HashAlgorithm::Sha1 => {
            if is_data_signature {
                timestamp < SHA1_DATA_CUTOFF_TIMESTAMP
            } else {
                timestamp < SHA1_STRUCTURAL_CUTOFF_TIMESTAMP
            }
        }
        // RIPEMD160 is deprecated in RFC 9580 but we allow it for now
        HashAlgorithm::Ripemd160 => true,
        // SHA2 and SHA3 family are acceptable
        _ => true,
    }
}

/// Check if a public key algorithm and parameters are acceptable at the given reference time.
///
/// # Arguments
/// * `algo` - The public key algorithm
/// * `params` - The public key parameters (for checking key size)
/// * `reference_time` - The signature/key creation time
///
/// # Returns
/// True if acceptable, false if rejected.
///
/// # Policy
/// - RSA < 2048 bits: Rejected after January 1, 2014
/// - DSA: Rejected after February 3, 2023
/// - All other algorithms: Accepted
pub fn acceptable_pk_algorithm(
    algo: PublicKeyAlgorithm,
    params: &PublicParams,
    reference_time: &DateTime<Utc>,
) -> bool {
    let timestamp = reference_time.timestamp();

    // Check RSA key size
    if let PublicParams::RSA(rsa_params) = params {
        use rsa::traits::PublicKeyParts;
        let bits = rsa_params.key.n().bits();
        if bits < RSA_MINIMUM_BITS && timestamp > RSA_WEAK_CUTOFF_TIMESTAMP {
            return false;
        }
    }

    // Check DSA deprecation
    if algo == PublicKeyAlgorithm::DSA && timestamp > DSA_CUTOFF_TIMESTAMP {
        return false;
    }

    true
}

/// Check if a signature's hash algorithm passes our policy.
///
/// # Arguments
/// * `hash_algo` - The hash algorithm used in the signature
/// * `sig_created` - When the signature was created
/// * `is_data_sig` - True for data signatures, false for structural signatures
pub fn signature_hash_acceptable(
    hash_algo: HashAlgorithm,
    sig_created: &DateTime<Utc>,
    is_data_sig: bool,
) -> bool {
    acceptable_hash_algorithm(hash_algo, sig_created, is_data_sig)
}

/// Check if a key's algorithm passes our policy for encryption.
///
/// For encryption, we check current time since encryption happens "now".
pub fn key_acceptable_for_encryption(params: &PublicParams) -> bool {
    let now = Utc::now();

    // For ECDH, check that acceptable algorithms are used
    if let PublicParams::ECDH(ecdh) = params {
        use pgp::types::EcdhPublicParams;
        match ecdh {
            EcdhPublicParams::Curve25519 { hash, alg_sym, .. }
            | EcdhPublicParams::P256 { hash, alg_sym, .. }
            | EcdhPublicParams::P384 { hash, alg_sym, .. }
            | EcdhPublicParams::P521 { hash, alg_sym, .. } => {
                // Check hash algorithm
                if !matches!(
                    hash,
                    HashAlgorithm::Sha256 | HashAlgorithm::Sha384 | HashAlgorithm::Sha512
                ) {
                    return false;
                }
                // Check symmetric algorithm
                use pgp::crypto::sym::SymmetricKeyAlgorithm;
                if !matches!(
                    alg_sym,
                    SymmetricKeyAlgorithm::AES128
                        | SymmetricKeyAlgorithm::AES192
                        | SymmetricKeyAlgorithm::AES256
                ) {
                    return false;
                }
            }
            _ => {}
        }
    }

    // Check RSA key size for encryption
    if let PublicParams::RSA(rsa_params) = params {
        use rsa::traits::PublicKeyParts;
        let bits = rsa_params.key.n().bits();
        if bits < RSA_MINIMUM_BITS {
            return false;
        }
    }

    true
}

/// Check if a key's algorithm passes our policy for signing.
///
/// # Arguments
/// * `algo` - The public key algorithm
/// * `params` - The public key parameters
/// * `reference_time` - When the signature will be created
pub fn key_acceptable_for_signing(
    algo: PublicKeyAlgorithm,
    params: &PublicParams,
    reference_time: &DateTime<Utc>,
) -> bool {
    acceptable_pk_algorithm(algo, params, reference_time)
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
    subkey.signatures.iter().any(|sig| {
        sig.typ() == Some(SignatureType::SubkeyRevocation)
    })
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

/// Check if the primary key is valid.
pub(crate) fn is_primary_key_valid(key: &SignedPublicKey, allow_expired: bool) -> bool {
    // Check revocation
    if !key.details.revocation_signatures.is_empty() {
        return false;
    }

    // Check expiration if not allowing expired
    if !allow_expired {
        // Get expiration from first user binding signature
        for user in &key.details.users {
            for sig in &user.signatures {
                if let Some(validity) = sig.key_expiration_time() {
                    let creation_time: SystemTime = key.primary_key.created_at().into();
                    if is_key_expired(creation_time, Some(validity.as_secs() as u64)) {
                        return false;
                    }
                }
            }
        }
    }

    true
}

/// Find encryption-capable subkeys.
pub(crate) fn find_encryption_subkeys(key: &SignedPublicKey) -> Vec<&SignedPublicSubKey> {
    key.public_subkeys
        .iter()
        .filter(|sk| {
            // Check key flags in binding signature
            if let Some(sig) = sk.signatures.first() {
                let flags = sig.key_flags();
                return flags.encrypt_comms() || flags.encrypt_storage();
            }
            false
        })
        .collect()
}

/// Find signing-capable subkeys.
pub(crate) fn find_signing_subkeys(key: &SignedPublicKey) -> Vec<&SignedPublicSubKey> {
    key.public_subkeys
        .iter()
        .filter(|sk| {
            if let Some(sig) = sk.signatures.first() {
                let flags = sig.key_flags();
                return flags.sign();
            }
            false
        })
        .collect()
}

/// Find authentication-capable subkeys.
pub(crate) fn find_authentication_subkeys(key: &SignedPublicKey) -> Vec<&SignedPublicSubKey> {
    key.public_subkeys
        .iter()
        .filter(|sk| {
            if let Some(sig) = sk.signatures.first() {
                let flags = sig.key_flags();
                return flags.authentication();
            }
            false
        })
        .collect()
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

/// Check if primary key can certify (has certification flag).
pub(crate) fn can_primary_certify(key: &SignedPublicKey) -> bool {
    // Check user binding signatures for key flags
    for user in &key.details.users {
        for sig in &user.signatures {
            let flags = sig.key_flags();
            if flags.certify() {
                return true;
            }
        }
    }
    // Default: primary keys can usually certify
    true
}

/// Get the expiration time for a key (from first user binding signature).
pub(crate) fn get_key_expiration(key: &SignedPublicKey) -> Option<SystemTime> {
    for user in &key.details.users {
        for sig in &user.signatures {
            if let Some(validity) = sig.key_expiration_time() {
                let creation_time: SystemTime = key.primary_key.created_at().into();
                return Some(creation_time + validity.into());
            }
        }
    }
    None
}
