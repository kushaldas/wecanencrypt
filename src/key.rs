//! Key generation and management functions.
//!
//! This module provides functions for generating new OpenPGP keys
//! and managing existing keys (expiry, UIDs, etc.).

use chrono::{DateTime, Utc};
use pgp::composed::{
    SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::packet::{SignatureConfig, SignatureType, Subpacket, SubpacketData};
use pgp::types::{KeyDetails, KeyVersion, Password, SignedUser, Timestamp};
use rand::thread_rng;
use std::time::Duration as StdDuration;

use crate::error::{Error, Result};
use crate::internal::{
    fingerprint_to_hex, parse_public_key, parse_secret_key, public_key_to_armored,
    secret_key_to_bytes,
};
use crate::types::{CertificationType, CipherSuite, GeneratedKey, SubkeyFlags};

/// Generate a new OpenPGP key pair.
///
/// # Arguments
/// * `password` - Password to protect the secret key
/// * `user_ids` - List of user IDs (e.g., "Name <email@example.com>")
/// * `cipher` - Cipher suite to use (RSA or Curve25519)
/// * `creation_time` - Optional creation time (defaults to now)
/// * `expiration_time` - Optional expiration time for the primary key
/// * `subkeys_expiration` - Optional expiration time for subkeys
/// * `which_keys` - Which subkeys to generate
/// * `can_primary_sign` - Whether the primary key can sign
/// * `can_primary_expire` - Whether the primary key can expire
///
/// # Returns
/// The generated key with public key (armored), secret key (binary), and fingerprint.
///
/// # Example
/// ```ignore
/// let key = create_key(
///     "password",
///     &["Alice <alice@example.com>"],
///     CipherSuite::Cv25519,
///     None, None, None,
///     SubkeyFlags::all(),
///     false, true,
/// )?;
/// println!("Fingerprint: {}", key.fingerprint);
/// ```
pub fn create_key(
    password: &str,
    user_ids: &[&str],
    cipher: CipherSuite,
    _creation_time: Option<DateTime<Utc>>,
    expiration_time: Option<DateTime<Utc>>,
    subkeys_expiration: Option<DateTime<Utc>>,
    which_keys: SubkeyFlags,
    can_primary_sign: bool,
    _can_primary_expire: bool,
) -> Result<GeneratedKey> {
    if user_ids.is_empty() {
        return Err(Error::InvalidInput(
            "At least one user ID is required".to_string(),
        ));
    }

    let mut rng = thread_rng();

    // Get key types for primary and subkeys
    let primary_key_type = cipher.primary_key_type();
    let encryption_key_type = cipher.encryption_key_type();

    // Calculate expiration duration
    let primary_expiration = expiration_time.map(|exp| {
        let now = Utc::now();
        let duration = exp.signed_duration_since(now);
        pgp::types::Duration::from_secs(duration.num_seconds().max(0) as u32)
    });

    let subkey_expiration = subkeys_expiration.map(|exp| {
        let now = Utc::now();
        let duration = exp.signed_duration_since(now);
        pgp::types::Duration::from_secs(duration.num_seconds().max(0) as u32)
    });

    // Build subkeys based on flags
    let mut subkeys = Vec::new();

    if which_keys.encryption {
        let mut enc_builder = SubkeyParamsBuilder::default();
        enc_builder
            .key_type(encryption_key_type)
            .can_encrypt(true)
            .can_sign(false)
            .can_authenticate(false);

        if let Some(exp) = subkey_expiration {
            enc_builder.expiration(Some(exp));
        }

        if !password.is_empty() {
            enc_builder.passphrase(Some(password.to_string()));
        }

        subkeys.push(enc_builder.build().map_err(|e| Error::Crypto(e.to_string()))?);
    }

    if which_keys.signing {
        let mut sign_builder = SubkeyParamsBuilder::default();
        sign_builder
            .key_type(primary_key_type.clone())
            .can_encrypt(false)
            .can_sign(true)
            .can_authenticate(false);

        if let Some(exp) = subkey_expiration {
            sign_builder.expiration(Some(exp));
        }

        if !password.is_empty() {
            sign_builder.passphrase(Some(password.to_string()));
        }

        subkeys.push(sign_builder.build().map_err(|e| Error::Crypto(e.to_string()))?);
    }

    if which_keys.authentication {
        let mut auth_builder = SubkeyParamsBuilder::default();
        auth_builder
            .key_type(primary_key_type.clone())
            .can_encrypt(false)
            .can_sign(false)
            .can_authenticate(true);

        if let Some(exp) = subkey_expiration {
            auth_builder.expiration(Some(exp));
        }

        if !password.is_empty() {
            auth_builder.passphrase(Some(password.to_string()));
        }

        subkeys.push(auth_builder.build().map_err(|e| Error::Crypto(e.to_string()))?);
    }

    // Build primary key params
    let mut key_params = SecretKeyParamsBuilder::default();
    key_params
        .key_type(primary_key_type)
        .can_certify(true)
        .can_sign(can_primary_sign)
        .can_encrypt(false)
        .primary_user_id(user_ids[0].to_string());

    // Add additional user IDs
    if user_ids.len() > 1 {
        let additional_uids: Vec<String> = user_ids[1..].iter().map(|s| s.to_string()).collect();
        key_params.user_ids(additional_uids);
    }

    if let Some(exp) = primary_expiration {
        key_params.expiration(Some(exp));
    }

    if !password.is_empty() {
        key_params.passphrase(Some(password.to_string()));
    }

    key_params.subkeys(subkeys);

    // Generate the key
    let secret_key_params = key_params.build().map_err(|e| Error::Crypto(e.to_string()))?;

    let secret_key = secret_key_params
        .generate(&mut rng)
        .map_err(|e| Error::Crypto(e.to_string()))?;

    // Export public key (armored)
    let public_key = secret_key.to_public_key();
    let public_key_armored = public_key_to_armored(&public_key)?;

    // Get fingerprint from the public key's primary key
    let fingerprint = fingerprint_to_hex(&public_key.primary_key);

    // Export secret key (binary)
    let secret_key_bytes = secret_key_to_bytes(&secret_key)?;

    Ok(GeneratedKey {
        public_key: public_key_armored,
        secret_key: secret_key_bytes,
        fingerprint,
    })
}

/// Generate a key with default settings (Cv25519, all subkeys).
///
/// # Arguments
/// * `password` - Password to protect the secret key
/// * `user_ids` - List of user IDs
///
/// # Returns
/// The generated key.
pub fn create_key_simple(password: &str, user_ids: &[&str]) -> Result<GeneratedKey> {
    create_key(
        password,
        user_ids,
        CipherSuite::Cv25519,
        None,
        None,
        None,
        SubkeyFlags::all(),
        false,
        true,
    )
}

/// Export the public key as ASCII armor.
///
/// # Arguments
/// * `cert_data` - The certificate data
///
/// # Returns
/// ASCII-armored public key.
pub fn get_pub_key(cert_data: &[u8]) -> Result<String> {
    let secret_key = parse_secret_key(cert_data)?;
    let public_key = SignedPublicKey::from(secret_key);
    public_key_to_armored(&public_key)
}

/// Update the expiration time for specific subkeys.
///
/// Note: This is a simplified implementation. Full subkey management
/// would require more complex signature manipulation.
///
/// # Arguments
/// * `cert_data` - The certificate data (with secret key)
/// * `fingerprints` - Fingerprints of subkeys to update
/// * `expiry_time` - New expiration time
/// * `password` - Password to unlock the secret key
///
/// # Returns
/// The updated certificate.
pub fn update_subkeys_expiry(
    _cert_data: &[u8],
    _fingerprints: &[&str],
    _expiry_time: DateTime<Utc>,
    _password: &str,
) -> Result<Vec<u8>> {
    // TODO: rpgp doesn't have a straightforward API for modifying existing keys
    // This would require manually creating new binding signatures
    Err(Error::InvalidInput(
        "Subkey expiry update not yet implemented for rpgp".to_string(),
    ))
}

/// Update the primary key expiration time.
///
/// Note: This is a simplified implementation.
///
/// # Arguments
/// * `cert_data` - The certificate data (with secret key)
/// * `expiry_time` - New expiration time
/// * `password` - Password to unlock the secret key
///
/// # Returns
/// The updated certificate.
pub fn update_primary_expiry(
    _cert_data: &[u8],
    _expiry_time: DateTime<Utc>,
    _password: &str,
) -> Result<Vec<u8>> {
    // TODO: rpgp doesn't have a straightforward API for modifying existing keys
    Err(Error::InvalidInput(
        "Primary key expiry update not yet implemented for rpgp".to_string(),
    ))
}

/// Add a new User ID to a certificate.
///
/// # Arguments
/// * `cert_data` - The certificate data (with secret key)
/// * `uid` - The new user ID string
/// * `password` - Password to unlock the secret key
///
/// # Returns
/// The updated certificate.
pub fn add_uid(_cert_data: &[u8], _uid: &str, _password: &str) -> Result<Vec<u8>> {
    // TODO: rpgp doesn't have a straightforward API for adding UIDs to existing keys
    Err(Error::InvalidInput(
        "Adding UIDs not yet implemented for rpgp".to_string(),
    ))
}

/// Revoke a User ID on a certificate.
///
/// # Arguments
/// * `cert_data` - The certificate data (with secret key)
/// * `uid` - The user ID to revoke
/// * `password` - Password to unlock the secret key
///
/// # Returns
/// The updated certificate with the revoked UID.
pub fn revoke_uid(_cert_data: &[u8], _uid: &str, _password: &str) -> Result<Vec<u8>> {
    // TODO: rpgp doesn't have a straightforward API for revoking UIDs
    Err(Error::InvalidInput(
        "Revoking UIDs not yet implemented for rpgp".to_string(),
    ))
}

/// Change the password on a secret key.
///
/// # Arguments
/// * `cert_data` - The certificate data (with secret key)
/// * `old_password` - Current password
/// * `new_password` - New password
///
/// # Returns
/// The certificate with the new password.
pub fn update_password(
    _cert_data: &[u8],
    _old_password: &str,
    _new_password: &str,
) -> Result<Vec<u8>> {
    // TODO: rpgp doesn't have a straightforward API for changing passwords
    Err(Error::InvalidInput(
        "Password update not yet implemented for rpgp".to_string(),
    ))
}

/// Certify another key with this key.
///
/// # Arguments
/// * `certifier_data` - The certifier's secret key
/// * `target_data` - The target certificate to certify
/// * `certification_type` - Type of certification
/// * `user_ids` - Specific user IDs to certify (None = all)
/// * `password` - Password for certifier's key
///
/// # Returns
/// The target certificate with the new certification.
pub fn certify_key(
    certifier_data: &[u8],
    target_data: &[u8],
    certification_type: CertificationType,
    user_ids: Option<&[&str]>,
    password: &str,
) -> Result<Vec<u8>> {
    let mut rng = thread_rng();

    // Parse the certifier's secret key
    let certifier = parse_secret_key(certifier_data)?;
    let password = Password::from(password);

    // Parse the target's public key
    let target = parse_public_key(target_data)?;

    // Convert our CertificationType to rpgp's SignatureType
    let sig_type = match certification_type {
        CertificationType::Generic => SignatureType::CertGeneric,
        CertificationType::Persona => SignatureType::CertPersona,
        CertificationType::Casual => SignatureType::CertCasual,
        CertificationType::Positive => SignatureType::CertPositive,
    };

    // Determine which user IDs to certify
    let uids_to_certify: Vec<&str> = match user_ids {
        Some(uids) => uids.to_vec(),
        None => {
            // Certify all user IDs
            target
                .details
                .users
                .iter()
                .map(|u| std::str::from_utf8(u.id.id()).unwrap_or(""))
                .filter(|s| !s.is_empty())
                .collect()
        }
    };

    // Create certifications for each selected user ID
    let mut new_users: Vec<SignedUser> = Vec::new();

    for signed_user in &target.details.users {
        let uid_str = std::str::from_utf8(signed_user.id.id()).unwrap_or("");

        // Check if this user ID should be certified
        let should_certify = uids_to_certify.iter().any(|&u| u == uid_str);

        if should_certify {
            // Create a certification signature using UserId::sign_third_party
            let certified_user = signed_user.id.sign_third_party(
                &mut rng,
                &certifier.primary_key,
                &password,
                &target.primary_key,
                sig_type,
            )?;

            // Combine existing signatures with the new certification
            let mut combined_sigs = signed_user.signatures.clone();
            combined_sigs.extend(certified_user.signatures);

            new_users.push(SignedUser::new(signed_user.id.clone(), combined_sigs));
        } else {
            // Keep the user ID unchanged
            new_users.push(signed_user.clone());
        }
    }

    // Reconstruct the public key with the new certifications
    let certified_key = SignedPublicKey {
        primary_key: target.primary_key.clone(),
        details: pgp::composed::SignedKeyDetails::new(
            target.details.revocation_signatures.clone(),
            target.details.direct_signatures.clone(),
            new_users,
            target.details.user_attributes.clone(),
        ),
        public_subkeys: target.public_subkeys.clone(),
    };

    // Serialize the certified key
    public_key_to_armored(&certified_key).map(|s| s.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subkey_flags() {
        let flags = SubkeyFlags::all();
        assert!(flags.encryption);
        assert!(flags.signing);
        assert!(flags.authentication);

        let flags = SubkeyFlags::from_bitmask(3);
        assert!(flags.encryption);
        assert!(flags.signing);
        assert!(!flags.authentication);
    }
}
