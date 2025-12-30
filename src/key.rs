//! Key generation and management functions.
//!
//! This module provides functions for generating new OpenPGP keys
//! and managing existing keys (expiry, UIDs, etc.).

use chrono::{DateTime, Utc};
use pgp::composed::{
    SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::packet::{PacketTrait, SignatureConfig, SignatureType, Subpacket, SubpacketData};
use pgp::types::{KeyDetails, KeyVersion, Password, SignedUser, Timestamp};
use rand::thread_rng;
use std::time::SystemTime;

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
/// Creates new binding signatures for the specified subkeys with
/// the updated expiration time.
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
    cert_data: &[u8],
    fingerprints: &[&str],
    expiry_time: DateTime<Utc>,
    password: &str,
) -> Result<Vec<u8>> {
    let mut rng = thread_rng();
    let secret_key = parse_secret_key(cert_data)?;
    let password = Password::from(password);

    // Normalize fingerprints for comparison (uppercase, no spaces)
    let normalized_fps: Vec<String> = fingerprints
        .iter()
        .map(|fp| fp.to_uppercase().replace(" ", ""))
        .collect();

    // Update public subkeys
    let mut new_public_subkeys = Vec::new();
    for subkey in &secret_key.public_subkeys {
        let subkey_fp = fingerprint_to_hex(&subkey.key);
        let should_update = normalized_fps.iter().any(|fp| subkey_fp.contains(fp) || fp.contains(&subkey_fp));

        if should_update {
            // Calculate duration from subkey creation to expiry
            let creation_systime: SystemTime = subkey.key.created_at().into();
            let subkey_creation: DateTime<Utc> = creation_systime.into();
            let duration = expiry_time.signed_duration_since(subkey_creation);
            if duration.num_seconds() <= 0 {
                return Err(Error::InvalidInput(
                    "Expiry time must be after subkey creation time".to_string(),
                ));
            }
            let expiry_duration = pgp::types::Duration::from_secs(duration.num_seconds() as u32);

            // Get existing key flags
            let key_flags = subkey
                .signatures
                .first()
                .map(|sig| sig.key_flags())
                .unwrap_or_default();

            // Build new binding signature
            let mut hashed_subpackets = vec![
                Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))
                    .map_err(|e| Error::Crypto(e.to_string()))?,
                Subpacket::regular(SubpacketData::IssuerFingerprint(
                    secret_key.primary_key.fingerprint(),
                ))
                .map_err(|e| Error::Crypto(e.to_string()))?,
                Subpacket::regular(SubpacketData::KeyFlags(key_flags))
                    .map_err(|e| Error::Crypto(e.to_string()))?,
                Subpacket::regular(SubpacketData::KeyExpirationTime(expiry_duration))
                    .map_err(|e| Error::Crypto(e.to_string()))?,
            ];

            let mut config = SignatureConfig::from_key(
                &mut rng,
                &secret_key.primary_key,
                SignatureType::SubkeyBinding,
            )
            .map_err(|e| Error::Crypto(e.to_string()))?;

            config.hashed_subpackets = hashed_subpackets;

            if secret_key.primary_key.version() <= KeyVersion::V4 {
                config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
                    secret_key.primary_key.legacy_key_id(),
                ))
                .map_err(|e| Error::Crypto(e.to_string()))?];
            }

            let sig = config
                .sign_subkey_binding(
                    &secret_key.primary_key,
                    &secret_key.primary_key.public_key(),
                    &password,
                    &subkey.key,
                )
                .map_err(|e| Error::Crypto(e.to_string()))?;

            // Create new subkey with updated signature
            let mut new_sigs = vec![sig];
            // Keep any non-binding signatures (like revocations)
            for existing_sig in &subkey.signatures {
                if existing_sig.typ() != Some(SignatureType::SubkeyBinding) {
                    new_sigs.push(existing_sig.clone());
                }
            }

            new_public_subkeys.push(pgp::composed::SignedPublicSubKey {
                key: subkey.key.clone(),
                signatures: new_sigs,
            });
        } else {
            new_public_subkeys.push(subkey.clone());
        }
    }

    // Update secret subkeys similarly
    let mut new_secret_subkeys = Vec::new();
    for subkey in &secret_key.secret_subkeys {
        let subkey_fp = fingerprint_to_hex(&subkey.key);
        let should_update = normalized_fps.iter().any(|fp| subkey_fp.contains(fp) || fp.contains(&subkey_fp));

        if should_update {
            // Calculate duration from subkey creation to expiry
            let creation_systime: SystemTime = subkey.key.created_at().into();
            let subkey_creation: DateTime<Utc> = creation_systime.into();
            let duration = expiry_time.signed_duration_since(subkey_creation);
            if duration.num_seconds() <= 0 {
                return Err(Error::InvalidInput(
                    "Expiry time must be after subkey creation time".to_string(),
                ));
            }
            let expiry_duration = pgp::types::Duration::from_secs(duration.num_seconds() as u32);

            // Get existing key flags
            let key_flags = subkey
                .signatures
                .first()
                .map(|sig| sig.key_flags())
                .unwrap_or_default();

            // Build new binding signature
            let mut hashed_subpackets = vec![
                Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))
                    .map_err(|e| Error::Crypto(e.to_string()))?,
                Subpacket::regular(SubpacketData::IssuerFingerprint(
                    secret_key.primary_key.fingerprint(),
                ))
                .map_err(|e| Error::Crypto(e.to_string()))?,
                Subpacket::regular(SubpacketData::KeyFlags(key_flags))
                    .map_err(|e| Error::Crypto(e.to_string()))?,
                Subpacket::regular(SubpacketData::KeyExpirationTime(expiry_duration))
                    .map_err(|e| Error::Crypto(e.to_string()))?,
            ];

            let mut config = SignatureConfig::from_key(
                &mut rng,
                &secret_key.primary_key,
                SignatureType::SubkeyBinding,
            )
            .map_err(|e| Error::Crypto(e.to_string()))?;

            config.hashed_subpackets = hashed_subpackets;

            if secret_key.primary_key.version() <= KeyVersion::V4 {
                config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
                    secret_key.primary_key.legacy_key_id(),
                ))
                .map_err(|e| Error::Crypto(e.to_string()))?];
            }

            let sig = config
                .sign_subkey_binding(
                    &secret_key.primary_key,
                    &secret_key.primary_key.public_key(),
                    &password,
                    &subkey.key.public_key(),
                )
                .map_err(|e| Error::Crypto(e.to_string()))?;

            // Create new subkey with updated signature
            let mut new_sigs = vec![sig];
            for existing_sig in &subkey.signatures {
                if existing_sig.typ() != Some(SignatureType::SubkeyBinding) {
                    new_sigs.push(existing_sig.clone());
                }
            }

            new_secret_subkeys.push(pgp::composed::SignedSecretSubKey {
                key: subkey.key.clone(),
                signatures: new_sigs,
            });
        } else {
            new_secret_subkeys.push(subkey.clone());
        }
    }

    // Rebuild the secret key with updated subkeys
    let updated_key = SignedSecretKey::new(
        secret_key.primary_key.clone(),
        secret_key.details.clone(),
        new_public_subkeys,
        new_secret_subkeys,
    );

    secret_key_to_bytes(&updated_key)
}

/// Update the primary key expiration time.
///
/// This creates new self-certification signatures for all user IDs with
/// the updated expiration time.
///
/// # Arguments
/// * `cert_data` - The certificate data (with secret key)
/// * `expiry_time` - New expiration time
/// * `password` - Password to unlock the secret key
///
/// # Returns
/// The updated certificate.
pub fn update_primary_expiry(
    cert_data: &[u8],
    expiry_time: DateTime<Utc>,
    password: &str,
) -> Result<Vec<u8>> {
    let mut rng = thread_rng();
    let secret_key = parse_secret_key(cert_data)?;
    let password = Password::from(password);

    // Calculate the duration from key creation to expiry
    let creation_systime: SystemTime = secret_key.primary_key.created_at().into();
    let key_creation: DateTime<Utc> = creation_systime.into();
    let duration = expiry_time.signed_duration_since(key_creation);
    if duration.num_seconds() <= 0 {
        return Err(Error::InvalidInput(
            "Expiry time must be after key creation time".to_string(),
        ));
    }
    let expiry_duration = pgp::types::Duration::from_secs(duration.num_seconds() as u32);

    // Create new self-certification signatures for each user ID
    let mut new_users: Vec<SignedUser> = Vec::new();

    for signed_user in &secret_key.details.users {
        // Build the hashed subpackets including expiry
        let mut hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))
                .map_err(|e| Error::Crypto(e.to_string()))?,
            Subpacket::regular(SubpacketData::IssuerFingerprint(
                secret_key.primary_key.fingerprint(),
            ))
            .map_err(|e| Error::Crypto(e.to_string()))?,
            Subpacket::regular(SubpacketData::KeyExpirationTime(expiry_duration))
                .map_err(|e| Error::Crypto(e.to_string()))?,
        ];

        // Copy key flags from existing signature if present
        if let Some(existing_sig) = signed_user.signatures.first() {
            let flags = existing_sig.key_flags();
            hashed_subpackets.push(
                Subpacket::regular(SubpacketData::KeyFlags(flags))
                    .map_err(|e| Error::Crypto(e.to_string()))?,
            );
        }

        // Create the signature config
        let mut config = SignatureConfig::from_key(&mut rng, &secret_key.primary_key, SignatureType::CertPositive)
            .map_err(|e| Error::Crypto(e.to_string()))?;

        config.hashed_subpackets = hashed_subpackets;

        if secret_key.primary_key.version() <= KeyVersion::V4 {
            config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
                secret_key.primary_key.legacy_key_id(),
            ))
            .map_err(|e| Error::Crypto(e.to_string()))?];
        }

        // Sign the user ID
        let sig = config
            .sign_certification(
                &secret_key.primary_key,
                &secret_key.primary_key.public_key(),
                &password,
                signed_user.id.tag(),
                &signed_user.id,
            )
            .map_err(|e| Error::Crypto(e.to_string()))?;

        // Combine with existing signatures (add new sig, keep existing third-party certs)
        let mut combined_sigs = vec![sig];
        // Keep third-party certifications but not old self-signatures
        for existing_sig in &signed_user.signatures {
            if existing_sig.typ() != Some(SignatureType::CertPositive) {
                combined_sigs.push(existing_sig.clone());
            }
        }

        new_users.push(SignedUser::new(signed_user.id.clone(), combined_sigs));
    }

    // Rebuild the secret key with new signatures
    let updated_key = SignedSecretKey::new(
        secret_key.primary_key.clone(),
        pgp::composed::SignedKeyDetails::new(
            secret_key.details.revocation_signatures.clone(),
            secret_key.details.direct_signatures.clone(),
            new_users,
            secret_key.details.user_attributes.clone(),
        ),
        secret_key.public_subkeys.clone(),
        secret_key.secret_subkeys.clone(),
    );

    secret_key_to_bytes(&updated_key)
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
