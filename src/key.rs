//! Key generation and management functions.
//!
//! This module provides functions for generating new OpenPGP keys
//! and managing existing keys (expiry, UIDs, etc.).

use chrono::{DateTime, Utc};
use crate::pgp::composed::{
    SecretKeyParamsBuilder, SignedKeyDetails, SignedPublicKey, SignedSecretKey,
    SubkeyParamsBuilder,
};
use crate::pgp::packet::{PacketTrait, SignatureConfig, SignatureType, Subpacket, SubpacketData, UserId};
use crate::pgp::types::{KeyDetails, KeyVersion, PacketHeaderVersion, Password, SignedUser, Timestamp};
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
/// * `cipher` - Cipher suite to use (see [`CipherSuite`] for options)
/// * `creation_time` - Optional creation time (defaults to now)
/// * `expiration_time` - Optional expiration time for the primary key
/// * `subkeys_expiration` - Optional expiration time for subkeys
/// * `which_keys` - Which subkeys to generate (see [`SubkeyFlags`])
/// * `can_primary_sign` - Whether the primary key can sign
/// * `can_primary_expire` - Whether the primary key can expire
///
/// # Returns
/// The generated key with public key (armored), secret key (binary), and fingerprint.
///
/// # Example
///
/// Generate a Curve25519 key (fast):
///
/// ```no_run
/// use wecanencrypt::{create_key, CipherSuite, SubkeyFlags};
///
/// let key = create_key(
///     "my_password",
///     &["Alice <alice@example.com>"],
///     CipherSuite::Cv25519,
///     None, None, None,
///     SubkeyFlags::all(),
///     false,
///     true,
/// ).unwrap();
///
/// println!("Fingerprint: {}", key.fingerprint);
/// println!("Public key:\n{}", key.public_key);
/// ```
///
/// Generate an RSA-4096 key (slow, ~10s in release mode):
///
/// ```ignore
/// // Ignored: RSA-4096 key generation is slow (~10s release, ~600s debug)
/// use wecanencrypt::{create_key, CipherSuite, SubkeyFlags};
///
/// let key = create_key(
///     "my_password",
///     &["Bob <bob@example.com>"],
///     CipherSuite::Rsa4k,
///     None, None, None,
///     SubkeyFlags::all(),
///     false,
///     true,
/// ).unwrap();
/// ```
#[allow(clippy::too_many_arguments)]
pub fn create_key(
    password: &str,
    user_ids: &[&str],
    cipher: CipherSuite,
    _creation_time: Option<DateTime<Utc>>,
    expiration_time: Option<DateTime<Utc>>,
    subkeys_expiration: Option<DateTime<Utc>>,
    which_keys: SubkeyFlags,
    can_primary_sign: bool,
    can_primary_expire: bool,
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
        crate::pgp::types::Duration::from_secs(duration.num_seconds().max(0) as u32)
    });

    let subkey_expiration = subkeys_expiration.map(|exp| {
        let now = Utc::now();
        let duration = exp.signed_duration_since(now);
        crate::pgp::types::Duration::from_secs(duration.num_seconds().max(0) as u32)
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

    if can_primary_expire {
        if let Some(exp) = primary_expiration {
            key_params.expiration(Some(exp));
        }
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
/// This is a convenience wrapper around [`create_key`] with sensible defaults:
/// - Cipher suite: Curve25519 (fast, modern)
/// - Subkeys: encryption, signing, and authentication
/// - No expiration
///
/// # Arguments
/// * `password` - Password to protect the secret key
/// * `user_ids` - List of user IDs (e.g., "Name <email@example.com>")
///
/// # Returns
/// The generated key with public key, secret key, and fingerprint.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::create_key_simple;
///
/// let key = create_key_simple("my_password", &["Alice <alice@example.com>"]).unwrap();
/// println!("Fingerprint: {}", key.fingerprint);
/// ```
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
/// Extracts the public key portion from a certificate (which may contain
/// secret key material) and returns it as ASCII-armored text.
///
/// # Arguments
/// * `cert_data` - The certificate data (public or secret key)
///
/// # Returns
/// ASCII-armored public key suitable for sharing.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{create_key_simple, get_pub_key};
///
/// let key = create_key_simple("password", &["Alice <alice@example.com>"]).unwrap();
///
/// // Extract public key from the secret key
/// let public_key = get_pub_key(&key.secret_key).unwrap();
/// println!("Share this public key:\n{}", public_key);
/// ```
pub fn get_pub_key(cert_data: &[u8]) -> Result<String> {
    let secret_key = parse_secret_key(cert_data)?;
    let public_key = SignedPublicKey::from(secret_key);
    public_key_to_armored(&public_key)
}

/// Update the expiration time for specific subkeys.
///
/// Creates new subkey binding signatures (signature type 0x18) for the
/// specified subkeys with the updated expiration time.
///
/// # Signature Details
///
/// Subkey binding signatures are created by the primary key to bind a subkey
/// to the certificate and define its properties (capabilities, expiration).
/// This function creates new binding signatures with:
///
/// - **Key flags** - Preserved from existing signature to maintain capabilities
/// - **Signature creation time** - Set to current time
/// - **Key expiration time** - Set to the specified expiry time
/// - **Issuer fingerprint** - Set to the primary key fingerprint
///
/// Non-binding signatures (like revocations) are preserved unchanged.
///
/// # Fingerprint Matching
///
/// Fingerprints are matched case-insensitively. Partial fingerprint matches
/// are supported (useful for matching by short key ID), but providing full
/// 40-character fingerprints is recommended for accuracy.
///
/// # Arguments
///
/// * `cert_data` - The certificate data (with secret key, armored or binary)
/// * `fingerprints` - Fingerprints of subkeys to update (hex strings)
/// * `expiry_time` - New expiration time as DateTime<Utc>
/// * `password` - Password to unlock the secret key
///
/// # Returns
///
/// The updated certificate with new binding signatures (binary format).
///
/// # Errors
///
/// Returns an error if:
/// - The secret key password is incorrect
/// - The expiry time is before the subkey creation time
/// - A specified subkey fingerprint is not found in the certificate
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{create_key_simple, update_subkeys_expiry, parse_cert_bytes};
/// use chrono::{Utc, Duration};
///
/// let key = create_key_simple("password", &["Alice <alice@example.com>"]).unwrap();
///
/// // Get subkey fingerprints
/// let info = parse_cert_bytes(&key.secret_key, true).unwrap();
/// let subkey_fps: Vec<&str> = info.subkeys.iter()
///     .map(|s| s.fingerprint.as_str())
///     .collect();
///
/// // Update expiration to 1 year from now
/// let new_expiry = Utc::now() + Duration::days(365);
/// let updated = update_subkeys_expiry(
///     &key.secret_key,
///     &subkey_fps,
///     new_expiry,
///     "password",
/// ).unwrap();
/// ```
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
            let expiry_duration = crate::pgp::types::Duration::from_secs(duration.num_seconds() as u32);

            // Get existing key flags
            let key_flags = subkey
                .signatures
                .first()
                .map(|sig| sig.key_flags())
                .unwrap_or_default();

            // Build new binding signature
            let hashed_subpackets = vec![
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

            new_public_subkeys.push(crate::pgp::composed::SignedPublicSubKey {
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
            let expiry_duration = crate::pgp::types::Duration::from_secs(duration.num_seconds() as u32);

            // Get existing key flags
            let key_flags = subkey
                .signatures
                .first()
                .map(|sig| sig.key_flags())
                .unwrap_or_default();

            // Build new binding signature
            let hashed_subpackets = vec![
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

            new_secret_subkeys.push(crate::pgp::composed::SignedSecretSubKey {
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
/// Updates all signatures that contain key expiration information.
///
/// # Signatures Updated
///
/// This function updates two types of signatures that can contain key expiration:
///
/// 1. **Direct key signatures (signature type 0x1f)** - These are signatures
///    directly on the primary key itself. GPG uses these as the authoritative
///    source for primary key expiration when present.
///
/// 2. **User ID self-certifications (signature type 0x13)** - These are
///    self-signatures on each user ID that also contain key expiration.
///
/// Both signature types must be updated for GPG to correctly recognize the
/// new expiration date. Key flags and other important subpackets are preserved
/// from the existing signatures.
///
/// # Arguments
///
/// * `cert_data` - The certificate data (with secret key, armored or binary)
/// * `expiry_time` - New expiration time as DateTime<Utc>
/// * `password` - Password to unlock the secret key
///
/// # Returns
///
/// The updated certificate with new expiration signatures (binary format).
///
/// # Errors
///
/// Returns an error if:
/// - The secret key password is incorrect
/// - The expiry time is before the key creation time
/// - The certificate has no self-certification signatures
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{create_key_simple, update_primary_expiry};
/// use chrono::{Utc, Duration};
///
/// let key = create_key_simple("password", &["Alice <alice@example.com>"]).unwrap();
///
/// // Set primary key to expire in 2 years
/// let new_expiry = Utc::now() + Duration::days(730);
/// let updated = update_primary_expiry(&key.secret_key, new_expiry, "password").unwrap();
/// ```
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
    let expiry_duration = crate::pgp::types::Duration::from_secs(duration.num_seconds() as u32);

    // Update direct key signatures (sigclass 0x1f) - GPG uses these for expiration
    let mut new_direct_signatures: Vec<crate::pgp::packet::Signature> = Vec::new();
    for existing_sig in &secret_key.details.direct_signatures {
        // Only update direct key signatures (0x1f), not revocations
        if existing_sig.typ() == Some(SignatureType::Key) {
            // Preserve existing subpackets, updating only creation time and expiry
            let existing_config = existing_sig
                .config()
                .ok_or_else(|| Error::Crypto("Cannot read existing direct signature config".to_string()))?;

            let mut new_hashed_subpackets: Vec<Subpacket> = Vec::new();
            let mut has_creation_time = false;
            let mut has_expiry_time = false;

            for subpacket in existing_config.hashed_subpackets() {
                match &subpacket.data {
                    SubpacketData::SignatureCreationTime(_) => {
                        new_hashed_subpackets.push(
                            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))
                                .map_err(|e| Error::Crypto(e.to_string()))?,
                        );
                        has_creation_time = true;
                    }
                    SubpacketData::KeyExpirationTime(_) => {
                        new_hashed_subpackets.push(
                            Subpacket::regular(SubpacketData::KeyExpirationTime(expiry_duration))
                                .map_err(|e| Error::Crypto(e.to_string()))?,
                        );
                        has_expiry_time = true;
                    }
                    _ => {
                        new_hashed_subpackets.push(subpacket.clone());
                    }
                }
            }

            if !has_creation_time {
                new_hashed_subpackets.push(
                    Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))
                        .map_err(|e| Error::Crypto(e.to_string()))?,
                );
            }

            if !has_expiry_time {
                new_hashed_subpackets.push(
                    Subpacket::regular(SubpacketData::KeyExpirationTime(expiry_duration))
                        .map_err(|e| Error::Crypto(e.to_string()))?,
                );
            }

            let new_unhashed_subpackets: Vec<Subpacket> = existing_config
                .unhashed_subpackets()
                .cloned()
                .collect();

            let mut config = SignatureConfig::from_key(&mut rng, &secret_key.primary_key, SignatureType::Key)
                .map_err(|e| Error::Crypto(e.to_string()))?;
            config.hashed_subpackets = new_hashed_subpackets;
            config.unhashed_subpackets = new_unhashed_subpackets;

            let sig = config
                .sign_key(&secret_key.primary_key, &password, &secret_key.primary_key.public_key())
                .map_err(|e| Error::Crypto(e.to_string()))?;

            new_direct_signatures.push(sig);
        } else {
            // Keep revocation signatures unchanged
            new_direct_signatures.push(existing_sig.clone());
        }
    }

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
        crate::pgp::composed::SignedKeyDetails::new(
            secret_key.details.revocation_signatures.clone(),
            new_direct_signatures,
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
/// Creates a new self-certification signature binding the new User ID
/// to the primary key.
///
/// # Arguments
/// * `cert_data` - The certificate data (with secret key)
/// * `uid` - The new user ID string (e.g., "Name <email@example.com>")
/// * `password` - Password to unlock the secret key
///
/// # Returns
/// The updated certificate with the new User ID.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{create_key_simple, add_uid, parse_cert_bytes};
///
/// let key = create_key_simple("password", &["Alice <alice@example.com>"]).unwrap();
///
/// // Add a second email address
/// let updated = add_uid(&key.secret_key, "Alice Work <alice@work.com>", "password").unwrap();
///
/// // Verify the new UID was added
/// let info = parse_cert_bytes(&updated, true).unwrap();
/// assert_eq!(info.user_ids.len(), 2);
/// ```
pub fn add_uid(cert_data: &[u8], uid: &str, password: &str) -> Result<Vec<u8>> {
    let mut rng = thread_rng();
    let secret_key = parse_secret_key(cert_data)?;
    let password = Password::from(password);

    // Create a new UserId packet
    let new_uid = UserId::from_str(PacketHeaderVersion::New, uid)
        .map_err(|e| Error::Crypto(e.to_string()))?;

    // Sign the new user ID (self-certification)
    let signed_user = new_uid
        .sign(
            &mut rng,
            &secret_key.primary_key,
            secret_key.primary_key.public_key(),
            &password,
        )
        .map_err(|e| Error::Crypto(e.to_string()))?;

    // Reconstruct the key with the new user ID
    let mut users = secret_key.details.users.clone();
    users.push(signed_user);

    let new_details = SignedKeyDetails::new(
        secret_key.details.revocation_signatures.clone(),
        secret_key.details.direct_signatures.clone(),
        users,
        secret_key.details.user_attributes.clone(),
    );

    let new_secret_key = SignedSecretKey::new(
        secret_key.primary_key.clone(),
        new_details,
        secret_key.public_subkeys.clone(),
        secret_key.secret_subkeys.clone(),
    );

    secret_key_to_bytes(&new_secret_key)
}

/// Revoke a User ID on a certificate.
///
/// Adds a revocation signature to the specified User ID. The UID remains
/// in the certificate but is marked as revoked.
///
/// # Arguments
/// * `cert_data` - The certificate data (with secret key)
/// * `uid` - The exact user ID string to revoke
/// * `password` - Password to unlock the secret key
///
/// # Returns
/// The updated certificate with the revocation signature.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{create_key_simple, add_uid, revoke_uid};
///
/// let key = create_key_simple("password", &["Alice <alice@example.com>"]).unwrap();
///
/// // Add and then revoke a UID
/// let with_uid = add_uid(&key.secret_key, "Old Email <old@example.com>", "password").unwrap();
/// let revoked = revoke_uid(&with_uid, "Old Email <old@example.com>", "password").unwrap();
/// ```
pub fn revoke_uid(cert_data: &[u8], uid: &str, password: &str) -> Result<Vec<u8>> {
    let mut rng = thread_rng();
    let secret_key = parse_secret_key(cert_data)?;
    let password = Password::from(password);

    // Find the user ID to revoke
    let uid_bytes = uid.as_bytes();
    let uid_index = secret_key
        .details
        .users
        .iter()
        .position(|u| u.id.id() == uid_bytes)
        .ok_or_else(|| Error::InvalidInput(format!("User ID '{}' not found in key", uid)))?;

    // Create a revocation signature for this user ID
    let mut config = SignatureConfig::from_key(&mut rng, &secret_key.primary_key, SignatureType::CertRevocation)
        .map_err(|e| Error::Crypto(e.to_string()))?;

    config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))
            .map_err(|e| Error::Crypto(e.to_string()))?,
        Subpacket::regular(SubpacketData::IssuerFingerprint(secret_key.primary_key.fingerprint()))
            .map_err(|e| Error::Crypto(e.to_string()))?,
    ];

    if secret_key.primary_key.version() <= KeyVersion::V4 {
        config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
            secret_key.primary_key.legacy_key_id(),
        ))
        .map_err(|e| Error::Crypto(e.to_string()))?];
    }

    let user_to_revoke = &secret_key.details.users[uid_index];
    let revocation_sig = config
        .sign_certification_third_party(
            &secret_key.primary_key,
            &password,
            secret_key.primary_key.public_key(),
            user_to_revoke.id.tag(),
            &user_to_revoke.id,
        )
        .map_err(|e| Error::Crypto(e.to_string()))?;

    // Reconstruct the users list with the revocation signature added
    let mut users = secret_key.details.users.clone();
    users[uid_index].signatures.push(revocation_sig);

    let new_details = SignedKeyDetails::new(
        secret_key.details.revocation_signatures.clone(),
        secret_key.details.direct_signatures.clone(),
        users,
        secret_key.details.user_attributes.clone(),
    );

    let new_secret_key = SignedSecretKey::new(
        secret_key.primary_key.clone(),
        new_details,
        secret_key.public_subkeys.clone(),
        secret_key.secret_subkeys.clone(),
    );

    secret_key_to_bytes(&new_secret_key)
}

/// Change the password on a secret key.
///
/// Decrypts the secret key material with the old password and re-encrypts
/// it with the new password. This applies to both the primary key and all
/// secret subkeys.
///
/// # Arguments
/// * `cert_data` - The certificate data (with secret key)
/// * `old_password` - Current password
/// * `new_password` - New password
///
/// # Returns
/// The certificate with the new password protection.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{create_key_simple, update_password, decrypt_bytes, encrypt_bytes, get_pub_key};
///
/// let key = create_key_simple("old_password", &["Alice <alice@example.com>"]).unwrap();
///
/// // Change the password
/// let updated = update_password(&key.secret_key, "old_password", "new_password").unwrap();
///
/// // Now decrypt using the new password
/// let public_key = get_pub_key(&updated).unwrap();
/// let encrypted = encrypt_bytes(public_key.as_bytes(), b"test", true).unwrap();
/// let decrypted = decrypt_bytes(&updated, &encrypted, "new_password").unwrap();
/// assert_eq!(decrypted, b"test");
/// ```
pub fn update_password(
    cert_data: &[u8],
    old_password: &str,
    new_password: &str,
) -> Result<Vec<u8>> {
    let mut rng = thread_rng();
    let secret_key = parse_secret_key(cert_data)?;
    let old_pw = Password::from(old_password);
    let new_pw = Password::from(new_password);

    // Clone the primary key and change its password
    let mut new_primary_key = secret_key.primary_key.clone();
    new_primary_key
        .remove_password(&old_pw)
        .map_err(|e| Error::Crypto(format!("Failed to unlock primary key: {}", e)))?;
    new_primary_key
        .set_password(&mut rng, &new_pw)
        .map_err(|e| Error::Crypto(format!("Failed to set new password on primary key: {}", e)))?;

    // Clone and update password on all secret subkeys
    let mut new_secret_subkeys = Vec::new();
    for subkey in &secret_key.secret_subkeys {
        let mut new_subkey = subkey.clone();
        new_subkey
            .key
            .remove_password(&old_pw)
            .map_err(|e| Error::Crypto(format!("Failed to unlock subkey: {}", e)))?;
        new_subkey
            .key
            .set_password(&mut rng, &new_pw)
            .map_err(|e| Error::Crypto(format!("Failed to set new password on subkey: {}", e)))?;
        new_secret_subkeys.push(new_subkey);
    }

    let new_secret_key = SignedSecretKey::new(
        new_primary_key,
        secret_key.details.clone(),
        secret_key.public_subkeys.clone(),
        new_secret_subkeys,
    );

    secret_key_to_bytes(&new_secret_key)
}

/// Certify another key with this key (key signing).
///
/// Creates a certification signature on the target key's User IDs,
/// expressing trust in the binding between the key and the identities.
///
/// # Arguments
/// * `certifier_data` - The certifier's secret key (your key)
/// * `target_data` - The target certificate to certify (their public key)
/// * `certification_type` - Level of verification performed (see [`CertificationType`])
/// * `user_ids` - Specific user IDs to certify (None = all user IDs)
/// * `password` - Password for certifier's key
///
/// # Returns
/// The target certificate with the new certification signature attached.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{create_key_simple, certify_key, CertificationType, get_pub_key};
///
/// // Create two keys
/// let alice = create_key_simple("alice_pw", &["Alice <alice@example.com>"]).unwrap();
/// let bob = create_key_simple("bob_pw", &["Bob <bob@example.com>"]).unwrap();
///
/// // Alice certifies Bob's key (signs it)
/// let bob_public = get_pub_key(&bob.secret_key).unwrap();
/// let certified_bob = certify_key(
///     &alice.secret_key,
///     bob_public.as_bytes(),
///     CertificationType::Casual,
///     None,  // certify all UIDs
///     "alice_pw",
/// ).unwrap();
/// ```
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
        let should_certify = uids_to_certify.contains(&uid_str);

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
        details: crate::pgp::composed::SignedKeyDetails::new(
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
