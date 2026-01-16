//! Key upload functionality for smart cards.
//!
//! This module provides functions to upload private keys to an OpenPGP smart card.
//! Uses talktosc for direct APDU communication to avoid openpgp-card's algorithm validation issues.

use std::io::Cursor;

use crate::error::{Error, Result};
use crate::pgp::composed::{Deserializable, SignedSecretKey};
use crate::pgp::types::{KeyDetails, Password, PlainSecretParams, PublicParams};

/// Key slot on the card
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardKeySlot {
    /// Signing key slot
    Signing,
    /// Decryption/encryption key slot
    Decryption,
    /// Authentication key slot
    Authentication,
}

impl CardKeySlot {
    fn crt_tag(&self) -> &[u8] {
        match self {
            CardKeySlot::Decryption => &[0xB8, 0x00],
            CardKeySlot::Signing => &[0xB6, 0x00],
            CardKeySlot::Authentication => &[0xA4, 0x00],
        }
    }

    fn algo_p2(&self) -> u8 {
        match self {
            CardKeySlot::Decryption => 0xC2,
            CardKeySlot::Signing => 0xC1,
            CardKeySlot::Authentication => 0xC3,
        }
    }

    fn fp_p2(&self) -> u8 {
        match self {
            CardKeySlot::Decryption => 0xC8,
            CardKeySlot::Signing => 0xC7,
            CardKeySlot::Authentication => 0xC9,
        }
    }

    fn time_p2(&self) -> u8 {
        match self {
            CardKeySlot::Decryption => 0xCF,
            CardKeySlot::Signing => 0xCE,
            CardKeySlot::Authentication => 0xD0,
        }
    }
}

/// Which key to upload from a certificate
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySelection {
    /// Automatically select the best key for the slot (default behavior)
    /// For signing: prefers signing subkey, falls back to primary
    /// For decryption: prefers encryption subkey, falls back to primary
    Auto,
    /// Upload the primary key regardless of subkeys
    Primary,
    /// Upload a subkey by its fingerprint (hex string, case insensitive)
    ByFingerprint,
}

/// Upload a key from a secret key file to a specific card slot.
///
/// # Arguments
///
/// * `secret_key_data` - The secret key file contents (armored or binary)
/// * `key_password` - Password to unlock the secret key (empty for unencrypted keys)
/// * `slot` - Which card slot to upload to
/// * `admin_pin` - The admin PIN for the card
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::card::upload::{upload_key_to_card, CardKeySlot};
///
/// let secret_key = std::fs::read("secret.asc").unwrap();
/// upload_key_to_card(&secret_key, b"password", CardKeySlot::Signing, b"12345678").unwrap();
/// ```
pub fn upload_key_to_card(
    secret_key_data: &[u8],
    key_password: &[u8],
    slot: CardKeySlot,
    admin_pin: &[u8],
) -> Result<()> {
    // Parse the secret key
    let secret_key = parse_secret_key(secret_key_data)?;
    let password = if key_password.is_empty() {
        Password::empty()
    } else {
        Password::from(std::str::from_utf8(key_password)
            .map_err(|_| Error::Parse("Password must be valid UTF-8".to_string()))?)
    };

    // Find the appropriate subkey for the slot
    let key_info = find_key_for_slot(&secret_key, &password, slot)?;

    // Upload to card using talktosc
    upload_with_talktosc(&key_info, slot, admin_pin)
}

/// Upload the PRIMARY key to a specific card slot.
///
/// Use this when you have a certificate with subkeys but specifically want
/// to upload the primary key (e.g., a primary key with Sign+Certify capabilities).
///
/// # Arguments
///
/// * `secret_key_data` - The secret key file contents (armored or binary)
/// * `key_password` - Password to unlock the secret key (empty for unencrypted keys)
/// * `slot` - Which card slot to upload to
/// * `admin_pin` - The admin PIN for the card
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::card::upload::{upload_primary_key_to_card, CardKeySlot};
///
/// // Key structure:
/// // - Primary: Ed25519 [S,C] (Sign + Certify)
/// // - Subkey 1: Ed25519 [S] (Sign)
/// // - Subkey 2: CV25519 [E] (Encrypt)
/// // - Subkey 3: Ed25519 [A] (Authenticate)
/// //
/// // This uploads ONLY the primary key to the signing slot
/// let secret_key = std::fs::read("secret.asc").unwrap();
/// upload_primary_key_to_card(&secret_key, b"password", CardKeySlot::Signing, b"12345678").unwrap();
/// ```
pub fn upload_primary_key_to_card(
    secret_key_data: &[u8],
    key_password: &[u8],
    slot: CardKeySlot,
    admin_pin: &[u8],
) -> Result<()> {
    let secret_key = parse_secret_key(secret_key_data)?;
    let password = if key_password.is_empty() {
        Password::empty()
    } else {
        Password::from(std::str::from_utf8(key_password)
            .map_err(|_| Error::Parse("Password must be valid UTF-8".to_string()))?)
    };

    // Extract primary key info
    let key_info = extract_primary_key_info(&secret_key, &password)?;

    // Upload to card using talktosc
    upload_with_talktosc(&key_info, slot, admin_pin)
}

/// Upload a specific subkey by fingerprint to a card slot.
///
/// # Arguments
///
/// * `secret_key_data` - The secret key file contents (armored or binary)
/// * `key_password` - Password to unlock the secret key (empty for unencrypted keys)
/// * `fingerprint` - Hex fingerprint of the subkey to upload (case insensitive)
/// * `slot` - Which card slot to upload to
/// * `admin_pin` - The admin PIN for the card
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::card::upload::{upload_subkey_by_fingerprint, CardKeySlot};
///
/// let secret_key = std::fs::read("secret.asc").unwrap();
/// // Upload a specific subkey by its fingerprint
/// upload_subkey_by_fingerprint(
///     &secret_key,
///     b"password",
///     "5286C32E7C71E14C4C82F9AE0B207108925CB162",
///     CardKeySlot::Signing,
///     b"12345678"
/// ).unwrap();
/// ```
pub fn upload_subkey_by_fingerprint(
    secret_key_data: &[u8],
    key_password: &[u8],
    fingerprint: &str,
    slot: CardKeySlot,
    admin_pin: &[u8],
) -> Result<()> {
    let secret_key = parse_secret_key(secret_key_data)?;
    let password = if key_password.is_empty() {
        Password::empty()
    } else {
        Password::from(std::str::from_utf8(key_password)
            .map_err(|_| Error::Parse("Password must be valid UTF-8".to_string()))?)
    };

    // Normalize fingerprint (remove spaces, lowercase)
    let fp_normalized: String = fingerprint
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_lowercase();

    // Check primary key first
    let primary_fp = hex::encode(secret_key.primary_key.fingerprint().as_bytes());
    if primary_fp == fp_normalized {
        let key_info = extract_primary_key_info(&secret_key, &password)?;
        return upload_with_talktosc(&key_info, slot, admin_pin);
    }

    // Search in subkeys
    for subkey in &secret_key.secret_subkeys {
        let subkey_fp = hex::encode(subkey.key.fingerprint().as_bytes());
        if subkey_fp == fp_normalized {
            let timestamp = subkey.key.created_at().as_secs() as u32;
            let fp_bytes = subkey.key.fingerprint().as_bytes().to_vec();

            let key_info = subkey.key.unlock(&password, |pub_p, priv_key| {
                extract_key_info(pub_p, priv_key, timestamp, fp_bytes.clone())
            }).map_err(|e| Error::Crypto(e.to_string()))??;

            return upload_with_talktosc(&key_info, slot, admin_pin);
        }
    }

    Err(Error::Crypto(format!(
        "No key found with fingerprint: {}",
        fingerprint
    )))
}

/// Extract key info from the primary key
fn extract_primary_key_info(
    secret_key: &SignedSecretKey,
    password: &Password,
) -> Result<KeyUploadInfo> {
    let primary = &secret_key.primary_key;
    let timestamp = primary.created_at().as_secs() as u32;
    let fingerprint = primary.fingerprint().as_bytes().to_vec();

    primary.unlock(password, |pub_p, priv_key| {
        extract_key_info(pub_p, priv_key, timestamp, fingerprint.clone())
    }).map_err(|e| Error::Crypto(e.to_string()))?
      .map_err(|e| Error::Crypto(e.to_string()))
}

struct KeyUploadInfo {
    key_type: KeyType,
    scalar: Vec<u8>,       // Private key scalar (for ECC) or components (for RSA)
    fingerprint: Vec<u8>,
    timestamp: u32,
    // RSA-specific
    n_bits: Option<u16>,
    e_bits: Option<u16>,
    e_value: Option<Vec<u8>>,
    p_value: Option<Vec<u8>>,
    q_value: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy)]
enum KeyType {
    Ed25519,
    Cv25519,
    Rsa,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
    EcdhP256,
    EcdhP384,
    EcdhP521,
}

/// Parse a secret key from armored or binary format
fn parse_secret_key(data: &[u8]) -> Result<SignedSecretKey> {
    // Try armored first
    match SignedSecretKey::from_armor_single(Cursor::new(data)) {
        Ok((key, _headers)) => Ok(key),
        Err(_) => {
            // Try binary
            SignedSecretKey::from_bytes(data)
                .map_err(|e| Error::Parse(e.to_string()))
        }
    }
}

/// Find the appropriate key material for the requested slot
fn find_key_for_slot(
    secret_key: &SignedSecretKey,
    password: &Password,
    slot: CardKeySlot,
) -> Result<KeyUploadInfo> {
    match slot {
        CardKeySlot::Signing | CardKeySlot::Authentication => find_signing_key(secret_key, password),
        CardKeySlot::Decryption => find_encryption_key(secret_key, password),
    }
}

/// Check if algorithm supports signing
fn is_signing_algorithm(params: &PublicParams) -> bool {
    matches!(params,
        PublicParams::RSA(_) |
        PublicParams::EdDSALegacy(_) |
        PublicParams::Ed25519(_) |
        PublicParams::ECDSA(_)
    )
}

/// Check if algorithm supports encryption
fn is_encryption_algorithm(params: &PublicParams) -> bool {
    matches!(params,
        PublicParams::RSA(_) |
        PublicParams::ECDH(_) |
        PublicParams::X25519(_)
    )
}

/// Find a signing-capable key (checks both algorithm and key flags)
fn find_signing_key(
    secret_key: &SignedSecretKey,
    password: &Password,
) -> Result<KeyUploadInfo> {
    // First check subkeys for a signing key
    for subkey in &secret_key.secret_subkeys {
        let pub_params = subkey.key.public_params();
        // Check algorithm supports signing
        if !is_signing_algorithm(pub_params) {
            continue;
        }
        // Check if binding signature has signing flag
        let has_signing_flag = subkey.signatures.iter().any(|sig| {
            sig.key_flags().sign()
        });
        if !has_signing_flag {
            continue;
        }

        let timestamp = subkey.key.created_at().as_secs() as u32;
        let fingerprint = subkey.key.fingerprint().as_bytes().to_vec();

        let info = subkey.key.unlock(password, |pub_p, priv_key| {
            extract_key_info(pub_p, priv_key, timestamp, fingerprint.clone())
        }).map_err(|e| Error::Crypto(e.to_string()))??;

        return Ok(info);
    }

    // Fall back to primary key
    let primary = &secret_key.primary_key;
    let pub_params = primary.public_params();
    if is_signing_algorithm(pub_params) {
        let timestamp = primary.created_at().as_secs() as u32;
        let fingerprint = primary.fingerprint().as_bytes().to_vec();

        let info = primary.unlock(password, |pub_p, priv_key| {
            extract_key_info(pub_p, priv_key, timestamp, fingerprint.clone())
        }).map_err(|e| Error::Crypto(e.to_string()))??;

        return Ok(info);
    }

    Err(Error::Crypto("No signing-capable key found".to_string()))
}

/// Find an encryption-capable key (checks both algorithm and key flags)
fn find_encryption_key(
    secret_key: &SignedSecretKey,
    password: &Password,
) -> Result<KeyUploadInfo> {
    // First check subkeys
    for subkey in &secret_key.secret_subkeys {
        let pub_params = subkey.key.public_params();
        // Check algorithm supports encryption
        if !is_encryption_algorithm(pub_params) {
            continue;
        }
        // Check if binding signature has encryption flags
        let has_encryption_flags = subkey.signatures.iter().any(|sig| {
            let flags = sig.key_flags();
            flags.encrypt_comms() || flags.encrypt_storage()
        });
        if !has_encryption_flags {
            continue;
        }

        let timestamp = subkey.key.created_at().as_secs() as u32;
        let fingerprint = subkey.key.fingerprint().as_bytes().to_vec();

        let info = subkey.key.unlock(password, |pub_p, priv_key| {
            extract_key_info(pub_p, priv_key, timestamp, fingerprint.clone())
        }).map_err(|e| Error::Crypto(e.to_string()))??;

        return Ok(info);
    }

    // Fall back to primary key
    let primary = &secret_key.primary_key;
    let pub_params = primary.public_params();
    if is_encryption_algorithm(pub_params) {
        let timestamp = primary.created_at().as_secs() as u32;
        let fingerprint = primary.fingerprint().as_bytes().to_vec();

        let info = primary.unlock(password, |pub_p, priv_key| {
            extract_key_info(pub_p, priv_key, timestamp, fingerprint.clone())
        }).map_err(|e| Error::Crypto(e.to_string()))??;

        return Ok(info);
    }

    Err(Error::Crypto("No encryption-capable key found".to_string()))
}

fn extract_key_info(
    pub_params: &PublicParams,
    priv_params: &PlainSecretParams,
    timestamp: u32,
    fingerprint: Vec<u8>,
) -> crate::pgp::errors::Result<KeyUploadInfo> {
    use rsa::traits::PublicKeyParts;

    match (pub_params, priv_params) {
        (PublicParams::EdDSALegacy(_), PlainSecretParams::Ed25519Legacy(ed_priv)) |
        (PublicParams::Ed25519(_), PlainSecretParams::Ed25519(ed_priv)) => {
            Ok(KeyUploadInfo {
                key_type: KeyType::Ed25519,
                scalar: ed_priv.to_bytes().to_vec(),
                fingerprint,
                timestamp,
                n_bits: None,
                e_bits: None,
                e_value: None,
                p_value: None,
                q_value: None,
            })
        }
        (PublicParams::ECDH(ecdh_pub), PlainSecretParams::ECDH(ecdh_priv)) => {
            use crate::pgp::types::EcdhPublicParams;
            match ecdh_pub {
                EcdhPublicParams::Curve25519 { .. } => {
                    // CV25519 scalar needs to be in big-endian format for the card
                    // rpgp stores it in little-endian (native x25519 format), so we reverse
                    let scalar_le = ecdh_priv.to_bytes();
                    let scalar_be: Vec<u8> = scalar_le.iter().rev().copied().collect();
                    Ok(KeyUploadInfo {
                        key_type: KeyType::Cv25519,
                        scalar: scalar_be,
                        fingerprint,
                        timestamp,
                        n_bits: None,
                        e_bits: None,
                        e_value: None,
                        p_value: None,
                        q_value: None,
                    })
                }
                EcdhPublicParams::P256 { .. } => {
                    Ok(KeyUploadInfo {
                        key_type: KeyType::EcdhP256,
                        scalar: ecdh_priv.to_bytes(),
                        fingerprint,
                        timestamp,
                        n_bits: None,
                        e_bits: None,
                        e_value: None,
                        p_value: None,
                        q_value: None,
                    })
                }
                EcdhPublicParams::P384 { .. } => {
                    Ok(KeyUploadInfo {
                        key_type: KeyType::EcdhP384,
                        scalar: ecdh_priv.to_bytes(),
                        fingerprint,
                        timestamp,
                        n_bits: None,
                        e_bits: None,
                        e_value: None,
                        p_value: None,
                        q_value: None,
                    })
                }
                EcdhPublicParams::P521 { .. } => {
                    Ok(KeyUploadInfo {
                        key_type: KeyType::EcdhP521,
                        scalar: ecdh_priv.to_bytes(),
                        fingerprint,
                        timestamp,
                        n_bits: None,
                        e_bits: None,
                        e_value: None,
                        p_value: None,
                        q_value: None,
                    })
                }
                _ => Err(crate::pgp::errors::format_err!("Unsupported ECDH curve for card")),
            }
        }
        (PublicParams::RSA(rsa_pub), PlainSecretParams::RSA(rsa_priv)) => {
            let (d, p, q, _u) = rsa_priv.to_bytes();
            let n = rsa_pub.key.n();
            let e = rsa_pub.key.e();

            Ok(KeyUploadInfo {
                key_type: KeyType::Rsa,
                scalar: d, // d for RSA
                fingerprint,
                timestamp,
                n_bits: Some(n.bits() as u16),
                e_bits: Some(e.bits() as u16),
                e_value: Some(e.to_bytes_be()),
                p_value: Some(p),
                q_value: Some(q),
            })
        }
        (PublicParams::ECDSA(ecdsa_pub), PlainSecretParams::ECDSA(ecdsa_priv)) => {
            use crate::pgp::types::EcdsaPublicParams;
            let key_type = match ecdsa_pub {
                EcdsaPublicParams::P256 { .. } => KeyType::EcdsaP256,
                EcdsaPublicParams::P384 { .. } => KeyType::EcdsaP384,
                EcdsaPublicParams::P521 { .. } => KeyType::EcdsaP521,
                _ => return Err(crate::pgp::errors::format_err!("Unsupported ECDSA curve for card")),
            };
            Ok(KeyUploadInfo {
                key_type,
                scalar: ecdsa_priv.to_bytes(),
                fingerprint,
                timestamp,
                n_bits: None,
                e_bits: None,
                e_value: None,
                p_value: None,
                q_value: None,
            })
        }
        _ => Err(crate::pgp::errors::format_err!(
            "Unsupported key type for card upload"
        )),
    }
}

/// Upload key to card using talktosc
fn upload_with_talktosc(
    key_info: &KeyUploadInfo,
    slot: CardKeySlot,
    admin_pin: &[u8],
) -> Result<()> {
    use talktosc::apdus::APDU;
    use talktosc::{create_connection, send_and_parse, disconnect};

    // Create connection to card
    let card = create_connection().map_err(|e| {
        Error::Card(super::types::CardError::CommunicationError(
            format!("Failed to connect to card: {}", e)
        ))
    })?;

    // Select OpenPGP application
    let select_apdu = APDU::new(0x00, 0xA4, 0x04, 0x00, Some(vec![0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]));
    let resp = send_and_parse(&card, select_apdu);
    if resp.is_err() {
        disconnect(card);
        return Err(Error::Card(super::types::CardError::CommunicationError(
            "Failed to select OpenPGP applet".to_string()
        )));
    }

    // Verify admin PIN (PW3)
    let pw3_apdu = talktosc::apdus::create_apdu_verify_pw3(admin_pin.to_vec());
    let resp = send_and_parse(&card, pw3_apdu);
    if resp.is_err() {
        disconnect(card);
        return Err(Error::Card(super::types::CardError::PinIncorrect {
            retries_remaining: 3,
        }));
    }

    // Build and send algorithm attributes
    let algo_attrs = build_algo_attributes(key_info);
    let algo_apdu = APDU::create_big_apdu(0x00, 0xDA, 0x00, slot.algo_p2(), algo_attrs);
    let resp = send_and_parse(&card, algo_apdu);
    if resp.is_err() {
        disconnect(card);
        return Err(Error::Card(super::types::CardError::CommunicationError(
            "Failed to set algorithm attributes".to_string()
        )));
    }

    // Verify admin PIN again (required by some cards)
    let pw3_apdu = talktosc::apdus::create_apdu_verify_pw3(admin_pin.to_vec());
    let _ = send_and_parse(&card, pw3_apdu);

    // Build and send key import data
    let key_data = build_key_import_data(key_info, slot)?;
    let import_apdu = APDU::create_big_apdu(0x00, 0xDB, 0x3F, 0xFF, key_data);
    let resp = send_and_parse(&card, import_apdu);
    if resp.is_err() {
        disconnect(card);
        return Err(Error::Card(super::types::CardError::CommunicationError(
            "Failed to import key".to_string()
        )));
    }

    // Set fingerprint
    let fp_apdu = APDU::create_big_apdu(0x00, 0xDA, 0x00, slot.fp_p2(), key_info.fingerprint.clone());
    let resp = send_and_parse(&card, fp_apdu);
    if resp.is_err() {
        disconnect(card);
        return Err(Error::Card(super::types::CardError::CommunicationError(
            "Failed to set fingerprint".to_string()
        )));
    }

    // Set timestamp
    let time_value: Vec<u8> = key_info.timestamp
        .to_be_bytes()
        .iter()
        .skip_while(|&&e| e == 0)
        .copied()
        .collect();
    let time_apdu = APDU::new(0x00, 0xDA, 0x00, slot.time_p2(), Some(time_value));
    let resp = send_and_parse(&card, time_apdu);
    if resp.is_err() {
        disconnect(card);
        return Err(Error::Card(super::types::CardError::CommunicationError(
            "Failed to set timestamp".to_string()
        )));
    }

    disconnect(card);
    Ok(())
}

fn build_algo_attributes(key_info: &KeyUploadInfo) -> Vec<u8> {
    match key_info.key_type {
        KeyType::Ed25519 => {
            // EdDSA with Ed25519 OID: 1.3.6.1.4.1.11591.15.1
            vec![0x16, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01]
        }
        KeyType::Cv25519 => {
            // ECDH with cv25519 OID: 1.3.6.1.4.1.3029.1.5.1
            vec![0x12, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01]
        }
        KeyType::EcdsaP256 => {
            // ECDSA with NIST P-256 OID: 1.2.840.10045.3.1.7
            vec![0x13, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]
        }
        KeyType::EcdsaP384 => {
            // ECDSA with NIST P-384 OID: 1.3.132.0.34
            vec![0x13, 0x2B, 0x81, 0x04, 0x00, 0x22]
        }
        KeyType::EcdsaP521 => {
            // ECDSA with NIST P-521 OID: 1.3.132.0.35
            vec![0x13, 0x2B, 0x81, 0x04, 0x00, 0x23]
        }
        KeyType::EcdhP256 => {
            // ECDH with NIST P-256 OID: 1.2.840.10045.3.1.7
            vec![0x12, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]
        }
        KeyType::EcdhP384 => {
            // ECDH with NIST P-384 OID: 1.3.132.0.34
            vec![0x12, 0x2B, 0x81, 0x04, 0x00, 0x22]
        }
        KeyType::EcdhP521 => {
            // ECDH with NIST P-521 OID: 1.3.132.0.35
            vec![0x12, 0x2B, 0x81, 0x04, 0x00, 0x23]
        }
        KeyType::Rsa => {
            let mut attrs = vec![0x01]; // RSA algorithm ID

            // n bit length (2 bytes)
            if let Some(n_bits) = key_info.n_bits {
                attrs.extend(n_bits.to_be_bytes());
            }

            // e bit length (2 bytes)
            if let Some(e_bits) = key_info.e_bits {
                attrs.extend(e_bits.to_be_bytes());
            }

            // Import format: 00 = standard (e, p, q)
            attrs.push(0x00);

            attrs
        }
    }
}

fn build_key_import_data(key_info: &KeyUploadInfo, slot: CardKeySlot) -> Result<Vec<u8>> {
    let mut for4d: Vec<u8> = vec![0x4D];

    match key_info.key_type {
        KeyType::Ed25519 | KeyType::Cv25519 | KeyType::EcdsaP256 | KeyType::EcdsaP384 | KeyType::EcdsaP521 |
        KeyType::EcdhP256 | KeyType::EcdhP384 | KeyType::EcdhP521 => {
            // Build 5F48 TLV (private key scalar)
            let mut for5f48: Vec<u8> = vec![0x5F, 0x48];
            let scalar_len = key_info.scalar.len();
            if scalar_len > 0x7F {
                // Use 2-byte length encoding for larger scalars (P-384: 48 bytes, P-521: 66 bytes)
                for5f48.push(0x81);
                for5f48.push(scalar_len as u8);
            } else {
                for5f48.push(scalar_len as u8);
            }
            for5f48.extend(&key_info.scalar);

            // Build 7F48 TLV (template)
            let mut for7f48 = vec![0x7F, 0x48];
            if scalar_len > 0x7F {
                for7f48.extend([0x03, 0x92, 0x81, scalar_len as u8]);
            } else {
                for7f48.extend([0x02, 0x92, scalar_len as u8]);
            }

            // Combine into main data
            let mut maindata: Vec<u8> = slot.crt_tag().to_vec();
            maindata.extend(&for7f48);
            maindata.extend(&for5f48);

            // Add length to 4D tag
            let maindata_len = maindata.len();
            if maindata_len > 0x7F {
                for4d.push(0x81);
            }
            for4d.push(maindata_len as u8);
            for4d.extend(maindata);
        }
        KeyType::Rsa => {
            // Build result: e + p + q
            let mut result: Vec<u8> = Vec::new();
            if let Some(ref e) = key_info.e_value {
                result.extend(e);
            }
            if let Some(ref p) = key_info.p_value {
                result.extend(p);
            }
            if let Some(ref q) = key_info.q_value {
                result.extend(q);
            }

            // Build 5F48 TLV
            let mut for5f48: Vec<u8> = vec![0x5F, 0x48];
            let len = result.len() as u16;
            if len > 0xFF {
                for5f48.push(0x82);
            } else {
                for5f48.push(0x81);
            }
            let length = len.to_be_bytes();
            for5f48.push(length[0]);
            for5f48.push(length[1]);
            for5f48.extend(result);

            // Build 7F48 TLV for RSA
            let for7f48 = vec![
                0x7F, 0x48, 0x0A, 0x91, 0x03, 0x92, 0x82, 0x01, 0x00, 0x93, 0x82, 0x01, 0x00,
            ];

            // Combine into main data
            let mut maindata: Vec<u8> = slot.crt_tag().to_vec();
            maindata.extend(&for7f48);
            maindata.extend(&for5f48);

            // Add length to 4D tag
            let len = maindata.len() as u16;
            if len > 0xFF {
                for4d.push(0x82);
            } else {
                for4d.push(0x81);
            }
            let length = len.to_be_bytes();
            for4d.push(length[0]);
            for4d.push(length[1]);
            for4d.extend(maindata);
        }
    }

    Ok(for4d)
}
