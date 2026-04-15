//! Key upload functionality for smart cards.
//!
//! This module provides functions to upload private keys to an OpenPGP smart card.
//! Uses openpgp-card's key import API for structured key upload with proper
//! algorithm attribute negotiation and TLV encoding.

use std::cell::RefCell;
use std::io::Cursor;

use openpgp_card::ocard::crypto::{CardUploadableKey, EccType, PrivateKeyMaterial};
use openpgp_card::ocard::data::{Fingerprint, KeyGenerationTime};
use openpgp_card::Card;
use secrecy::SecretString;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use pgp::composed::{Deserializable, SignedSecretKey};
use pgp::types::{KeyDetails, Password, PlainSecretParams, PublicParams};

use super::types::CardError;

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
    fn to_openpgp_key_type(self) -> openpgp_card::ocard::KeyType {
        match self {
            CardKeySlot::Signing => openpgp_card::ocard::KeyType::Signing,
            CardKeySlot::Decryption => openpgp_card::ocard::KeyType::Decryption,
            CardKeySlot::Authentication => openpgp_card::ocard::KeyType::Authentication,
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
    let secret_key = parse_secret_key(secret_key_data)?;
    let password = if key_password.is_empty() {
        Password::empty()
    } else {
        Password::from(
            std::str::from_utf8(key_password)
                .map_err(|_| Error::Parse("Password must be valid UTF-8".to_string()))?,
        )
    };

    let key_info = find_key_for_slot(&secret_key, &password, slot)?;
    upload_via_openpgp_card(key_info, slot, admin_pin)
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
        Password::from(
            std::str::from_utf8(key_password)
                .map_err(|_| Error::Parse("Password must be valid UTF-8".to_string()))?,
        )
    };

    let key_info = extract_primary_key_info(&secret_key, &password)?;
    upload_via_openpgp_card(key_info, slot, admin_pin)
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
        Password::from(
            std::str::from_utf8(key_password)
                .map_err(|_| Error::Parse("Password must be valid UTF-8".to_string()))?,
        )
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
        return upload_via_openpgp_card(key_info, slot, admin_pin);
    }

    // Search in subkeys
    for subkey in &secret_key.secret_subkeys {
        let subkey_fp = hex::encode(subkey.key.fingerprint().as_bytes());
        if subkey_fp == fp_normalized {
            let timestamp = subkey.key.created_at().as_secs();
            let fp_bytes = subkey.key.fingerprint().as_bytes().to_vec();

            let key_info = subkey
                .key
                .unlock(&password, |pub_p, priv_key| {
                    extract_key_info(pub_p, priv_key, timestamp, fp_bytes.clone())
                })
                .map_err(|e| Error::Crypto(e.to_string()))??;

            return upload_via_openpgp_card(key_info, slot, admin_pin);
        }
    }

    Err(Error::Crypto(format!(
        "No key found with fingerprint: {}",
        fingerprint
    )))
}

// ---------------------------------------------------------------------------
// Internal data structures
// ---------------------------------------------------------------------------

struct KeyUploadInfo {
    fingerprint: Vec<u8>,
    timestamp: u32,
    key_material: KeyMaterial,
}

enum KeyMaterial {
    Ecc {
        scalar: Zeroizing<Vec<u8>>,
        public_key: Vec<u8>,
        oid: Vec<u8>,
        ecc_type: EccType,
    },
    Rsa {
        e: Vec<u8>,
        n: Vec<u8>,
        p: Zeroizing<Vec<u8>>,
        q: Zeroizing<Vec<u8>>,
        dp1: Zeroizing<Vec<u8>>,
        dq1: Zeroizing<Vec<u8>>,
        pq: Zeroizing<Vec<u8>>,
    },
}

// ---------------------------------------------------------------------------
// openpgp-card trait implementations
// ---------------------------------------------------------------------------

struct UploadableEccKey {
    oid: Vec<u8>,
    private_scalar: Zeroizing<Vec<u8>>,
    public_point: Vec<u8>,
    ecc_type: EccType,
}

impl openpgp_card::ocard::crypto::EccKey for UploadableEccKey {
    fn oid(&self) -> &[u8] {
        &self.oid
    }
    fn private(&self) -> Vec<u8> {
        self.private_scalar.to_vec()
    }
    fn public(&self) -> Vec<u8> {
        self.public_point.clone()
    }
    fn ecc_type(&self) -> EccType {
        self.ecc_type
    }
}

struct UploadableRsaKey {
    e: Vec<u8>,
    n: Vec<u8>,
    p: Zeroizing<Vec<u8>>,
    q: Zeroizing<Vec<u8>>,
    dp1: Zeroizing<Vec<u8>>,
    dq1: Zeroizing<Vec<u8>>,
    pq: Zeroizing<Vec<u8>>,
}

impl openpgp_card::ocard::crypto::RSAKey for UploadableRsaKey {
    fn e(&self) -> &[u8] {
        &self.e
    }
    fn p(&self) -> &[u8] {
        &self.p
    }
    fn q(&self) -> &[u8] {
        &self.q
    }
    fn pq(&self) -> Box<[u8]> {
        self.pq.to_vec().into_boxed_slice()
    }
    fn dp1(&self) -> Box<[u8]> {
        self.dp1.to_vec().into_boxed_slice()
    }
    fn dq1(&self) -> Box<[u8]> {
        self.dq1.to_vec().into_boxed_slice()
    }
    fn n(&self) -> &[u8] {
        &self.n
    }
}

struct UploadableKey {
    material: RefCell<Option<PrivateKeyMaterial>>,
    fp: [u8; 20],
    ts: u32,
}

impl CardUploadableKey for UploadableKey {
    fn private_key(&self) -> std::result::Result<PrivateKeyMaterial, openpgp_card::Error> {
        self.material.borrow_mut().take().ok_or_else(|| {
            openpgp_card::Error::InternalError("Key material already consumed".into())
        })
    }

    fn timestamp(&self) -> KeyGenerationTime {
        self.ts.into()
    }

    fn fingerprint(&self) -> std::result::Result<Fingerprint, openpgp_card::Error> {
        Ok(self.fp.into())
    }
}

// ---------------------------------------------------------------------------
// Upload via openpgp-card
// ---------------------------------------------------------------------------

fn upload_via_openpgp_card(
    key_info: KeyUploadInfo,
    slot: CardKeySlot,
    admin_pin: &[u8],
) -> Result<()> {
    let key_type = slot.to_openpgp_key_type();

    // Build the PrivateKeyMaterial
    let material = match key_info.key_material {
        KeyMaterial::Ecc {
            scalar,
            public_key,
            oid,
            ecc_type,
        } => PrivateKeyMaterial::E(Box::new(UploadableEccKey {
            oid,
            private_scalar: scalar,
            public_point: public_key,
            ecc_type,
        })),
        KeyMaterial::Rsa {
            e,
            n,
            p,
            q,
            dp1,
            dq1,
            pq,
        } => PrivateKeyMaterial::R(Box::new(UploadableRsaKey {
            e,
            n,
            p,
            q,
            dp1,
            dq1,
            pq,
        })),
    };

    // Build the fingerprint array
    let fp: [u8; 20] = key_info
        .fingerprint
        .as_slice()
        .try_into()
        .map_err(|_| Error::Crypto("Fingerprint must be exactly 20 bytes".to_string()))?;

    let uploadable = UploadableKey {
        material: RefCell::new(Some(material)),
        fp,
        ts: key_info.timestamp,
    };

    // Connect to card
    let backend = super::connection::get_card_backend(None)?;
    let mut card = Card::new(backend)
        .map_err(|e| Error::Card(CardError::CommunicationError(e.to_string())))?;
    let mut tx = card
        .transaction()
        .map_err(|e| Error::Card(CardError::CommunicationError(e.to_string())))?;

    // Verify admin PIN and get admin card — zeroize the intermediate String
    let pin_str = std::str::from_utf8(admin_pin).map_err(|_| {
        Error::Card(CardError::InvalidData(
            "Admin PIN must be valid UTF-8".to_string(),
        ))
    })?;
    let mut pin_owned = pin_str.to_string();
    let pin_secret: SecretString = pin_owned.clone().into();
    zeroize::Zeroize::zeroize(&mut pin_owned);

    let mut admin = tx
        .to_admin_card(pin_secret)
        .map_err(|e| Error::Card(CardError::from(e)))?;

    // Import the key
    admin
        .import_key(Box::new(uploadable), key_type)
        .map_err(|e| {
            Error::Card(CardError::CommunicationError(format!(
                "Key import failed: {}",
                e
            )))
        })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Key parsing and extraction
// ---------------------------------------------------------------------------

/// Parse a secret key from armored or binary format
fn parse_secret_key(data: &[u8]) -> Result<SignedSecretKey> {
    match SignedSecretKey::from_armor_single(Cursor::new(data)) {
        Ok((key, _headers)) => Ok(key),
        Err(_) => SignedSecretKey::from_bytes(data).map_err(|e| Error::Parse(e.to_string())),
    }
}

/// Find the appropriate key material for the requested slot
fn find_key_for_slot(
    secret_key: &SignedSecretKey,
    password: &Password,
    slot: CardKeySlot,
) -> Result<KeyUploadInfo> {
    match slot {
        CardKeySlot::Signing | CardKeySlot::Authentication => {
            find_signing_key(secret_key, password)
        }
        CardKeySlot::Decryption => find_encryption_key(secret_key, password),
    }
}

fn is_signing_algorithm(params: &PublicParams) -> bool {
    matches!(
        params,
        PublicParams::RSA(_)
            | PublicParams::EdDSALegacy(_)
            | PublicParams::Ed25519(_)
            | PublicParams::ECDSA(_)
    )
}

fn is_encryption_algorithm(params: &PublicParams) -> bool {
    matches!(
        params,
        PublicParams::RSA(_) | PublicParams::ECDH(_) | PublicParams::X25519(_)
    )
}

fn find_signing_key(secret_key: &SignedSecretKey, password: &Password) -> Result<KeyUploadInfo> {
    for subkey in &secret_key.secret_subkeys {
        let pub_params = subkey.key.public_params();
        if !is_signing_algorithm(pub_params) {
            continue;
        }
        let has_signing_flag = subkey.signatures.iter().any(|sig| sig.key_flags().sign());
        if !has_signing_flag {
            continue;
        }

        let timestamp = subkey.key.created_at().as_secs();
        let fingerprint = subkey.key.fingerprint().as_bytes().to_vec();

        let info = subkey
            .key
            .unlock(password, |pub_p, priv_key| {
                extract_key_info(pub_p, priv_key, timestamp, fingerprint.clone())
            })
            .map_err(|e| Error::Crypto(e.to_string()))??;

        return Ok(info);
    }

    let primary = &secret_key.primary_key;
    let pub_params = primary.public_params();
    if is_signing_algorithm(pub_params) {
        let timestamp = primary.created_at().as_secs();
        let fingerprint = primary.fingerprint().as_bytes().to_vec();

        let info = primary
            .unlock(password, |pub_p, priv_key| {
                extract_key_info(pub_p, priv_key, timestamp, fingerprint.clone())
            })
            .map_err(|e| Error::Crypto(e.to_string()))??;

        return Ok(info);
    }

    Err(Error::Crypto("No signing-capable key found".to_string()))
}

fn find_encryption_key(secret_key: &SignedSecretKey, password: &Password) -> Result<KeyUploadInfo> {
    for subkey in &secret_key.secret_subkeys {
        let pub_params = subkey.key.public_params();
        if !is_encryption_algorithm(pub_params) {
            continue;
        }
        let has_encryption_flags = subkey.signatures.iter().any(|sig| {
            let flags = sig.key_flags();
            flags.encrypt_comms() || flags.encrypt_storage()
        });
        if !has_encryption_flags {
            continue;
        }

        let timestamp = subkey.key.created_at().as_secs();
        let fingerprint = subkey.key.fingerprint().as_bytes().to_vec();

        let info = subkey
            .key
            .unlock(password, |pub_p, priv_key| {
                extract_key_info(pub_p, priv_key, timestamp, fingerprint.clone())
            })
            .map_err(|e| Error::Crypto(e.to_string()))??;

        return Ok(info);
    }

    let primary = &secret_key.primary_key;
    let pub_params = primary.public_params();
    if is_encryption_algorithm(pub_params) {
        let timestamp = primary.created_at().as_secs();
        let fingerprint = primary.fingerprint().as_bytes().to_vec();

        let info = primary
            .unlock(password, |pub_p, priv_key| {
                extract_key_info(pub_p, priv_key, timestamp, fingerprint.clone())
            })
            .map_err(|e| Error::Crypto(e.to_string()))??;

        return Ok(info);
    }

    Err(Error::Crypto("No encryption-capable key found".to_string()))
}

/// Extract key info from the primary key
fn extract_primary_key_info(
    secret_key: &SignedSecretKey,
    password: &Password,
) -> Result<KeyUploadInfo> {
    let primary = &secret_key.primary_key;
    let timestamp = primary.created_at().as_secs();
    let fingerprint = primary.fingerprint().as_bytes().to_vec();

    primary
        .unlock(password, |pub_p, priv_key| {
            extract_key_info(pub_p, priv_key, timestamp, fingerprint.clone())
        })
        .map_err(|e| Error::Crypto(e.to_string()))?
        .map_err(|e| Error::Crypto(e.to_string()))
}

// OID constants matching openpgp-card's oid module
const OID_ED25519: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];
const OID_CV25519: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];
const OID_NIST_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const OID_NIST_P384: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];
const OID_NIST_P521: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x23];

fn extract_key_info(
    pub_params: &PublicParams,
    priv_params: &PlainSecretParams,
    timestamp: u32,
    fingerprint: Vec<u8>,
) -> pgp::errors::Result<KeyUploadInfo> {
    match (pub_params, priv_params) {
        // Ed25519 (legacy v4 and modern v6)
        (PublicParams::EdDSALegacy(ed_pub), PlainSecretParams::Ed25519Legacy(ed_priv)) => {
            use pgp::types::EddsaLegacyPublicParams;
            let public_key = match ed_pub {
                EddsaLegacyPublicParams::Ed25519 { key } => key.as_bytes().to_vec(),
                _ => return Err("Unsupported EdDSA curve for card".to_string().into()),
            };
            Ok(KeyUploadInfo {
                fingerprint,
                timestamp,
                key_material: KeyMaterial::Ecc {
                    scalar: Zeroizing::new(ed_priv.to_bytes().to_vec()),
                    public_key,
                    oid: OID_ED25519.to_vec(),
                    ecc_type: EccType::EdDSA,
                },
            })
        }
        (PublicParams::Ed25519(ed_pub), PlainSecretParams::Ed25519(ed_priv)) => Ok(KeyUploadInfo {
            fingerprint,
            timestamp,
            key_material: KeyMaterial::Ecc {
                scalar: Zeroizing::new(ed_priv.to_bytes().to_vec()),
                public_key: ed_pub.key.as_bytes().to_vec(),
                oid: OID_ED25519.to_vec(),
                ecc_type: EccType::EdDSA,
            },
        }),
        // ECDH (Cv25519 and NIST curves)
        (PublicParams::ECDH(ecdh_pub), PlainSecretParams::ECDH(ecdh_priv)) => {
            use pgp::types::EcdhPublicParams;
            match ecdh_pub {
                EcdhPublicParams::Curve25519 { p, .. } => {
                    // CV25519 scalar: rpgp stores little-endian, card expects big-endian
                    let scalar_le = ecdh_priv.to_bytes();
                    let scalar_be: Vec<u8> = scalar_le.iter().rev().copied().collect();
                    Ok(KeyUploadInfo {
                        fingerprint,
                        timestamp,
                        key_material: KeyMaterial::Ecc {
                            scalar: Zeroizing::new(scalar_be),
                            public_key: p.as_bytes().to_vec(),
                            oid: OID_CV25519.to_vec(),
                            ecc_type: EccType::ECDH,
                        },
                    })
                }
                EcdhPublicParams::P256 { p, .. } => Ok(KeyUploadInfo {
                    fingerprint,
                    timestamp,
                    key_material: KeyMaterial::Ecc {
                        scalar: Zeroizing::new(ecdh_priv.to_bytes()),
                        public_key: p.to_sec1_bytes().to_vec(),
                        oid: OID_NIST_P256.to_vec(),
                        ecc_type: EccType::ECDH,
                    },
                }),
                EcdhPublicParams::P384 { p, .. } => Ok(KeyUploadInfo {
                    fingerprint,
                    timestamp,
                    key_material: KeyMaterial::Ecc {
                        scalar: Zeroizing::new(ecdh_priv.to_bytes()),
                        public_key: p.to_sec1_bytes().to_vec(),
                        oid: OID_NIST_P384.to_vec(),
                        ecc_type: EccType::ECDH,
                    },
                }),
                EcdhPublicParams::P521 { p, .. } => Ok(KeyUploadInfo {
                    fingerprint,
                    timestamp,
                    key_material: KeyMaterial::Ecc {
                        scalar: Zeroizing::new(ecdh_priv.to_bytes()),
                        public_key: p.to_sec1_bytes().to_vec(),
                        oid: OID_NIST_P521.to_vec(),
                        ecc_type: EccType::ECDH,
                    },
                }),
                _ => Err("Unsupported ECDH curve for card".to_string().into()),
            }
        }
        // RSA
        (PublicParams::RSA(rsa_pub), PlainSecretParams::RSA(rsa_priv)) => {
            use rsa::traits::{PrivateKeyParts, PublicKeyParts};
            use rsa::{BigUint, RsaPrivateKey};

            let (d, p, q, _u) = rsa_priv.to_bytes();
            let n_bn = rsa_pub.key.n().clone();
            let e_bn = rsa_pub.key.e().clone();
            let d_bn = BigUint::from_bytes_be(&d);
            let p_bn = BigUint::from_bytes_be(&p);
            let q_bn = BigUint::from_bytes_be(&q);

            let mut rsa_key = RsaPrivateKey::from_components(n_bn, e_bn, d_bn, vec![p_bn, q_bn])
                .map_err(|e| format!("Invalid RSA key: {}", e))?;
            rsa_key
                .precompute()
                .map_err(|e| format!("RSA precompute failed: {}", e))?;

            let dp1 = rsa_key
                .dp()
                .ok_or_else(|| String::from("Missing dp1"))?
                .to_bytes_be();
            let dq1 = rsa_key
                .dq()
                .ok_or_else(|| String::from("Missing dq1"))?
                .to_bytes_be();
            let pq = rsa_key
                .qinv()
                .ok_or_else(|| String::from("Missing qinv"))?
                .to_biguint()
                .ok_or_else(|| String::from("qinv is negative"))?
                .to_bytes_be();

            Ok(KeyUploadInfo {
                fingerprint,
                timestamp,
                key_material: KeyMaterial::Rsa {
                    e: rsa_pub.key.e().to_bytes_be(),
                    n: rsa_pub.key.n().to_bytes_be(),
                    p: Zeroizing::new(p),
                    q: Zeroizing::new(q),
                    dp1: Zeroizing::new(dp1),
                    dq1: Zeroizing::new(dq1),
                    pq: Zeroizing::new(pq),
                },
            })
        }
        // ECDSA (NIST curves)
        (PublicParams::ECDSA(ecdsa_pub), PlainSecretParams::ECDSA(ecdsa_priv)) => {
            use pgp::types::EcdsaPublicParams;
            match ecdsa_pub {
                EcdsaPublicParams::P256 { key } => {
                    use p256::elliptic_curve::sec1::ToEncodedPoint;
                    Ok(KeyUploadInfo {
                        fingerprint,
                        timestamp,
                        key_material: KeyMaterial::Ecc {
                            scalar: Zeroizing::new(ecdsa_priv.to_bytes()),
                            public_key: key.to_encoded_point(false).as_bytes().to_vec(),
                            oid: OID_NIST_P256.to_vec(),
                            ecc_type: EccType::ECDSA,
                        },
                    })
                }
                EcdsaPublicParams::P384 { key } => {
                    use p384::elliptic_curve::sec1::ToEncodedPoint;
                    Ok(KeyUploadInfo {
                        fingerprint,
                        timestamp,
                        key_material: KeyMaterial::Ecc {
                            scalar: Zeroizing::new(ecdsa_priv.to_bytes()),
                            public_key: key.to_encoded_point(false).as_bytes().to_vec(),
                            oid: OID_NIST_P384.to_vec(),
                            ecc_type: EccType::ECDSA,
                        },
                    })
                }
                EcdsaPublicParams::P521 { key } => {
                    use p521::elliptic_curve::sec1::ToEncodedPoint;
                    Ok(KeyUploadInfo {
                        fingerprint,
                        timestamp,
                        key_material: KeyMaterial::Ecc {
                            scalar: Zeroizing::new(ecdsa_priv.to_bytes()),
                            public_key: key.to_encoded_point(false).as_bytes().to_vec(),
                            oid: OID_NIST_P521.to_vec(),
                            ecc_type: EccType::ECDSA,
                        },
                    })
                }
                _ => Err("Unsupported ECDSA curve for card".to_string().into()),
            }
        }
        _ => Err("Unsupported key type for card upload".to_string().into()),
    }
}
