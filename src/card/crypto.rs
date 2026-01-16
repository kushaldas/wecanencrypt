//! Cryptographic operations using smart card.
//!
//! This module provides signing and decryption operations that use keys
//! stored on a YubiKey or other OpenPGP-compatible smart card.

use std::io::Cursor;

use card_backend_pcsc::PcscBackend;
use openpgp_card::ocard::crypto::{Cryptogram, Hash};
use openpgp_card::Card;
use secrecy::SecretString;

use super::types::CardError;
use crate::error::{Error, Result};
use crate::internal::parse_public_key;
use crate::pgp::composed::{DetachedSignature, Esk, Message, PlainSessionKey, RawSessionKey, SignedPublicKey};
use crate::pgp::crypto::hash::HashAlgorithm;
use crate::pgp::crypto::sym::SymmetricKeyAlgorithm;
use crate::pgp::packet::{Signature, SignatureConfig, SignatureType, Subpacket, SubpacketData};
use crate::pgp::types::{
    EskType, Fingerprint, KeyDetails, Mpi, PkeskBytes, PkeskVersion,
    PublicParams, SignatureBytes, Timestamp,
};

/// Sign bytes using the signing key on the smart card.
///
/// Creates a detached signature using the key stored in the signature slot
/// of the connected smart card.
///
/// # Arguments
///
/// * `data` - The data to sign
/// * `public_cert` - The public certificate corresponding to the key on the card
/// * `pin` - The user PIN for the card
///
/// # Returns
///
/// The ASCII-armored detached signature.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::card::sign_bytes_detached_on_card;
///
/// let public_key = std::fs::read("pubkey.asc").unwrap();
/// let signature = sign_bytes_detached_on_card(
///     b"Important document",
///     &public_key,
///     b"123456",
/// ).unwrap();
/// ```
pub fn sign_bytes_detached_on_card(data: &[u8], public_cert: &[u8], pin: &[u8]) -> Result<String> {
    let public_key = parse_public_key(public_cert)?;

    // Get signing key info from the public key
    let key_info = get_signing_key_info(&public_key)?;

    // Create the signature using the card
    let signature = create_card_signature(data, &key_info, pin)?;

    // Wrap in DetachedSignature and armor
    let detached = DetachedSignature::new(signature);
    detached
        .to_armored_string(None.into())
        .map_err(|e| Error::Crypto(e.to_string()))
}

/// Get the first available card backend.
fn get_card_backend() -> Result<PcscBackend> {
    let mut cards = PcscBackend::cards(None)
        .map_err(|e| Error::Card(CardError::CommunicationError(e.to_string())))?;

    cards.next()
        .ok_or(Error::Card(CardError::NotConnected))?
        .map_err(|e| Error::Card(CardError::CommunicationError(e.to_string())))
}

/// Convert a PIN byte slice to SecretString.
fn pin_to_secret(pin: &[u8]) -> Result<SecretString> {
    let pin_str = std::str::from_utf8(pin)
        .map_err(|_| Error::Card(CardError::InvalidData("PIN must be valid UTF-8".to_string())))?;
    Ok(SecretString::new(pin_str.to_string()))
}

/// Signing key info extracted from a public key
struct SigningKeyInfo {
    algorithm: crate::pgp::crypto::public_key::PublicKeyAlgorithm,
    public_params: PublicParams,
    fingerprint: Fingerprint,
    key_id: crate::pgp::types::KeyId,
    hash_alg: HashAlgorithm,
}

/// Get signing key info by matching the card's signing slot fingerprint against the public certificate.
///
/// This queries the card to get the actual fingerprint of the key in the signing slot,
/// then finds the matching key in the public certificate.
fn get_signing_key_info(public_key: &SignedPublicKey) -> Result<SigningKeyInfo> {
    // First, query the card to get the fingerprint of the key in the signing slot
    let card_fp = get_card_signing_fingerprint()?;

    // Try to match against the primary key
    let primary = &public_key.primary_key;
    let primary_fp = hex::encode(primary.fingerprint().as_bytes());
    if primary_fp == card_fp && can_sign(primary.public_params()) {
        let params = primary.public_params();
        let hash_alg = select_hash_for_params(params);
        return Ok(SigningKeyInfo {
            algorithm: primary.algorithm(),
            public_params: params.clone(),
            fingerprint: primary.fingerprint(),
            key_id: primary.legacy_key_id(),
            hash_alg,
        });
    }

    // Try to match against subkeys
    for subkey in &public_key.public_subkeys {
        let key = &subkey.key;
        let subkey_fp = hex::encode(key.fingerprint().as_bytes());
        if subkey_fp == card_fp && can_sign(key.public_params()) {
            let params = key.public_params();
            let hash_alg = select_hash_for_params(params);
            return Ok(SigningKeyInfo {
                algorithm: key.algorithm(),
                public_params: params.clone(),
                fingerprint: key.fingerprint(),
                key_id: key.legacy_key_id(),
                hash_alg,
            });
        }
    }

    Err(Error::Crypto(format!(
        "No key in certificate matches card signing slot fingerprint: {}",
        card_fp
    )))
}

/// Get the fingerprint of the key currently in the card's signing slot.
fn get_card_signing_fingerprint() -> Result<String> {
    let backend = get_card_backend()?;
    let mut card = Card::new(backend)
        .map_err(|e| Error::Card(CardError::from(e)))?;

    let mut tx = card.transaction()
        .map_err(|e| Error::Card(CardError::from(e)))?;

    let fps = tx.fingerprints()
        .map_err(|e| Error::Card(CardError::from(e)))?;

    fps.signature()
        .map(|fp| hex::encode(fp.as_bytes()))
        .ok_or_else(|| Error::Card(CardError::InvalidData(
            "No signing key fingerprint on card".to_string()
        )))
}

/// Check if the public params indicate a signing-capable key
fn can_sign(params: &PublicParams) -> bool {
    matches!(params,
        PublicParams::RSA(_) |
        PublicParams::DSA(_) |
        PublicParams::ECDSA(_) |
        PublicParams::EdDSALegacy(_) |
        PublicParams::Ed25519(_) |
        PublicParams::Ed448(_)
    )
}

/// Select appropriate hash algorithm based on key parameters.
fn select_hash_for_params(params: &PublicParams) -> HashAlgorithm {
    match params {
        PublicParams::ECDSA(ecdsa) => {
            use crate::pgp::types::EcdsaPublicParams;
            match ecdsa {
                EcdsaPublicParams::P256 { .. } => HashAlgorithm::Sha256,
                EcdsaPublicParams::P384 { .. } => HashAlgorithm::Sha384,
                EcdsaPublicParams::P521 { .. } => HashAlgorithm::Sha512,
                _ => HashAlgorithm::Sha256,
            }
        }
        PublicParams::EdDSALegacy(_) | PublicParams::Ed25519(_) => HashAlgorithm::Sha256,
        PublicParams::RSA(_) => HashAlgorithm::Sha256,
        _ => HashAlgorithm::Sha256,
    }
}

/// Create a signature using the smart card.
fn create_card_signature(
    data: &[u8],
    key_info: &SigningKeyInfo,
    pin: &[u8],
) -> Result<Signature> {
    // Create signature config
    let mut config = SignatureConfig::v4(
        SignatureType::Binary,
        key_info.algorithm,
        key_info.hash_alg,
    );

    // Add subpackets
    let now = Timestamp::now();
    config.hashed_subpackets.push(
        Subpacket::regular(SubpacketData::SignatureCreationTime(now))
            .map_err(|e| Error::Crypto(e.to_string()))?
    );

    // Add issuer fingerprint
    config.hashed_subpackets.push(
        Subpacket::regular(SubpacketData::IssuerFingerprint(key_info.fingerprint.clone()))
            .map_err(|e| Error::Crypto(e.to_string()))?
    );

    // Add issuer key ID
    config.unhashed_subpackets.push(
        Subpacket::regular(SubpacketData::IssuerKeyId(key_info.key_id))
            .map_err(|e| Error::Crypto(e.to_string()))?
    );

    // Compute the hash for the signature
    let hash_data = compute_signature_hash(data, &config, key_info.hash_alg)?;
    let signed_hash_value = [hash_data[0], hash_data[1]];

    // Sign on the card
    let raw_signature = sign_on_card(&hash_data, key_info.hash_alg, &key_info.public_params, pin)?;

    // Create the SignatureBytes from raw card output
    let signature_bytes = create_signature_bytes(&raw_signature, &key_info.public_params)?;

    // Build the signature
    Signature::from_config(config, signed_hash_value, signature_bytes)
        .map_err(|e| Error::Crypto(e.to_string()))
}

/// Compute the hash for the signature packet.
fn compute_signature_hash(
    data: &[u8],
    config: &SignatureConfig,
    hash_alg: HashAlgorithm,
) -> Result<Vec<u8>> {
    use digest::DynDigest;

    // Create hasher
    let mut hasher: Box<dyn DynDigest + Send> = hash_alg.new_hasher()
        .map_err(|e| Error::Crypto(e.to_string()))?;

    // Hash the data first
    config.hash_data_to_sign(&mut hasher, Cursor::new(data))
        .map_err(|e| Error::Crypto(e.to_string()))?;

    // Hash the signature packet metadata
    let sig_len = config.hash_signature_data(&mut hasher)
        .map_err(|e| Error::Crypto(e.to_string()))?;

    // Add trailer
    let trailer = config.trailer(sig_len)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    hasher.update(&trailer);

    Ok(hasher.finalize_reset().to_vec())
}

/// Sign a hash on the smart card using openpgp-card.
fn sign_on_card(
    hash: &[u8],
    hash_alg: HashAlgorithm,
    public_params: &PublicParams,
    pin: &[u8],
) -> Result<Vec<u8>> {
    let backend = get_card_backend()?;
    let mut card = Card::new(backend)
        .map_err(|e| Error::Card(CardError::from(e)))?;

    let mut tx = card.transaction()
        .map_err(|e| Error::Card(CardError::from(e)))?;

    // Verify PIN for signing
    let secret_pin = pin_to_secret(pin)?;
    tx.verify_user_signing_pin(secret_pin)
        .map_err(|e| Error::Card(CardError::from(e)))?;

    // Get low-level transaction for signing
    let low_tx = tx.card();

    // Convert hash to openpgp-card Hash type based on algorithm and key type
    let card_hash = match public_params {
        PublicParams::EdDSALegacy(_) | PublicParams::Ed25519(_) => {
            // EdDSA uses the raw hash data
            Hash::EdDSA(hash)
        }
        PublicParams::ECDSA(_) => {
            // ECDSA uses the raw hash data
            Hash::ECDSA(hash)
        }
        _ => {
            // RSA uses algorithm-specific hash type
            match hash_alg {
                HashAlgorithm::Sha256 => Hash::SHA256(hash.try_into().map_err(|_|
                    Error::Crypto("Invalid hash length for SHA256".to_string()))?),
                HashAlgorithm::Sha384 => Hash::SHA384(hash.try_into().map_err(|_|
                    Error::Crypto("Invalid hash length for SHA384".to_string()))?),
                HashAlgorithm::Sha512 => Hash::SHA512(hash.try_into().map_err(|_|
                    Error::Crypto("Invalid hash length for SHA512".to_string()))?),
                _ => return Err(Error::Crypto(format!("Unsupported hash algorithm: {:?}", hash_alg))),
            }
        }
    };

    // Perform the signature operation
    let signature = low_tx.signature_for_hash(card_hash)
        .map_err(|e| Error::Card(CardError::from(e)))?;

    Ok(signature)
}

/// Create SignatureBytes from raw card output.
fn create_signature_bytes(
    raw_sig: &[u8],
    public_params: &PublicParams,
) -> Result<SignatureBytes> {
    use bytes::Bytes;

    match public_params {
        PublicParams::RSA(_) => {
            // RSA signature is a single MPI
            let mpi = Mpi::from_slice(raw_sig);
            Ok(SignatureBytes::Mpis(vec![mpi]))
        }
        PublicParams::EdDSALegacy(_) => {
            // EdDSA Legacy: r and s are each 32 bytes (for Ed25519)
            if raw_sig.len() != 64 {
                return Err(Error::Crypto(format!(
                    "Invalid EdDSA signature length: {} (expected 64)",
                    raw_sig.len()
                )));
            }
            let r = Mpi::from_slice(&raw_sig[..32]);
            let s = Mpi::from_slice(&raw_sig[32..]);
            Ok(SignatureBytes::Mpis(vec![r, s]))
        }
        PublicParams::Ed25519(_) => {
            // Ed25519 native format (RFC 9580)
            Ok(SignatureBytes::Native(Bytes::copy_from_slice(raw_sig)))
        }
        PublicParams::ECDSA(_) => {
            // ECDSA: r and s MPIs
            let half = raw_sig.len() / 2;
            let r = Mpi::from_slice(&raw_sig[..half]);
            let s = Mpi::from_slice(&raw_sig[half..]);
            Ok(SignatureBytes::Mpis(vec![r, s]))
        }
        _ => Err(Error::Crypto(format!(
            "Unsupported algorithm: {:?}",
            public_params
        ))),
    }
}

/// Decrypt bytes using the encryption key on the smart card.
///
/// Decrypts OpenPGP encrypted data using the key stored in the encryption slot
/// of the connected smart card.
///
/// # Arguments
///
/// * `data` - The encrypted data (OpenPGP message)
/// * `public_cert` - The public certificate corresponding to the key on the card
/// * `pin` - The user PIN for the card
///
/// # Returns
///
/// The decrypted plaintext bytes.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::card::decrypt_bytes_on_card;
///
/// let public_key = std::fs::read("pubkey.asc").unwrap();
/// let encrypted = std::fs::read("secret.gpg").unwrap();
/// let plaintext = decrypt_bytes_on_card(
///     &encrypted,
///     &public_key,
///     b"123456",
/// ).unwrap();
/// ```
pub fn decrypt_bytes_on_card(data: &[u8], public_cert: &[u8], pin: &[u8]) -> Result<Vec<u8>> {
    let public_key = parse_public_key(public_cert)?;

    // Parse the encrypted message (try armored first, then binary)
    let message = match Message::from_armor(Cursor::new(data)) {
        Ok((msg, _headers)) => msg,
        Err(_) => Message::from_bytes(data)
            .map_err(|e| Error::Parse(e.to_string()))?,
    };

    // Extract the encrypted message with its ESK packets
    let (esk_packets, _edata) = match &message {
        Message::Encrypted { esk, edata, .. } => (esk.clone(), edata),
        _ => return Err(Error::Crypto("Message is not encrypted".to_string())),
    };

    // Find a matching PKESK for our encryption subkey
    let enc_key_info = get_encryption_key_info(&public_key)?;

    let mut session_key: Option<PlainSessionKey> = None;

    for esk in &esk_packets {
        if let Esk::PublicKeyEncryptedSessionKey(pkesk) = esk {
            // Check if this PKESK matches our encryption key
            if pkesk.match_identity(&enc_key_info) {
                // Extract encrypted values and decrypt on card
                let values = pkesk.values()
                    .map_err(|e| Error::Crypto(e.to_string()))?;

                let esk_type = match pkesk.version() {
                    PkeskVersion::V3 => EskType::V3_4,
                    PkeskVersion::V6 => EskType::V6,
                    _ => continue,
                };

                // Decrypt the session key on the card
                let decrypted = decrypt_session_key_on_card(
                    values,
                    &enc_key_info,
                    pin,
                    esk_type,
                )?;

                session_key = Some(decrypted);
                break;
            }
        }
    }

    let session_key = session_key
        .ok_or_else(|| Error::Crypto("No matching PKESK found for card key".to_string()))?;

    // Decrypt the message with the session key
    let decrypted = message.decrypt_with_session_key(session_key)
        .map_err(|e| Error::Crypto(e.to_string()))?;

    // Handle compression if present
    let mut decompressed = if decrypted.is_compressed() {
        decrypted.decompress()
            .map_err(|e| Error::Crypto(e.to_string()))?
    } else {
        decrypted
    };

    // Extract the plaintext data
    decompressed.as_data_vec()
        .map_err(|e| Error::Crypto(e.to_string()))
}

/// Encryption key info extracted from a public key
#[derive(Debug)]
struct EncryptionKeyInfo {
    public_params: PublicParams,
    fingerprint: Fingerprint,
    key_id: crate::pgp::types::KeyId,
}

impl KeyDetails for EncryptionKeyInfo {
    fn version(&self) -> crate::pgp::types::KeyVersion {
        self.fingerprint.version().unwrap_or(crate::pgp::types::KeyVersion::V4)
    }

    fn legacy_key_id(&self) -> crate::pgp::types::KeyId {
        self.key_id
    }

    fn fingerprint(&self) -> Fingerprint {
        self.fingerprint.clone()
    }

    fn algorithm(&self) -> crate::pgp::crypto::public_key::PublicKeyAlgorithm {
        match &self.public_params {
            PublicParams::RSA(_) => crate::pgp::crypto::public_key::PublicKeyAlgorithm::RSA,
            PublicParams::ECDH(_) => crate::pgp::crypto::public_key::PublicKeyAlgorithm::ECDH,
            PublicParams::X25519(_) => crate::pgp::crypto::public_key::PublicKeyAlgorithm::X25519,
            PublicParams::X448(_) => crate::pgp::crypto::public_key::PublicKeyAlgorithm::X448,
            _ => crate::pgp::crypto::public_key::PublicKeyAlgorithm::RSA,
        }
    }

    fn created_at(&self) -> Timestamp {
        Timestamp::now()
    }

    fn expiration(&self) -> Option<u16> {
        None
    }

    fn public_params(&self) -> &PublicParams {
        &self.public_params
    }
}

/// Get encryption key info from the public certificate.
fn get_encryption_key_info(public_key: &SignedPublicKey) -> Result<EncryptionKeyInfo> {
    // First try to find an encryption-capable subkey
    // Check both algorithm and key flags
    for subkey in &public_key.public_subkeys {
        let key = &subkey.key;
        // Check if algorithm supports encryption
        if !can_encrypt_algorithm(key.public_params()) {
            continue;
        }
        // Check if binding signature has encryption flags
        let has_encryption_flags = subkey.signatures.iter().any(|sig| {
            let flags = sig.key_flags();
            flags.encrypt_comms() || flags.encrypt_storage()
        });
        if has_encryption_flags {
            return Ok(EncryptionKeyInfo {
                public_params: key.public_params().clone(),
                fingerprint: key.fingerprint(),
                key_id: key.legacy_key_id(),
            });
        }
    }

    // Fall back to primary key if it can encrypt
    let primary = &public_key.primary_key;
    if can_encrypt_algorithm(primary.public_params()) {
        return Ok(EncryptionKeyInfo {
            public_params: primary.public_params().clone(),
            fingerprint: primary.fingerprint(),
            key_id: primary.legacy_key_id(),
        });
    }

    Err(Error::Crypto("No encryption-capable key found".to_string()))
}

/// Check if the algorithm supports encryption
fn can_encrypt_algorithm(params: &PublicParams) -> bool {
    matches!(params,
        PublicParams::RSA(_) |
        PublicParams::ECDH(_) |
        PublicParams::X25519(_) |
        PublicParams::X448(_)
    )
}

/// Decrypt session key using the card.
fn decrypt_session_key_on_card(
    values: &PkeskBytes,
    key_info: &EncryptionKeyInfo,
    pin: &[u8],
    esk_type: EskType,
) -> Result<PlainSessionKey> {
    let backend = get_card_backend()?;
    let mut card = Card::new(backend)
        .map_err(|e| Error::Card(CardError::from(e)))?;

    let mut tx = card.transaction()
        .map_err(|e| Error::Card(CardError::from(e)))?;

    // Verify PIN for decryption
    let secret_pin = pin_to_secret(pin)?;
    tx.verify_user_pin(secret_pin)
        .map_err(|e| Error::Card(CardError::from(e)))?;

    // Get low-level transaction for decryption
    let low_tx = tx.card();

    // Prepare data for card based on algorithm and decrypt
    let decrypted = match (values, &key_info.public_params) {
        (PkeskBytes::Rsa { mpi }, PublicParams::RSA(_)) => {
            // RSA decryption - get the raw bytes from MPI
            let ciphertext: &[u8] = mpi.as_ref();
            let cryptogram = Cryptogram::RSA(ciphertext);
            low_tx.decipher(cryptogram)
                .map_err(|e| Error::Card(CardError::from(e)))?
        }
        (PkeskBytes::Ecdh { public_point, encrypted_session_key }, PublicParams::ECDH(ecdh_params)) => {
            // ECDH decryption - card returns the shared secret
            let point_bytes: &[u8] = public_point.as_ref();

            // For CV25519, the point may have a 0x40 prefix that needs to be stripped
            // The card expects raw 32-byte public key for X25519/CV25519
            let card_point = if is_cv25519_key(ecdh_params) {
                strip_cv25519_prefix(point_bytes)?
            } else {
                point_bytes
            };

            let cryptogram = Cryptogram::ECDH(card_point);
            let shared_secret = low_tx.decipher(cryptogram)
                .map_err(|e| Error::Card(CardError::from(e)))?;

            // Unwrap the session key using the shared secret
            ecdh_unwrap_session_key(&shared_secret, encrypted_session_key.as_ref(), ecdh_params, &key_info.fingerprint)?
        }
        (PkeskBytes::X25519 { ephemeral, session_key, .. }, PublicParams::X25519(_)) => {
            // X25519 native format
            let cryptogram = Cryptogram::ECDH(ephemeral.as_ref());
            let shared_secret = low_tx.decipher(cryptogram)
                .map_err(|e| Error::Card(CardError::from(e)))?;

            x25519_unwrap_session_key(&shared_secret, session_key.as_ref())?
        }
        (PkeskBytes::Ecdh { public_point, encrypted_session_key }, PublicParams::X25519(_)) => {
            // Legacy PKESK with X25519 key
            let point_bytes: &[u8] = public_point.as_ref();
            let card_point = strip_cv25519_prefix(point_bytes)?;

            let cryptogram = Cryptogram::ECDH(card_point);
            let shared_secret = low_tx.decipher(cryptogram)
                .map_err(|e| Error::Card(CardError::from(e)))?;

            x25519_unwrap_session_key(&shared_secret, encrypted_session_key.as_ref())?
        }
        _ => return Err(Error::Crypto("Mismatched PKESK values and key params".to_string())),
    };

    // Build the PlainSessionKey from decrypted data
    // Format for V3/V4: sym_algo (1 byte) + session_key + checksum (2 bytes)
    // Format for V6: session_key + checksum (2 bytes)
    match esk_type {
        EskType::V3_4 => {
            if decrypted.is_empty() {
                return Err(Error::Crypto("Empty decryption result".to_string()));
            }
            let sym_alg = SymmetricKeyAlgorithm::from(decrypted[0]);
            if sym_alg == SymmetricKeyAlgorithm::Plaintext {
                return Err(Error::Crypto("Session key algorithm cannot be plaintext".to_string()));
            }

            let key_size = sym_alg.key_size();
            // Decrypted should be: 1 byte algo + key_size bytes key + 2 bytes checksum
            if decrypted.len() != key_size + 3 {
                return Err(Error::Crypto(format!(
                    "Unexpected decrypted key length ({}) for sym_alg {:?}",
                    decrypted.len(), sym_alg
                )));
            }

            // Extract just the session key (skip algo byte, exclude checksum)
            let key = RawSessionKey::from(&decrypted[1..=key_size]);

            Ok(PlainSessionKey::V3_4 {
                sym_alg,
                key,
            })
        }
        EskType::V6 => {
            if decrypted.len() < 2 {
                return Err(Error::Crypto(format!(
                    "Unexpected decrypted key length ({}) for V6 ESK",
                    decrypted.len()
                )));
            }
            // V6: session_key + 2-byte checksum
            let len = decrypted.len();
            let key = RawSessionKey::from(&decrypted[0..len - 2]);
            Ok(PlainSessionKey::V6 { key })
        }
    }
}

/// Check if ECDH params indicate a CV25519 key (legacy Curve25519)
fn is_cv25519_key(params: &crate::pgp::types::EcdhPublicParams) -> bool {
    use crate::pgp::types::EcdhPublicParams;
    matches!(params, EcdhPublicParams::Curve25519 { .. })
}

/// Strip the 0x40 prefix from CV25519 public points
fn strip_cv25519_prefix(point: &[u8]) -> Result<&[u8]> {
    if point.len() == 33 && point[0] == 0x40 {
        Ok(&point[1..])
    } else if point.len() == 32 {
        Ok(point)
    } else {
        Err(Error::Crypto(format!(
            "Invalid CV25519 point length: {} (expected 32 or 33)",
            point.len()
        )))
    }
}

/// ECDH unwrap the session key using the shared secret from the card.
/// Implements RFC 6637/9580 KDF for OpenPGP ECDH.
fn ecdh_unwrap_session_key(
    shared_secret: &[u8],
    encrypted_session_key: &[u8],
    ecdh_params: &crate::pgp::types::EcdhPublicParams,
    fingerprint: &Fingerprint,
) -> Result<Vec<u8>> {
    use crate::pgp::crypto::ecdh::derive_session_key;
    use crate::pgp::types::EcdhPublicParams;
    use crate::pgp::crypto::hash::HashAlgorithm;
    use crate::pgp::crypto::sym::SymmetricKeyAlgorithm;

    // Get the KDF parameters based on the curve type
    let (hash_algo, sym_algo): (HashAlgorithm, SymmetricKeyAlgorithm) = match ecdh_params {
        EcdhPublicParams::Curve25519 { hash, alg_sym, .. } => (*hash, *alg_sym),
        EcdhPublicParams::P256 { hash, alg_sym, .. } => (*hash, *alg_sym),
        EcdhPublicParams::P384 { hash, alg_sym, .. } => (*hash, *alg_sym),
        EcdhPublicParams::P521 { hash, alg_sym, .. } => (*hash, *alg_sym),
        EcdhPublicParams::Brainpool256 { hash, alg_sym, .. } => (*hash, *alg_sym),
        EcdhPublicParams::Brainpool384 { hash, alg_sym, .. } => (*hash, *alg_sym),
        EcdhPublicParams::Brainpool512 { hash, alg_sym, .. } => (*hash, *alg_sym),
        EcdhPublicParams::Unsupported { curve, .. } => {
            return Err(Error::Crypto(format!("Unsupported ECDH curve: {:?}", curve)));
        }
    };

    let curve = ecdh_params.curve();

    // Use rpgp's derive_session_key which handles KDF and AES key unwrap correctly
    derive_session_key(
        shared_secret,
        encrypted_session_key,
        encrypted_session_key.len(),
        curve,
        hash_algo,
        sym_algo,
        fingerprint.as_bytes(),
    ).map_err(|e| Error::Crypto(e.to_string()))
}

/// X25519 native format session key unwrap (RFC 9580)
fn x25519_unwrap_session_key(
    shared_secret: &[u8],
    encrypted_session_key: &[u8],
) -> Result<Vec<u8>> {
    use aes_kw::Kek;
    use aes::Aes256;
    use hkdf::Hkdf;
    use sha2::Sha256;

    // RFC 9580 X25519 uses HKDF-SHA256
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
    let mut kek = [0u8; 32];
    hkdf.expand(b"OpenPGP X25519", &mut kek)
        .map_err(|e| Error::Crypto(format!("HKDF failed: {:?}", e)))?;

    let kek_key = Kek::<Aes256>::try_from(kek.as_slice())
        .map_err(|e| Error::Crypto(format!("Invalid KEK: {:?}", e)))?;

    let unwrapped = kek_key.unwrap_vec(encrypted_session_key)
        .map_err(|e| Error::Crypto(format!("AES unwrap failed: {:?}", e)))?;

    Ok(unwrapped)
}

/// A signing key wrapper that delegates signing to the smart card.
///
/// This allows using the card's primary key for certification operations
/// through the standard SigningKey trait.
struct CardSigningKey<'a> {
    /// Public key parameters
    public_params: PublicParams,
    /// Key fingerprint
    fingerprint: Fingerprint,
    /// Key ID
    key_id: crate::pgp::types::KeyId,
    /// Key algorithm
    algorithm: crate::pgp::crypto::public_key::PublicKeyAlgorithm,
    /// Key version
    version: crate::pgp::types::KeyVersion,
    /// Creation timestamp
    created_at: Timestamp,
    /// Hash algorithm to use
    hash_alg: HashAlgorithm,
    /// PIN for card operations
    pin: &'a [u8],
}

impl std::fmt::Debug for CardSigningKey<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CardSigningKey")
            .field("fingerprint", &hex::encode(self.fingerprint.as_bytes()))
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

impl crate::pgp::types::KeyDetails for CardSigningKey<'_> {
    fn version(&self) -> crate::pgp::types::KeyVersion {
        self.version
    }

    fn legacy_key_id(&self) -> crate::pgp::types::KeyId {
        self.key_id
    }

    fn fingerprint(&self) -> Fingerprint {
        self.fingerprint.clone()
    }

    fn algorithm(&self) -> crate::pgp::crypto::public_key::PublicKeyAlgorithm {
        self.algorithm
    }

    fn created_at(&self) -> Timestamp {
        self.created_at
    }

    fn expiration(&self) -> Option<u16> {
        None
    }

    fn public_params(&self) -> &PublicParams {
        &self.public_params
    }
}

impl crate::pgp::types::SigningKey for CardSigningKey<'_> {
    fn sign(
        &self,
        _key_pw: &crate::pgp::types::Password,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> crate::pgp::errors::Result<crate::pgp::types::SignatureBytes> {
        // Sign on the card instead of using software key
        let raw_signature = sign_on_card(data, hash, &self.public_params, self.pin)
            .map_err(|e| -> String { e.to_string() })?;

        create_signature_bytes(&raw_signature, &self.public_params)
            .map_err(|e| -> crate::pgp::errors::Error { e.to_string().into() })
    }

    fn hash_alg(&self) -> HashAlgorithm {
        self.hash_alg
    }
}

/// Get primary key info for card signing operations.
///
/// This retrieves the primary key from the certificate and verifies it matches
/// the card's signing slot fingerprint.
fn get_primary_key_for_card_signing<'a>(
    public_key: &'a SignedPublicKey,
    pin: &'a [u8],
) -> Result<CardSigningKey<'a>> {
    // Get the fingerprint of the key in the card's signature slot
    let card_fp = get_card_signing_fingerprint()?;

    let primary = &public_key.primary_key;
    let primary_fp = hex::encode(primary.fingerprint().as_bytes());

    // Verify the primary key matches what's on the card
    if primary_fp != card_fp {
        return Err(Error::Crypto(format!(
            "Primary key fingerprint {} does not match card signing slot {}",
            primary_fp, card_fp
        )));
    }

    let params = primary.public_params();
    let hash_alg = select_hash_for_params(params);

    Ok(CardSigningKey {
        public_params: params.clone(),
        fingerprint: primary.fingerprint(),
        key_id: primary.legacy_key_id(),
        algorithm: primary.algorithm(),
        version: primary.version(),
        created_at: primary.created_at(),
        hash_alg,
        pin,
    })
}

/// Update the primary key expiration time using the smart card.
///
/// Updates all signatures that contain key expiration information, signing
/// with the primary key stored on the card's signature slot.
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
/// new expiration date. The function preserves all other subpackets from
/// the original signatures (preferred algorithms, features, key flags, etc.)
/// and only updates the signature creation time and key expiration time.
///
/// # Arguments
///
/// * `certdata` - The public certificate data (armored or binary)
/// * `expirytime` - Expiration time as seconds from now
/// * `pin` - The user PIN for the card
///
/// # Returns
///
/// The updated public certificate with new expiration signatures (armored).
///
/// # Errors
///
/// Returns an error if:
/// - No smart card is connected
/// - The primary key fingerprint doesn't match the card's signature slot
/// - PIN verification fails
/// - The certificate has no self-certification signatures
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::card::update_primary_expiry_on_card;
///
/// let public_key = std::fs::read("pubkey.asc").unwrap();
///
/// // Set expiry to 1 year from now (in seconds)
/// let one_year = 365 * 24 * 60 * 60;
/// let updated = update_primary_expiry_on_card(&public_key, one_year, b"123456").unwrap();
///
/// std::fs::write("updated_key.pub", &updated).unwrap();
/// ```
pub fn update_primary_expiry_on_card(
    certdata: &[u8],
    expirytime: u64,
    pin: &[u8],
) -> Result<Vec<u8>> {
    use crate::pgp::types::{Duration as PgpDuration, Tag, KeyDetails};

    let public_key = parse_public_key(certdata)?;
    let card_signer = get_primary_key_for_card_signing(&public_key, pin)?;

    // Calculate the expiry duration from key creation
    let key_creation = public_key.primary_key.created_at();
    let now_ts = Timestamp::now();

    // Calculate seconds from key creation to (now + expirytime)
    let creation_secs: u64 = key_creation.as_secs() as u64;
    let now_secs: u64 = now_ts.as_secs() as u64;
    let expiry_secs = now_secs.saturating_sub(creation_secs) + expirytime;
    let expiry_duration = PgpDuration::from_secs(expiry_secs as u32);

    let password = crate::pgp::types::Password::from("");  // Not used for card signing

    // Helper closure to update subpackets in a signature
    let update_subpackets = |existing_config: &SignatureConfig| -> Result<(Vec<Subpacket>, Vec<Subpacket>)> {
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

        Ok((new_hashed_subpackets, new_unhashed_subpackets))
    };

    // Update direct key signatures (sigclass 0x1f) - these also contain key expiration
    let mut new_direct_signatures: Vec<crate::pgp::packet::Signature> = Vec::new();
    for existing_sig in &public_key.details.direct_signatures {
        // Only update direct key signatures (0x1f), not revocations
        if existing_sig.typ() == Some(SignatureType::Key) {
            let existing_config = existing_sig
                .config()
                .ok_or_else(|| Error::Crypto("Cannot read existing direct signature config".to_string()))?;

            let (new_hashed, new_unhashed) = update_subpackets(existing_config)?;

            let mut config = SignatureConfig::v4(
                SignatureType::Key,
                card_signer.algorithm(),
                card_signer.hash_alg,
            );
            config.hashed_subpackets = new_hashed;
            config.unhashed_subpackets = new_unhashed;

            // Sign the primary key directly
            let sig = config
                .sign_key(&card_signer, &password, &public_key.primary_key)
                .map_err(|e| Error::Crypto(e.to_string()))?;

            new_direct_signatures.push(sig);
        } else {
            // Keep revocation signatures unchanged
            new_direct_signatures.push(existing_sig.clone());
        }
    }

    // Update self-certification signatures for each user ID
    let mut new_users: Vec<crate::pgp::types::SignedUser> = Vec::new();

    for signed_user in &public_key.details.users {
        let existing_self_sig = signed_user
            .signatures
            .iter()
            .find(|sig| sig.is_certification())
            .ok_or_else(|| Error::Crypto("No self-certification signature found".to_string()))?;

        let existing_config = existing_self_sig
            .config()
            .ok_or_else(|| Error::Crypto("Cannot read existing signature config".to_string()))?;

        let (new_hashed, new_unhashed) = update_subpackets(existing_config)?;

        let mut config = SignatureConfig::v4(
            existing_config.typ(),
            card_signer.algorithm(),
            card_signer.hash_alg,
        );
        config.hashed_subpackets = new_hashed;
        config.unhashed_subpackets = new_unhashed;

        let sig = config
            .sign_certification_third_party(
                &card_signer,
                &password,
                &public_key.primary_key,
                Tag::UserId,
                &signed_user.id,
            )
            .map_err(|e| Error::Crypto(e.to_string()))?;

        let mut combined_sigs = vec![sig];
        for existing_sig in &signed_user.signatures {
            if !existing_sig.is_certification() {
                combined_sigs.push(existing_sig.clone());
            }
        }

        new_users.push(crate::pgp::types::SignedUser::new(signed_user.id.clone(), combined_sigs));
    }

    // Rebuild the public key with new signatures
    let updated_key = SignedPublicKey {
        primary_key: public_key.primary_key.clone(),
        details: crate::pgp::composed::SignedKeyDetails::new(
            public_key.details.revocation_signatures.clone(),
            new_direct_signatures,
            new_users,
            public_key.details.user_attributes.clone(),
        ),
        public_subkeys: public_key.public_subkeys.clone(),
    };

    // Serialize to armored format
    let armored = crate::internal::public_key_to_armored(&updated_key)?;
    Ok(armored.into_bytes())
}

/// Update the expiration time for specific subkeys using the smart card.
///
/// Creates new subkey binding signatures (signature type 0x18) for the
/// specified subkeys with the updated expiration time, signing with the
/// primary key stored on the card's signature slot.
///
/// # Signature Details
///
/// Subkey binding signatures are created by the primary key to bind a subkey
/// to the certificate and define its properties (capabilities, expiration).
/// This function updates these signatures while preserving all other subpackets:
///
/// - **Key flags** - Preserved to maintain subkey capabilities (encrypt, sign, etc.)
/// - **Preferred algorithms** - Preserved for compatibility
/// - **Embedded signatures** - For signing subkeys, the embedded primary key
///   binding signature is preserved (required for signing-capable subkeys)
/// - **Other subpackets** - All other metadata is preserved unchanged
///
/// Only the signature creation time and key expiration time are updated.
///
/// # Fingerprint Matching
///
/// Fingerprints are matched case-insensitively. Partial fingerprint matches
/// are supported (useful for matching by short key ID), but providing full
/// 40-character fingerprints is recommended for accuracy.
///
/// # Arguments
///
/// * `certdata` - The public certificate data (armored or binary)
/// * `fingerprints` - Fingerprints of subkeys to update (hex strings)
/// * `expirytime` - Expiration time as seconds from now
/// * `pin` - The user PIN for the card
///
/// # Returns
///
/// The updated public certificate with new binding signatures (armored).
///
/// # Errors
///
/// Returns an error if:
/// - No smart card is connected
/// - The primary key fingerprint doesn't match the card's signature slot
/// - PIN verification fails
/// - A specified subkey has no binding signature to update
/// - A specified subkey fingerprint is not found in the certificate
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::card::update_subkeys_expiry_on_card;
///
/// let public_key = std::fs::read("pubkey.asc").unwrap();
/// let subkey_fps = vec!["ABCD1234...", "EFGH5678..."];
///
/// // Set expiry to 6 months from now (in seconds)
/// let six_months = 180 * 24 * 60 * 60;
/// let updated = update_subkeys_expiry_on_card(
///     &public_key,
///     &subkey_fps,
///     six_months,
///     b"123456",
/// ).unwrap();
/// ```
pub fn update_subkeys_expiry_on_card(
    certdata: &[u8],
    fingerprints: &[&str],
    expirytime: u64,
    pin: &[u8],
) -> Result<Vec<u8>> {
    use crate::pgp::types::{Duration as PgpDuration, KeyDetails};

    let public_key = parse_public_key(certdata)?;
    let card_signer = get_primary_key_for_card_signing(&public_key, pin)?;

    let password = crate::pgp::types::Password::from("");  // Not used for card signing

    // Normalize fingerprints for comparison (uppercase, no spaces)
    let normalized_fps: Vec<String> = fingerprints
        .iter()
        .map(|fp| fp.to_uppercase().replace(" ", ""))
        .collect();

    let now_ts = Timestamp::now();
    let now_secs: u64 = now_ts.as_secs() as u64;

    // Update public subkeys
    let mut new_public_subkeys = Vec::new();
    for subkey in &public_key.public_subkeys {
        let subkey_fp = hex::encode(subkey.key.fingerprint().as_bytes()).to_uppercase();
        let should_update = normalized_fps.iter().any(|fp| subkey_fp.contains(fp) || fp.contains(&subkey_fp));

        if should_update {
            // Calculate duration from subkey creation to (now + expirytime)
            let creation_secs: u64 = subkey.key.created_at().as_secs() as u64;
            let expiry_secs = now_secs.saturating_sub(creation_secs) + expirytime;
            let expiry_duration = PgpDuration::from_secs(expiry_secs as u32);

            // Find the existing binding signature to clone
            let existing_binding_sig = subkey
                .signatures
                .iter()
                .find(|sig| sig.typ() == Some(SignatureType::SubkeyBinding))
                .ok_or_else(|| Error::Crypto("No binding signature found for subkey".to_string()))?;

            let existing_config = existing_binding_sig
                .config()
                .ok_or_else(|| Error::Crypto("Cannot read existing binding signature config".to_string()))?;

            // Clone the existing hashed subpackets, updating only the ones we need to change
            let mut new_hashed_subpackets: Vec<Subpacket> = Vec::new();
            let mut has_creation_time = false;
            let mut has_expiry_time = false;

            for subpacket in existing_config.hashed_subpackets() {
                match &subpacket.data {
                    SubpacketData::SignatureCreationTime(_) => {
                        // Replace with new creation time
                        new_hashed_subpackets.push(
                            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))
                                .map_err(|e| Error::Crypto(e.to_string()))?,
                        );
                        has_creation_time = true;
                    }
                    SubpacketData::KeyExpirationTime(_) => {
                        // Replace with new expiry time
                        new_hashed_subpackets.push(
                            Subpacket::regular(SubpacketData::KeyExpirationTime(expiry_duration))
                                .map_err(|e| Error::Crypto(e.to_string()))?,
                        );
                        has_expiry_time = true;
                    }
                    _ => {
                        // Keep all other subpackets unchanged (including embedded signatures)
                        new_hashed_subpackets.push(subpacket.clone());
                    }
                }
            }

            // Add creation time if not present in original
            if !has_creation_time {
                new_hashed_subpackets.push(
                    Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))
                        .map_err(|e| Error::Crypto(e.to_string()))?,
                );
            }

            // Add expiry time if not present in original
            if !has_expiry_time {
                new_hashed_subpackets.push(
                    Subpacket::regular(SubpacketData::KeyExpirationTime(expiry_duration))
                        .map_err(|e| Error::Crypto(e.to_string()))?,
                );
            }

            // Clone unhashed subpackets as-is
            let new_unhashed_subpackets: Vec<Subpacket> = existing_config
                .unhashed_subpackets()
                .cloned()
                .collect();

            // Create the signature config based on the existing signature
            let mut config = SignatureConfig::v4(
                SignatureType::SubkeyBinding,
                card_signer.algorithm(),
                card_signer.hash_alg,
            );
            config.hashed_subpackets = new_hashed_subpackets;
            config.unhashed_subpackets = new_unhashed_subpackets;

            let sig = config
                .sign_subkey_binding(
                    &card_signer,
                    &public_key.primary_key,
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

    // Rebuild the public key with updated subkeys
    let updated_key = SignedPublicKey {
        primary_key: public_key.primary_key.clone(),
        details: public_key.details.clone(),
        public_subkeys: new_public_subkeys,
    };

    // Serialize to armored format
    let armored = crate::internal::public_key_to_armored(&updated_key)?;
    Ok(armored.into_bytes())
}

#[cfg(test)]
mod tests {
    // Tests require a virtual card or physical YubiKey
    // Run with: cargo test --features card -- --ignored
}
