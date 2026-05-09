//! Internal helper functions.

use std::io::Cursor;

use pgp::composed::{Deserializable, SignedPublicKey, SignedSecretKey};
use pgp::ser::Serialize;
use pgp::types::KeyDetails;

use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Parse a secret key from bytes (armored or binary).
pub(crate) fn parse_secret_key(data: &[u8]) -> Result<SignedSecretKey> {
    // Try armored first, then binary
    let cursor = Cursor::new(data);
    let key = match SignedSecretKey::from_armor_single(cursor) {
        Ok((key, _headers)) => key,
        Err(_) => {
            let cursor = Cursor::new(data);
            SignedSecretKey::from_bytes(cursor).map_err(|e| Error::Parse(e.to_string()))?
        }
    };
    crate::crypto_policy::check_certificate(&key.to_public_key())?;
    Ok(key)
}

/// Parse a public key from bytes (armored or binary).
/// Also handles secret key data by extracting the public key.
pub(crate) fn parse_public_key(data: &[u8]) -> Result<SignedPublicKey> {
    // Try armored public key first
    let cursor = Cursor::new(data);
    if let Ok((key, _headers)) = SignedPublicKey::from_armor_single(cursor) {
        crate::crypto_policy::check_certificate(&key)?;
        return Ok(key);
    }

    // Try binary public key
    let cursor = Cursor::new(data);
    if let Ok(key) = SignedPublicKey::from_bytes(cursor) {
        crate::crypto_policy::check_certificate(&key)?;
        return Ok(key);
    }

    // Maybe it's a secret key - try to extract public key from it
    // (parse_secret_key already runs the policy check.)
    if let Ok(secret_key) = parse_secret_key(data) {
        return Ok(secret_key.to_public_key());
    }

    Err(Error::Parse("no matching packet found".to_string()))
}

/// Parse an OpenPGP key from bytes — tries secret key first, then public.
/// Returns (public_key, is_secret).
pub(crate) fn parse_key(data: &[u8]) -> Result<(SignedPublicKey, bool)> {
    // Try as secret key first
    if let Ok(secret_key) = parse_secret_key(data) {
        let public_key = secret_key.to_public_key();
        return Ok((public_key, true));
    }

    // Try as public key
    let public_key = parse_public_key(data)?;
    Ok((public_key, false))
}

/// Serialize a secret key to binary format.
///
/// Returns `Zeroizing<Vec<u8>>` so the secret key material is securely
/// erased from memory when the value is dropped.
pub(crate) fn secret_key_to_bytes(key: &SignedSecretKey) -> Result<Zeroizing<Vec<u8>>> {
    key.to_bytes()
        .map(Zeroizing::new)
        .map_err(|e| Error::Crypto(e.to_string()))
}

/// Serialize a public key to ASCII-armored format.
pub(crate) fn public_key_to_armored(key: &SignedPublicKey) -> Result<String> {
    key.to_armored_string(None.into())
        .map_err(|e| Error::Crypto(e.to_string()))
}

/// Get the fingerprint as a hex string (uppercase, no spaces).
pub(crate) fn fingerprint_to_hex(key: &impl KeyDetails) -> String {
    hex::encode_upper(key.fingerprint().as_bytes())
}

/// Get the key ID as a hex string.
pub(crate) fn keyid_to_hex(key: &impl KeyDetails) -> String {
    hex::encode_upper(key.legacy_key_id().as_ref())
}

/// Convert a SystemTime to chrono DateTime.
pub(crate) fn system_time_to_datetime(st: std::time::SystemTime) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from(st)
}

/// Get a normalized algorithm name for display.
/// Converts rpgp's internal naming to common OpenPGP names.
pub(crate) fn get_algorithm_name(key: &impl KeyDetails) -> String {
    use pgp::crypto::public_key::PublicKeyAlgorithm;

    match key.algorithm() {
        PublicKeyAlgorithm::RSA => "RSA".to_string(),
        PublicKeyAlgorithm::RSAEncrypt => "RSA".to_string(),
        PublicKeyAlgorithm::RSASign => "RSA".to_string(),
        PublicKeyAlgorithm::EdDSALegacy | PublicKeyAlgorithm::Ed25519 => "EdDSA".to_string(),
        PublicKeyAlgorithm::ECDH => "ECDH".to_string(),
        PublicKeyAlgorithm::ECDSA => "ECDSA".to_string(),
        PublicKeyAlgorithm::X25519 => "X25519".to_string(),
        PublicKeyAlgorithm::X448 => "X448".to_string(),
        PublicKeyAlgorithm::Ed448 => "Ed448".to_string(),
        PublicKeyAlgorithm::DSA => "DSA".to_string(),
        PublicKeyAlgorithm::Elgamal => "Elgamal".to_string(),
        algo => format!("{:?}", algo),
    }
}

/// Classify an OpenPGP key into a [`crate::types::KeyAlgorithm`], looking
/// into `PublicParams` so that ECDH/Curve25519 is distinguished from
/// ECDH/NIST and `EdDSALegacy` from `Ed25519`.
pub(crate) fn classify_key_algorithm(key: &impl KeyDetails) -> crate::types::KeyAlgorithm {
    use crate::types::KeyAlgorithm;
    use pgp::crypto::public_key::PublicKeyAlgorithm;
    use pgp::types::{EcdhPublicParams, PublicParams};

    match key.algorithm() {
        PublicKeyAlgorithm::RSA | PublicKeyAlgorithm::RSAEncrypt | PublicKeyAlgorithm::RSASign => {
            KeyAlgorithm::Rsa
        }
        PublicKeyAlgorithm::DSA => KeyAlgorithm::Dsa,
        PublicKeyAlgorithm::Elgamal => KeyAlgorithm::Elgamal,
        PublicKeyAlgorithm::EdDSALegacy => KeyAlgorithm::EdDsaLegacy,
        PublicKeyAlgorithm::Ed25519 => KeyAlgorithm::Ed25519,
        PublicKeyAlgorithm::Ed448 => KeyAlgorithm::Ed448,
        PublicKeyAlgorithm::X25519 => KeyAlgorithm::X25519,
        PublicKeyAlgorithm::X448 => KeyAlgorithm::X448,
        PublicKeyAlgorithm::ECDSA => KeyAlgorithm::Ecdsa,
        PublicKeyAlgorithm::ECDH => match key.public_params() {
            PublicParams::ECDH(EcdhPublicParams::Curve25519 { .. }) => KeyAlgorithm::EcdhCurve25519,
            PublicParams::ECDH(EcdhPublicParams::P256 { .. })
            | PublicParams::ECDH(EcdhPublicParams::P384 { .. })
            | PublicParams::ECDH(EcdhPublicParams::P521 { .. }) => KeyAlgorithm::EcdhNist,
            PublicParams::ECDH(EcdhPublicParams::Brainpool256 { .. })
            | PublicParams::ECDH(EcdhPublicParams::Brainpool384 { .. })
            | PublicParams::ECDH(EcdhPublicParams::Brainpool512 { .. }) => {
                KeyAlgorithm::EcdhBrainpool
            }
            _ => KeyAlgorithm::Unknown,
        },
        _ => KeyAlgorithm::Unknown,
    }
}

/// Get the bit size for a key based on its algorithm and parameters.
/// Returns 0 if the bit size cannot be determined.
pub(crate) fn get_key_bit_size(key: &impl KeyDetails) -> usize {
    use pgp::crypto::public_key::PublicKeyAlgorithm;

    match key.algorithm() {
        PublicKeyAlgorithm::RSA | PublicKeyAlgorithm::RSAEncrypt | PublicKeyAlgorithm::RSASign => {
            // Extract actual RSA modulus bit length from the public parameters
            match key.public_params() {
                pgp::types::PublicParams::RSA(ref rsa) => {
                    use rsa::traits::PublicKeyParts;
                    rsa.key.n().bits()
                }
                _ => 0,
            }
        }
        PublicKeyAlgorithm::EdDSALegacy | PublicKeyAlgorithm::Ed25519 => 256,
        PublicKeyAlgorithm::X25519 => 256,
        PublicKeyAlgorithm::X448 => 448,
        PublicKeyAlgorithm::Ed448 => 448,
        PublicKeyAlgorithm::ECDH => {
            // Could be 256 (Curve25519) or other sizes
            256
        }
        PublicKeyAlgorithm::ECDSA => 256,
        PublicKeyAlgorithm::DSA => 2048,
        PublicKeyAlgorithm::Elgamal => 2048,
        _ => 0,
    }
}
