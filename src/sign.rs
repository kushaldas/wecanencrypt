//! Signing functions.
//!
//! This module provides functions for creating OpenPGP signatures
//! on data using secret key material.

use std::io::Cursor;
use std::path::Path;

use pgp::composed::{
    CleartextSignedMessage, DetachedSignature, MessageBuilder, SignedSecretKey, SignedSecretSubKey,
};
use pgp::crypto::hash::HashAlgorithm;
use pgp::packet::SignatureType;
use pgp::types::{KeyDetails, Password, PublicParams};
use rand::thread_rng;

use crate::error::{Error, Result};
use crate::internal::{is_key_expired, parse_secret_key, validate_signing_usage, SigningKeyUsage};

/// Select appropriate hash algorithm based on public key params.
/// ECDSA keys require hash algorithms that match or exceed their security level.
fn select_hash_for_params(params: &PublicParams) -> HashAlgorithm {
    match params {
        PublicParams::ECDSA(ecdsa) => {
            // Match hash size to curve size
            use pgp::types::EcdsaPublicParams;
            match ecdsa {
                EcdsaPublicParams::P256 { .. } => HashAlgorithm::Sha256,
                EcdsaPublicParams::P384 { .. } => HashAlgorithm::Sha384,
                EcdsaPublicParams::P521 { .. } => HashAlgorithm::Sha512,
                _ => HashAlgorithm::Sha256,
            }
        }
        PublicParams::EdDSALegacy(_) | PublicParams::Ed25519(_) => HashAlgorithm::Sha256,
        PublicParams::Ed448(_) => HashAlgorithm::Sha512,
        PublicParams::RSA(_) => HashAlgorithm::Sha256,
        _ => HashAlgorithm::Sha256,
    }
}

/// Find the best signing subkey: valid, non-revoked, non-expired, with sign flag.
fn find_signing_subkey(secret_key: &SignedSecretKey) -> Option<&SignedSecretSubKey> {
    for subkey in &secret_key.secret_subkeys {
        let has_sign_flag = subkey.signatures.iter().any(|sig| sig.key_flags().sign());
        if !has_sign_flag {
            continue;
        }

        let is_revoked = subkey
            .signatures
            .iter()
            .any(|sig| sig.typ() == Some(SignatureType::SubkeyRevocation));
        if is_revoked {
            continue;
        }

        // Check expiration using the most recent binding signature
        let most_recent_sig = subkey
            .signatures
            .iter()
            .filter(|sig| sig.key_expiration_time().is_some())
            .max_by_key(|sig| sig.created().map(|t| t.as_secs()).unwrap_or(0));
        if let Some(sig) = most_recent_sig {
            if let Some(validity) = sig.key_expiration_time() {
                let creation_time: std::time::SystemTime = subkey.key.created_at().into();
                if is_key_expired(creation_time, Some(validity.as_secs() as u64)) {
                    continue;
                }
            }
        }

        return Some(subkey);
    }
    None
}

/// Sign bytes with a binary signature (wrapping the message).
///
/// Creates an OpenPGP signed message that includes both the signature and
/// the original data. The recipient can verify and extract the original message.
///
/// # Arguments
/// * `secret_cert` - The signer's secret key (armored or binary)
/// * `data` - The data to sign
/// * `password` - Password to unlock the secret key
///
/// # Returns
/// The signed message containing both the signature and the original data.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{create_key_simple, sign_bytes, verify_bytes, get_pub_key};
///
/// let key = create_key_simple("password", &["Alice <alice@example.com>"]).unwrap();
/// let public_key = get_pub_key(&key.secret_key).unwrap();
///
/// // Sign a message
/// let signed = sign_bytes(&key.secret_key, b"Important message", "password").unwrap();
///
/// // Verify it
/// let valid = verify_bytes(public_key.as_bytes(), &signed).unwrap();
/// assert!(valid);
/// ```
pub fn sign_bytes(secret_cert: &[u8], data: &[u8], password: &str) -> Result<Vec<u8>> {
    sign_bytes_internal(secret_cert, data, password, false, false)
}

/// Sign bytes with a binary signature, forcing use of the primary key.
///
/// Like [`sign_bytes`], but always uses the primary key for signing even when
/// a signing subkey is available. Useful when you need the signature to come
/// from the primary key specifically (e.g., for certification-level trust).
///
/// # Arguments
/// * `secret_cert` - The signer's secret key (armored or binary)
/// * `data` - The data to sign
/// * `password` - Password to unlock the secret key
pub fn sign_bytes_with_primary_key(
    secret_cert: &[u8],
    data: &[u8],
    password: &str,
) -> Result<Vec<u8>> {
    sign_bytes_internal(secret_cert, data, password, false, true)
}

/// Sign bytes with a cleartext signature.
///
/// Creates a cleartext signed message where the original text remains
/// human-readable with the signature appended. Useful for email and text files.
///
/// # Arguments
/// * `secret_cert` - The signer's secret key (armored or binary)
/// * `data` - The data to sign (should be text)
/// * `password` - Password to unlock the secret key
///
/// # Returns
/// The cleartext signed message (text remains visible).
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{create_key_simple, sign_bytes_cleartext};
///
/// let key = create_key_simple("password", &["Alice <alice@example.com>"]).unwrap();
///
/// let signed = sign_bytes_cleartext(&key.secret_key, b"Hello, World!", "password").unwrap();
/// // The output looks like:
/// // -----BEGIN PGP SIGNED MESSAGE-----
/// // Hash: SHA256
/// //
/// // Hello, World!
/// // -----BEGIN PGP SIGNATURE-----
/// // ...
/// // -----END PGP SIGNATURE-----
/// ```
pub fn sign_bytes_cleartext(secret_cert: &[u8], data: &[u8], password: &str) -> Result<Vec<u8>> {
    sign_bytes_internal(secret_cert, data, password, true, false)
}

/// Sign bytes with a cleartext signature, forcing use of the primary key.
///
/// Like [`sign_bytes_cleartext`], but always uses the primary key for signing.
///
/// # Arguments
/// * `secret_cert` - The signer's secret key (armored or binary)
/// * `data` - The data to sign (should be text)
/// * `password` - Password to unlock the secret key
pub fn sign_bytes_cleartext_with_primary_key(
    secret_cert: &[u8],
    data: &[u8],
    password: &str,
) -> Result<Vec<u8>> {
    sign_bytes_internal(secret_cert, data, password, true, true)
}

/// Create a detached signature for bytes.
///
/// Creates a signature that is separate from the original data. The recipient
/// needs both the signature and the original file to verify.
///
/// # Arguments
/// * `secret_cert` - The signer's secret key (armored or binary)
/// * `data` - The data to sign
/// * `password` - Password to unlock the secret key
///
/// # Returns
/// The ASCII-armored detached signature.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{create_key_simple, sign_bytes_detached, verify_bytes_detached, get_pub_key};
///
/// let key = create_key_simple("password", &["Alice <alice@example.com>"]).unwrap();
/// let public_key = get_pub_key(&key.secret_key).unwrap();
///
/// let data = b"File contents";
/// let signature = sign_bytes_detached(&key.secret_key, data, "password").unwrap();
///
/// // Verify with the original data and signature
/// let valid = verify_bytes_detached(public_key.as_bytes(), data, signature.as_bytes()).unwrap();
/// assert!(valid);
/// ```
pub fn sign_bytes_detached(secret_cert: &[u8], data: &[u8], password: &str) -> Result<String> {
    sign_bytes_detached_impl(secret_cert, data, password, false)
}

/// Create a detached signature for bytes, forcing use of the primary key.
///
/// Like [`sign_bytes_detached`], but always uses the primary key for signing
/// even when a signing subkey is available.
///
/// # Arguments
/// * `secret_cert` - The signer's secret key (armored or binary)
/// * `data` - The data to sign
/// * `password` - Password to unlock the secret key
pub fn sign_bytes_detached_with_primary_key(
    secret_cert: &[u8],
    data: &[u8],
    password: &str,
) -> Result<String> {
    sign_bytes_detached_impl(secret_cert, data, password, true)
}

/// Internal implementation for detached signatures.
fn sign_bytes_detached_impl(
    secret_cert: &[u8],
    data: &[u8],
    password: &str,
    use_primary: bool,
) -> Result<String> {
    let secret_key = parse_secret_key(secret_cert)?;
    validate_signing_usage(
        secret_key.primary_key.created_at().into(),
        &secret_key.details,
        SigningKeyUsage::DataSignature,
    )?;
    let password: Password = password.into();

    let mut rng = thread_rng();

    // Prefer a signing subkey if available; fall back to primary key
    let signature = if !use_primary {
        if let Some(subkey) = find_signing_subkey(&secret_key) {
            let hash_alg = select_hash_for_params(subkey.key.public_params());
            DetachedSignature::sign_binary_data(
                &mut rng,
                &subkey.key,
                &password,
                hash_alg,
                Cursor::new(data),
            )
            .map_err(|e| Error::Crypto(e.to_string()))?
        } else {
            let hash_alg = select_hash_for_params(secret_key.primary_key.public_params());
            DetachedSignature::sign_binary_data(
                &mut rng,
                &secret_key.primary_key,
                &password,
                hash_alg,
                Cursor::new(data),
            )
            .map_err(|e| Error::Crypto(e.to_string()))?
        }
    } else {
        let hash_alg = select_hash_for_params(secret_key.primary_key.public_params());
        DetachedSignature::sign_binary_data(
            &mut rng,
            &secret_key.primary_key,
            &password,
            hash_alg,
            Cursor::new(data),
        )
        .map_err(|e| Error::Crypto(e.to_string()))?
    };

    signature
        .to_armored_string(None.into())
        .map_err(|e| Error::Crypto(e.to_string()))
}

/// Sign a file to an output file (binary signature).
///
/// Reads the input file, signs it, and writes the signed message to the output file.
///
/// # Arguments
/// * `secret_cert` - The signer's secret key (armored or binary)
/// * `input` - Path to the file to sign
/// * `output` - Path to write the signed file
/// * `password` - Password to unlock the secret key
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::sign_file;
///
/// let secret_key = std::fs::read("secret.asc").unwrap();
/// sign_file(&secret_key, "document.pdf", "document.pdf.sig", "password").unwrap();
/// ```
pub fn sign_file(
    secret_cert: &[u8],
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    password: &str,
) -> Result<()> {
    let data = std::fs::read(input.as_ref())?;
    let signed = sign_bytes(secret_cert, &data, password)?;
    std::fs::write(output.as_ref(), signed)?;
    Ok(())
}

/// Sign a file with cleartext signature.
///
/// # Arguments
/// * `secret_cert` - The signer's secret key
/// * `input` - Path to the file to sign (should be text)
/// * `output` - Path to write the signed file
/// * `password` - Password to unlock the secret key
pub fn sign_file_cleartext(
    secret_cert: &[u8],
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    password: &str,
) -> Result<()> {
    let data = std::fs::read(input.as_ref())?;
    let signed = sign_bytes_cleartext(secret_cert, &data, password)?;
    std::fs::write(output.as_ref(), signed)?;
    Ok(())
}

/// Create a detached signature for a file.
///
/// # Arguments
/// * `secret_cert` - The signer's secret key
/// * `input` - Path to the file to sign
/// * `password` - Password to unlock the secret key
///
/// # Returns
/// The ASCII-armored detached signature.
pub fn sign_file_detached(
    secret_cert: &[u8],
    input: impl AsRef<Path>,
    password: &str,
) -> Result<String> {
    let data = std::fs::read(input.as_ref())?;
    sign_bytes_detached(secret_cert, &data, password)
}

/// Internal implementation for signing with or without cleartext.
fn sign_bytes_internal(
    secret_cert: &[u8],
    data: &[u8],
    password: &str,
    cleartext: bool,
    use_primary: bool,
) -> Result<Vec<u8>> {
    let secret_key = parse_secret_key(secret_cert)?;
    validate_signing_usage(
        secret_key.primary_key.created_at().into(),
        &secret_key.details,
        SigningKeyUsage::DataSignature,
    )?;
    let password_obj: Password = password.into();

    let mut rng = thread_rng();

    // Determine which key to use: signing subkey (preferred) or primary key
    let use_subkey = !use_primary && find_signing_subkey(&secret_key).is_some();

    if cleartext {
        let text = String::from_utf8_lossy(data);
        let csf = if use_subkey {
            let subkey = find_signing_subkey(&secret_key).unwrap();
            CleartextSignedMessage::sign(&mut rng, &text, &subkey.key, &password_obj)
                .map_err(|e| Error::Crypto(e.to_string()))?
        } else {
            CleartextSignedMessage::sign(&mut rng, &text, &secret_key.primary_key, &password_obj)
                .map_err(|e| Error::Crypto(e.to_string()))?
        };

        csf.to_armored_string(None.into())
            .map(|s| s.into_bytes())
            .map_err(|e| Error::Crypto(e.to_string()))
    } else {
        let mut builder = MessageBuilder::from_bytes("", data.to_vec());

        if use_subkey {
            let subkey = find_signing_subkey(&secret_key).unwrap();
            let hash_alg = select_hash_for_params(subkey.key.public_params());
            builder.sign(&subkey.key, password_obj, hash_alg);
        } else {
            let hash_alg = select_hash_for_params(secret_key.primary_key.public_params());
            builder.sign(&secret_key.primary_key, password_obj, hash_alg);
        };

        builder
            .to_armored_string(&mut rng, None.into())
            .map(|s| s.into_bytes())
            .map_err(|e| Error::Crypto(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    // Tests would require key fixtures
}
