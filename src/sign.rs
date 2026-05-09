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
use pgp::types::{KeyDetails, Password, PublicParams};
use rand::thread_rng;

use crate::error::{Error, Result};
use crate::internal::{
    can_details_sign, is_key_expired, is_secret_subkey_revoked, parse_secret_key,
    validate_secret_signing_usage, SigningKeyUsage,
};

/// Select appropriate hash algorithm based on public key params.
/// ECDSA keys require hash algorithms that match or exceed their security level.
pub(crate) fn select_hash_for_params(params: &PublicParams) -> HashAlgorithm {
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
///
/// When multiple signing subkeys are valid, the most recently created one is
/// preferred (e.g. after key rotation the newest subkey should be used).
pub(crate) fn find_signing_subkey(secret_key: &SignedSecretKey) -> Option<&SignedSecretSubKey> {
    let mut best: Option<&SignedSecretSubKey> = None;

    for subkey in &secret_key.secret_subkeys {
        let has_sign_flag = subkey.signatures.iter().any(|sig| sig.key_flags().sign());
        if !has_sign_flag {
            continue;
        }

        if is_secret_subkey_revoked(secret_key.primary_key.public_key(), subkey) {
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

        // Prefer the most recently created signing subkey
        let dominated = match best {
            Some(prev) => subkey.key.created_at() > prev.key.created_at(),
            None => true,
        };
        if dominated {
            best = Some(subkey);
        }
    }
    best
}

/// Verify that a passphrase unlocks the primary secret key without
/// performing a sign or decrypt round-trip.
///
/// The S2K KDF and the secret-key-packet decryption do run as part of
/// `unlock` — those are the cheapest crypto bits and are exactly what
/// proves the passphrase correct. What this function explicitly skips
/// is producing a signature or decrypting message data with the
/// unlocked key.
///
/// Useful for daemons (tumpa-cli agent, Tumpa Mail XPC service) that
/// just received a freshly-typed passphrase from a pinentry frontend
/// and want to validate it before broadcasting it as cached.
///
/// Implementation: parses the secret key bytes, then calls
/// `pgp::SignedSecretKey::primary_key.unlock(password, |_, _| Ok(()))`.
/// The closure returns immediately, so we exercise only the
/// passphrase-driven secret-packet decrypt step.
///
/// # Errors
///
/// * `Error::Parse` - secret key bytes do not parse.
/// * `Error::Crypto` - the passphrase did not unlock the secret-key
///   packet (wrong passphrase, or a corrupted key).
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{create_key_simple, verify_software_passphrase};
///
/// let key = create_key_simple("password", &["Alice <a@example.com>"]).unwrap();
/// assert!(verify_software_passphrase(&key.secret_key, "password").is_ok());
/// assert!(verify_software_passphrase(&key.secret_key, "wrong").is_err());
/// ```
pub fn verify_software_passphrase(secret_key: &[u8], password: &str) -> Result<()> {
    let secret_key = parse_secret_key(secret_key)?;
    let password_obj: Password = password.into();
    let unlock_err = |e: pgp::errors::Error| Error::Crypto(format!("primary-key unlock failed: {e}"));
    secret_key
        .primary_key
        .unlock(&password_obj, |_pub_params, _plain| Ok(()))
        .map_err(unlock_err)?
        .map_err(unlock_err)?;
    Ok(())
}

/// Sign bytes with a binary signature (wrapping the message).
///
/// Creates an OpenPGP signed message that includes both the signature and
/// the original data. The recipient can verify and extract the original message.
///
/// # Arguments
/// * `secret_key` - The signer's secret key (armored or binary)
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
pub fn sign_bytes(secret_key: &[u8], data: &[u8], password: &str) -> Result<Vec<u8>> {
    sign_bytes_internal(secret_key, data, password, false, false)
}

/// Sign bytes with a binary signature, forcing use of the primary key.
///
/// Like [`sign_bytes`], but always uses the primary key for signing even when
/// a signing subkey is available. Useful when you need the signature to come
/// from the primary key specifically (e.g., for certification-level trust).
///
/// # Arguments
/// * `secret_key` - The signer's secret key (armored or binary)
/// * `data` - The data to sign
/// * `password` - Password to unlock the secret key
pub fn sign_bytes_with_primary_key(
    secret_key: &[u8],
    data: &[u8],
    password: &str,
) -> Result<Vec<u8>> {
    sign_bytes_internal(secret_key, data, password, false, true)
}

/// Sign bytes with a cleartext signature.
///
/// Creates a cleartext signed message where the original text remains
/// human-readable with the signature appended. Useful for email and text files.
///
/// # Arguments
/// * `secret_key` - The signer's secret key (armored or binary)
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
pub fn sign_bytes_cleartext(secret_key: &[u8], data: &[u8], password: &str) -> Result<Vec<u8>> {
    sign_bytes_internal(secret_key, data, password, true, false)
}

/// Sign bytes with a cleartext signature, forcing use of the primary key.
///
/// Like [`sign_bytes_cleartext`], but always uses the primary key for signing.
///
/// # Arguments
/// * `secret_key` - The signer's secret key (armored or binary)
/// * `data` - The data to sign (should be text)
/// * `password` - Password to unlock the secret key
pub fn sign_bytes_cleartext_with_primary_key(
    secret_key: &[u8],
    data: &[u8],
    password: &str,
) -> Result<Vec<u8>> {
    sign_bytes_internal(secret_key, data, password, true, true)
}

/// Create a detached signature for bytes.
///
/// Creates a signature that is separate from the original data. The recipient
/// needs both the signature and the original file to verify.
///
/// # Arguments
/// * `secret_key` - The signer's secret key (armored or binary)
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
pub fn sign_bytes_detached(secret_key: &[u8], data: &[u8], password: &str) -> Result<String> {
    sign_bytes_detached_impl(secret_key, data, password, false, None).map(|out| out.armored)
}

/// Create a detached signature for bytes, forcing use of the primary key.
///
/// Like [`sign_bytes_detached`], but always uses the primary key for signing
/// even when a signing subkey is available.
///
/// # Arguments
/// * `secret_key` - The signer's secret key (armored or binary)
/// * `data` - The data to sign
/// * `password` - Password to unlock the secret key
pub fn sign_bytes_detached_with_primary_key(
    secret_key: &[u8],
    data: &[u8],
    password: &str,
) -> Result<String> {
    sign_bytes_detached_impl(secret_key, data, password, true, None).map(|out| out.armored)
}

/// Output of [`sign_bytes_detached_with_hash`]: the armored signature plus
/// the hash algorithm that was actually used.
///
/// Callers building PGP/MIME `multipart/signed` parts need the hash to fill
/// the `micalg` parameter (e.g. `pgp-sha256`); rather than re-parsing the
/// signature packet, we surface it directly here.
#[derive(Debug, Clone)]
pub struct DetachedSignOutput {
    pub armored: String,
    pub hash_algorithm: HashAlgorithm,
}

/// Create a detached signature for bytes, optionally pinning the hash
/// algorithm.
///
/// Behaves like [`sign_bytes_detached`] when `hash_algo` is `None` (the
/// hash is derived from the signing key's public params per
/// [`select_hash_for_params`]). When `hash_algo` is `Some(algo)`, that
/// algorithm is used regardless. The chosen algorithm is returned in the
/// output so the caller can echo it onto a status line or into a
/// `multipart/signed` `micalg` parameter.
///
/// rpgp may reject combinations the underlying public-key algorithm
/// disallows (e.g. an unsupported hash for an Ed448 key); those surface
/// as [`Error::Crypto`].
pub fn sign_bytes_detached_with_hash(
    secret_key: &[u8],
    data: &[u8],
    password: &str,
    hash_algo: Option<HashAlgorithm>,
) -> Result<DetachedSignOutput> {
    if let Some(h) = hash_algo {
        crate::crypto_policy::current().hash_algorithm(h)?;
    }
    sign_bytes_detached_impl(secret_key, data, password, false, hash_algo)
}

/// Log the data buffer the software-sign path is about to hash. Mirror of
/// the card-path diagnostic; enable with
/// `RUST_LOG=wecanencrypt::sign=debug`.
fn log_software_sign_diag(site: &str, data: &[u8], use_primary: bool) {
    if !log::log_enabled!(target: "wecanencrypt::sign", log::Level::Debug) {
        return;
    }
    use sha2::{Digest, Sha256};
    let data_sha256 = Sha256::digest(data);
    let head = &data[..data.len().min(48)];
    let tail = if data.len() > 48 {
        &data[data.len().saturating_sub(48)..]
    } else {
        &[][..]
    };
    log::debug!(
        target: "wecanencrypt::sign",
        "{site}: use_primary={up} data_len={dl} data_sha256={ds} \
         data_head_hex={head} data_tail_hex={tail}",
        up = use_primary,
        dl = data.len(),
        ds = hex::encode(data_sha256),
        head = hex::encode(head),
        tail = hex::encode(tail),
    );
}

/// Internal implementation for detached signatures.
///
/// `hash_override`: when `Some`, that hash algorithm is used for the
/// signature; when `None`, the algorithm is derived from the signing key's
/// public params via [`select_hash_for_params`].
fn sign_bytes_detached_impl(
    secret_key: &[u8],
    data: &[u8],
    password: &str,
    use_primary: bool,
    hash_override: Option<HashAlgorithm>,
) -> Result<DetachedSignOutput> {
    log_software_sign_diag("sign_bytes_detached_impl", data, use_primary);
    let secret_key = parse_secret_key(secret_key)?;
    validate_secret_signing_usage(&secret_key, SigningKeyUsage::DataSignature)?;
    let password: Password = password.into();

    let mut rng = thread_rng();

    // Prefer a signing subkey if available; fall back to primary key
    let (signature, hash_used) = if !use_primary {
        if let Some(subkey) = find_signing_subkey(&secret_key) {
            let hash_alg =
                hash_override.unwrap_or_else(|| select_hash_for_params(subkey.key.public_params()));
            crate::crypto_policy::current().hash_algorithm(hash_alg)?;
            let sig = DetachedSignature::sign_binary_data(
                &mut rng,
                &subkey.key,
                &password,
                hash_alg,
                Cursor::new(data),
            )
            .map_err(|e| Error::Crypto(e.to_string()))?;
            (sig, hash_alg)
        } else if can_details_sign(&secret_key.details) {
            let hash_alg = hash_override
                .unwrap_or_else(|| select_hash_for_params(secret_key.primary_key.public_params()));
            crate::crypto_policy::current().hash_algorithm(hash_alg)?;
            let sig = DetachedSignature::sign_binary_data(
                &mut rng,
                &secret_key.primary_key,
                &password,
                hash_alg,
                Cursor::new(data),
            )
            .map_err(|e| Error::Crypto(e.to_string()))?;
            (sig, hash_alg)
        } else {
            return Err(Error::NoSigningSubkey);
        }
    } else {
        let hash_alg = hash_override
            .unwrap_or_else(|| select_hash_for_params(secret_key.primary_key.public_params()));
        crate::crypto_policy::current().hash_algorithm(hash_alg)?;
        let sig = DetachedSignature::sign_binary_data(
            &mut rng,
            &secret_key.primary_key,
            &password,
            hash_alg,
            Cursor::new(data),
        )
        .map_err(|e| Error::Crypto(e.to_string()))?;
        (sig, hash_alg)
    };

    let armored = signature
        .to_armored_string(None.into())
        .map_err(|e| Error::Crypto(e.to_string()))?;
    Ok(DetachedSignOutput {
        armored,
        hash_algorithm: hash_used,
    })
}

/// Sign a file to an output file (binary signature).
///
/// Reads the input file, signs it, and writes the signed message to the output file.
///
/// # Arguments
/// * `secret_key` - The signer's secret key (armored or binary)
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
    secret_key: &[u8],
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    password: &str,
) -> Result<()> {
    let data = std::fs::read(input.as_ref())?;
    let signed = sign_bytes(secret_key, &data, password)?;
    std::fs::write(output.as_ref(), signed)?;
    Ok(())
}

/// Sign a file with cleartext signature.
///
/// # Arguments
/// * `secret_key` - The signer's secret key
/// * `input` - Path to the file to sign (should be text)
/// * `output` - Path to write the signed file
/// * `password` - Password to unlock the secret key
pub fn sign_file_cleartext(
    secret_key: &[u8],
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    password: &str,
) -> Result<()> {
    let data = std::fs::read(input.as_ref())?;
    let signed = sign_bytes_cleartext(secret_key, &data, password)?;
    std::fs::write(output.as_ref(), signed)?;
    Ok(())
}

/// Create a detached signature for a file.
///
/// # Arguments
/// * `secret_key` - The signer's secret key
/// * `input` - Path to the file to sign
/// * `password` - Password to unlock the secret key
///
/// # Returns
/// The ASCII-armored detached signature.
pub fn sign_file_detached(
    secret_key: &[u8],
    input: impl AsRef<Path>,
    password: &str,
) -> Result<String> {
    let data = std::fs::read(input.as_ref())?;
    sign_bytes_detached(secret_key, &data, password)
}

/// Internal implementation for signing with or without cleartext.
fn sign_bytes_internal(
    secret_key: &[u8],
    data: &[u8],
    password: &str,
    cleartext: bool,
    use_primary: bool,
) -> Result<Vec<u8>> {
    let secret_key = parse_secret_key(secret_key)?;
    validate_secret_signing_usage(&secret_key, SigningKeyUsage::DataSignature)?;
    let password_obj: Password = password.into();

    let mut rng = thread_rng();

    // Determine which key to use: signing subkey (preferred) or primary key.
    // When not explicitly using the primary, check that the primary has the
    // signing capability flag before falling back to it.
    let signing_subkey = if !use_primary {
        find_signing_subkey(&secret_key)
    } else {
        None
    };
    let use_subkey = signing_subkey.is_some();

    if !use_subkey && !use_primary && !can_details_sign(&secret_key.details) {
        return Err(Error::NoSigningSubkey);
    }

    if cleartext {
        let text = String::from_utf8_lossy(data);
        let csf = if let Some(subkey) = signing_subkey {
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

        if let Some(subkey) = signing_subkey {
            let hash_alg = select_hash_for_params(subkey.key.public_params());
            crate::crypto_policy::current().hash_algorithm(hash_alg)?;
            builder.sign(&subkey.key, password_obj, hash_alg);
        } else {
            let hash_alg = select_hash_for_params(secret_key.primary_key.public_params());
            crate::crypto_policy::current().hash_algorithm(hash_alg)?;
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
    use super::*;
    use crate::create_key_simple;

    #[test]
    fn verify_software_passphrase_accepts_correct() {
        let key = create_key_simple("pw", &["Alice <a@example.com>"]).unwrap();
        verify_software_passphrase(&key.secret_key, "pw").unwrap();
    }

    #[test]
    fn verify_software_passphrase_rejects_wrong() {
        let key = create_key_simple("pw", &["Alice <a@example.com>"]).unwrap();
        let err = verify_software_passphrase(&key.secret_key, "WRONG").unwrap_err();
        match err {
            Error::Crypto(_) => (),
            other => panic!("expected Error::Crypto, got {:?}", other),
        }
    }

    #[test]
    fn verify_software_passphrase_rejects_garbage_key() {
        // Random bytes that don't parse as an OpenPGP key should fail
        // at the parse step, not at the unlock step.
        let err = verify_software_passphrase(b"not an openpgp key", "anything").unwrap_err();
        match err {
            Error::Parse(_) => (),
            other => panic!("expected Error::Parse, got {:?}", other),
        }
    }

    /// `sign_bytes_detached_with_hash(_, _, _, None)` matches the auto-
    /// selected algorithm for an Ed25519 key (SHA256).
    #[test]
    fn sign_with_hash_default_is_sha256_for_ed25519() {
        let key = create_key_simple("pw", &["Alice <a@example.com>"]).unwrap();
        let out = sign_bytes_detached_with_hash(&key.secret_key, b"hello", "pw", None).unwrap();
        assert_eq!(out.hash_algorithm, HashAlgorithm::Sha256);
        assert!(out.armored.contains("BEGIN PGP SIGNATURE"));
    }

    /// Explicit override is honored and reflected in the output struct.
    #[test]
    fn sign_with_hash_override_sha512() {
        let key = create_key_simple("pw", &["Alice <a@example.com>"]).unwrap();
        let out = sign_bytes_detached_with_hash(
            &key.secret_key,
            b"hello",
            "pw",
            Some(HashAlgorithm::Sha512),
        )
        .unwrap();
        assert_eq!(out.hash_algorithm, HashAlgorithm::Sha512);

        // Resulting signature must still verify.
        let valid = crate::verify_bytes_detached(
            key.public_key.as_bytes(),
            b"hello",
            out.armored.as_bytes(),
        )
        .unwrap();
        assert!(valid, "overridden-hash signature must verify");
    }

    /// CRLF input must be signed verbatim (no normalization). PGP/MIME
    /// `multipart/signed` requires the signed part to be CRLF-canonical
    /// before hashing; libtumpa's contract is "we sign exactly the bytes
    /// you hand us." Regression guard so future refactors don't slip in
    /// a normalize-to-LF.
    #[test]
    fn detached_sign_does_not_normalize_crlf() {
        let key = create_key_simple("pw", &["Alice <a@example.com>"]).unwrap();
        let crlf = b"line one\r\nline two\r\n";

        let out =
            sign_bytes_detached_with_hash(&key.secret_key, crlf, "pw", Some(HashAlgorithm::Sha256))
                .unwrap();

        // Verify against the EXACT CRLF bytes — succeeds only if the
        // signer hashed the CRLF form, not an LF-normalized version.
        let valid =
            crate::verify_bytes_detached(key.public_key.as_bytes(), crlf, out.armored.as_bytes())
                .unwrap();
        assert!(
            valid,
            "CRLF-signed signature must verify against CRLF input"
        );

        // Negative side: same signature against the LF-normalized input
        // must NOT verify. Confirms we're really signing CRLF, not LF.
        let lf = b"line one\nline two\n";
        let still_valid =
            crate::verify_bytes_detached(key.public_key.as_bytes(), lf, out.armored.as_bytes())
                .unwrap();
        assert!(
            !still_valid,
            "signature over CRLF must NOT verify against LF (would mean signer normalized line endings)"
        );
    }
}
