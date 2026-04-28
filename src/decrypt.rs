//! Decryption functions.
//!
//! This module provides functions for decrypting OpenPGP encrypted messages
//! using secret key material.

use std::io::{Cursor, Read};
use std::path::Path;

use pgp::composed::{Deserializable, Message, SignedPublicKey, SignedSecretKey};
use pgp::types::{KeyDetails, Password};

use crate::error::{Error, Result};
use crate::internal::parse_secret_key;

/// Decrypt bytes using a secret key.
///
/// Decrypts an OpenPGP encrypted message using the recipient's secret key.
/// The message must have been encrypted to this key.
///
/// Only decrypts integrity-protected messages (SEIPDv1 with MDC, SEIPDv2 with AEAD).
/// Legacy SED packets (no integrity protection) are rejected by default.
/// Use [`decrypt_bytes_legacy`] to opt into decrypting legacy messages.
///
/// # Arguments
/// * `secret_key` - The recipient's secret key (armored or binary)
/// * `ciphertext` - The encrypted data (armored or binary)
/// * `password` - Password to unlock the secret key
///
/// # Returns
/// The decrypted plaintext bytes.
///
/// # Errors
/// * [`Error::InvalidPassword`] - If the password is incorrect
/// * [`Error::Crypto`] - If the message wasn't encrypted to this key
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{create_key_simple, encrypt_bytes, decrypt_bytes, get_pub_key};
///
/// let key = create_key_simple("password", &["Alice <alice@example.com>"]).unwrap();
/// let public_key = get_pub_key(&key.secret_key).unwrap();
///
/// // Encrypt
/// let ciphertext = encrypt_bytes(public_key.as_bytes(), b"Hello!", true).unwrap();
///
/// // Decrypt
/// let plaintext = decrypt_bytes(&key.secret_key, &ciphertext, "password").unwrap();
/// assert_eq!(plaintext, b"Hello!");
/// ```
pub fn decrypt_bytes(secret_key: &[u8], ciphertext: &[u8], password: &str) -> Result<Vec<u8>> {
    let secret_key = parse_secret_key(secret_key)?;
    decrypt_with_key(&secret_key, ciphertext, password, false)
}

/// Decrypt bytes, allowing legacy SED (no integrity protection) messages.
///
/// **WARNING**: Legacy SED packets (packet type 9) have no integrity protection.
/// An attacker can modify the ciphertext without detection. Only use this for
/// historical data encrypted before 2007 that cannot be re-encrypted.
///
/// # Arguments
/// * `secret_key` - The recipient's secret key (armored or binary)
/// * `ciphertext` - The encrypted data (armored or binary)
/// * `password` - Password to unlock the secret key
///
/// # Returns
/// The decrypted plaintext bytes.
pub fn decrypt_bytes_legacy(
    secret_key: &[u8],
    ciphertext: &[u8],
    password: &str,
) -> Result<Vec<u8>> {
    let secret_key = parse_secret_key(secret_key)?;
    decrypt_with_key(&secret_key, ciphertext, password, true)
}

/// Decrypt bytes using an already-parsed secret key.
///
/// # Arguments
/// * `secret_key` - The parsed secret key
/// * `ciphertext` - The encrypted data
/// * `password` - Password to unlock the secret key
/// * `allow_legacy` - If true, allows decryption of legacy SED packets (no integrity protection)
///
/// # Returns
/// The decrypted plaintext.
pub fn decrypt_with_key(
    secret_key: &SignedSecretKey,
    ciphertext: &[u8],
    password: &str,
    allow_legacy: bool,
) -> Result<Vec<u8>> {
    let password: Password = password.into();

    // Parse the encrypted message (try armored first, then binary)
    let message = match Message::from_armor(Cursor::new(ciphertext)) {
        Ok((msg, _headers)) => msg,
        Err(_) => Message::from_bytes(ciphertext).map_err(|e| Error::Parse(e.to_string()))?,
    };

    // Try standard decrypt first (integrity-protected: SEIPDv1/MDC or SEIPDv2/AEAD).
    // Return a uniform error to avoid leaking which phase failed (oracle prevention).
    let decrypted = message
        .decrypt(&password, secret_key)
        .or_else(|_| {
            if !allow_legacy {
                return Err(Error::Crypto("Decryption failed".to_string()));
            }
            // Legacy fallback: allows SED packets (no integrity protection).
            let msg = match Message::from_armor(Cursor::new(ciphertext)) {
                Ok((m, _headers)) => m,
                Err(_) => {
                    Message::from_bytes(ciphertext).map_err(|e| Error::Parse(e.to_string()))?
                }
            };
            msg.decrypt_legacy(&password, secret_key)
                .map_err(|e| Error::Crypto(e.to_string()))
        })
        .map_err(|_| Error::Crypto("Decryption failed".to_string()))?;

    // Handle compression if present
    let mut decompressed = if decrypted.is_compressed() {
        decrypted
            .decompress()
            .map_err(|e| Error::Crypto(e.to_string()))?
    } else {
        decrypted
    };

    // Extract the plaintext data
    decompressed
        .as_data_vec()
        .map_err(|e| Error::Crypto(e.to_string()))
}

/// Outcome of [`decrypt_and_verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecryptVerifySignature {
    /// Ciphertext contained no inner OpenPGP signature (encrypt-only).
    Unsigned,
    /// Inner signature(s) present and at least one verified against a key
    /// returned by `resolve_signer`. The fingerprint is the 40-char
    /// uppercase hex of the verifying key (subkey fingerprint when the
    /// signature was made by a subkey, else primary).
    Good { verifier_fingerprint: String },
    /// Inner signature(s) present, signer(s) resolved by the caller, but
    /// none verified.
    Bad,
    /// Inner signature(s) present, but no signer was resolvable via
    /// `resolve_signer`. Returns the issuer ids (uppercase hex
    /// fingerprints / 16-char key IDs) so the caller can report them.
    UnknownKey { issuer_ids: Vec<String> },
}

/// Result of [`decrypt_and_verify`].
#[derive(Debug)]
pub struct DecryptVerifyResult {
    /// Decrypted plaintext.
    pub plaintext: Vec<u8>,
    /// Whether and how the inner OpenPGP signature was checked.
    pub signature: DecryptVerifySignature,
}

/// Decrypt `ciphertext` and, if the encrypted payload was sign-then-encrypt,
/// verify the inner signature against a signer key the caller supplies via
/// `resolve_signer`.
///
/// `resolve_signer` is invoked once per inner signature with the issuer
/// identifiers extracted from that signature (uppercase hex; both 40-char
/// fingerprints and 16-char key IDs may appear in the slice). Return
/// `Some(cert_bytes)` (armored or binary OpenPGP public key, or a secret
/// key — only the public material is used) for a candidate signer, or
/// `None` if the issuer is unknown.
///
/// PGP/MIME `multipart/encrypted` messages from clients that sign-then-
/// encrypt (Thunderbird, ProtonMail, etc.) all hit the `Good`/`Bad` arms;
/// encrypt-only messages return `Unsigned`.
///
/// The caller is responsible for checking that the resolved signer key is
/// not revoked or expired *before* trusting the `Good` outcome — this
/// function only checks the cryptographic signature, not key validity.
///
/// Only integrity-protected messages (SEIPDv1 with MDC, SEIPDv2 with
/// AEAD) are decrypted; legacy SED packets are rejected, matching
/// [`decrypt_bytes`].
pub fn decrypt_and_verify<F>(
    secret_key: &[u8],
    ciphertext: &[u8],
    password: &str,
    mut resolve_signer: F,
) -> Result<DecryptVerifyResult>
where
    F: FnMut(&[String]) -> Option<Vec<u8>>,
{
    let secret_key = parse_secret_key(secret_key)?;
    let password: Password = password.into();

    // Parse the encrypted message (try armored first, then binary).
    let message = match Message::from_armor(Cursor::new(ciphertext)) {
        Ok((msg, _headers)) => msg,
        Err(_) => Message::from_bytes(ciphertext).map_err(|e| Error::Parse(e.to_string()))?,
    };

    // Standard decrypt. Uniform "Decryption failed" matches `decrypt_bytes`
    // to avoid leaking which phase failed.
    let decrypted = message
        .decrypt(&password, &secret_key)
        .map_err(|_| Error::Crypto("Decryption failed".to_string()))?;

    let mut decompressed = if decrypted.is_compressed() {
        decrypted
            .decompress()
            .map_err(|e| Error::Crypto(e.to_string()))?
    } else {
        decrypted
    };

    // Drain the message. This populates the internal hash state needed by
    // Message::verify on a signed-then-encrypted payload.
    let plaintext = decompressed
        .as_data_vec()
        .map_err(|e| Error::Crypto(e.to_string()))?;

    let signature = inspect_inner_signatures(&decompressed, &mut resolve_signer)?;

    Ok(DecryptVerifyResult {
        plaintext,
        signature,
    })
}

/// After a signed-then-encrypted message has been drained, inspect its
/// inner signature(s) and verify against caller-supplied signer keys.
///
/// Crate-public so the card path (`card::decrypt_and_verify_on_card`) can
/// reuse the exact same signer-resolution and `Good`/`Bad`/`UnknownKey`
/// classification after on-card session-key decryption.
pub(crate) fn inspect_inner_signatures<F>(
    message: &Message<'_>,
    resolve_signer: &mut F,
) -> Result<DecryptVerifySignature>
where
    F: FnMut(&[String]) -> Option<Vec<u8>>,
{
    let reader = match message {
        Message::Signed { reader, .. } => reader,
        // Literal-only or other shapes mean encrypt-only — no inner sig.
        _ => return Ok(DecryptVerifySignature::Unsigned),
    };

    let n = reader.num_signatures();
    if n == 0 {
        return Ok(DecryptVerifySignature::Unsigned);
    }

    let mut all_unknown_issuers: Vec<String> = Vec::new();
    let mut saw_resolvable = false;

    for index in 0..n {
        let Some(sig) = reader.signature(index) else {
            continue;
        };
        let Some(cfg) = sig.config() else { continue };

        let mut issuer_ids: Vec<String> = Vec::new();
        for fp in cfg.issuer_fingerprint() {
            let id = hex::encode(fp.as_bytes()).to_uppercase();
            if !issuer_ids.contains(&id) {
                issuer_ids.push(id);
            }
        }
        for kid in cfg.issuer_key_id() {
            let id = hex::encode(kid).to_uppercase();
            if !issuer_ids.contains(&id) {
                issuer_ids.push(id);
            }
        }
        if issuer_ids.is_empty() {
            continue;
        }

        let Some(cert_bytes) = resolve_signer(&issuer_ids) else {
            for id in &issuer_ids {
                if !all_unknown_issuers.contains(id) {
                    all_unknown_issuers.push(id.clone());
                }
            }
            continue;
        };

        saw_resolvable = true;

        let cert = parse_verifying_cert(&cert_bytes)?;

        // Try primary first, then each subkey. We need to find which
        // specific key was used so we can report its fingerprint.
        let primary_fp = hex::encode(cert.primary_key.fingerprint().as_bytes()).to_uppercase();
        let primary_kid = hex::encode(cert.primary_key.legacy_key_id()).to_uppercase();

        if issuer_matches(&issuer_ids, &primary_fp, &primary_kid)
            && message
                .verify_nested_explicit(index, &cert.primary_key)
                .is_ok()
        {
            return Ok(DecryptVerifySignature::Good {
                verifier_fingerprint: primary_fp,
            });
        }
        for sub in &cert.public_subkeys {
            let sub_fp = hex::encode(sub.fingerprint().as_bytes()).to_uppercase();
            let sub_kid = hex::encode(sub.legacy_key_id()).to_uppercase();
            if issuer_matches(&issuer_ids, &sub_fp, &sub_kid)
                && message.verify_nested_explicit(index, &sub.key).is_ok()
            {
                return Ok(DecryptVerifySignature::Good {
                    verifier_fingerprint: sub_fp,
                });
            }
        }
    }

    if saw_resolvable {
        Ok(DecryptVerifySignature::Bad)
    } else {
        Ok(DecryptVerifySignature::UnknownKey {
            issuer_ids: all_unknown_issuers,
        })
    }
}

fn issuer_matches(issuer_ids: &[String], fingerprint: &str, key_id: &str) -> bool {
    issuer_ids
        .iter()
        .any(|id| id.eq_ignore_ascii_case(fingerprint) || id.eq_ignore_ascii_case(key_id))
}

/// Parse caller-supplied bytes as a public key, accepting armored, binary,
/// and secret-key forms (we only consume the public component for
/// verification).
fn parse_verifying_cert(cert_bytes: &[u8]) -> Result<SignedPublicKey> {
    if let Ok((cert, _)) = SignedPublicKey::from_armor_single(Cursor::new(cert_bytes)) {
        return Ok(cert);
    }
    if let Ok((cert, _)) = SignedPublicKey::from_reader_single(Cursor::new(cert_bytes)) {
        return Ok(cert);
    }
    if let Ok((secret, _)) =
        pgp::composed::SignedSecretKey::from_armor_single(Cursor::new(cert_bytes))
    {
        return Ok(secret.into());
    }
    let (secret, _) = pgp::composed::SignedSecretKey::from_reader_single(Cursor::new(cert_bytes))
        .map_err(|e| {
        Error::Parse(format!("failed to parse signer cert for verification: {e}"))
    })?;
    Ok(secret.into())
}

/// Decrypt a file using a secret key.
///
/// # Arguments
/// * `secret_key` - The recipient's secret key
/// * `input` - Path to the encrypted file
/// * `output` - Path to write the decrypted file
/// * `password` - Password to unlock the secret key
pub fn decrypt_file(
    secret_key: &[u8],
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    password: &str,
) -> Result<()> {
    let ciphertext = std::fs::read(input.as_ref())?;
    let plaintext = decrypt_bytes(secret_key, &ciphertext, password)?;
    std::fs::write(output.as_ref(), plaintext)?;
    Ok(())
}

/// Decrypt data from a reader to a file.
///
/// # Arguments
/// * `secret_key` - The recipient's secret key
/// * `reader` - Source of encrypted data
/// * `output` - Path to write the decrypted file
/// * `password` - Password to unlock the secret key
pub fn decrypt_reader_to_file<R: Read>(
    secret_key: &[u8],
    mut reader: R,
    output: impl AsRef<Path>,
    password: &str,
) -> Result<()> {
    let mut ciphertext = Vec::new();
    reader.read_to_end(&mut ciphertext)?;
    let plaintext = decrypt_bytes(secret_key, &ciphertext, password)?;
    std::fs::write(output.as_ref(), plaintext)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        create_key_simple, encrypt_bytes_to_multiple, sign_and_encrypt_to_multiple, sign_bytes,
    };

    /// Encrypt-only ciphertext should decrypt and report Unsigned.
    #[test]
    fn decrypt_and_verify_encrypt_only_is_unsigned() {
        let alice = create_key_simple("pw", &["Alice <a@example.com>"]).unwrap();

        // Encrypt-only — no signer.
        let ct = encrypt_bytes_to_multiple(&[alice.public_key.as_bytes()], b"hello world", true)
            .unwrap();

        let result = decrypt_and_verify(&alice.secret_key, &ct, "pw", |_| {
            panic!("resolve_signer must not be invoked for unsigned message");
        })
        .unwrap();

        assert_eq!(result.plaintext, b"hello world");
        assert_eq!(result.signature, DecryptVerifySignature::Unsigned);
    }

    /// Sign-then-encrypt with a known signer should return Good and the
    /// verifier fingerprint must match the signer's primary or signing
    /// subkey fingerprint.
    #[test]
    fn decrypt_and_verify_sign_then_encrypt_good() {
        let alice = create_key_simple("pw", &["Alice <a@example.com>"]).unwrap();
        let bob = create_key_simple("pw", &["Bob <b@example.com>"]).unwrap();

        let ct = sign_and_encrypt_to_multiple(
            &alice.secret_key,
            "pw",
            &[bob.public_key.as_bytes()],
            b"signed and sealed",
            true,
        )
        .unwrap();

        let mut resolver_calls = 0;
        let result = decrypt_and_verify(&bob.secret_key, &ct, "pw", |issuer_ids| {
            resolver_calls += 1;
            // Caller-side issuer ids must be uppercase hex.
            for id in issuer_ids {
                assert!(
                    id.chars().all(|c| c.is_ascii_hexdigit()),
                    "issuer id must be hex: {id}",
                );
                assert_eq!(id.to_uppercase(), *id, "issuer id must be uppercase");
            }
            Some(alice.public_key.as_bytes().to_vec())
        })
        .unwrap();

        assert_eq!(result.plaintext, b"signed and sealed");
        assert!(
            resolver_calls >= 1,
            "resolve_signer must be invoked at least once for signed payload"
        );
        match result.signature {
            DecryptVerifySignature::Good {
                verifier_fingerprint,
            } => {
                assert_eq!(verifier_fingerprint.len(), 40);
                assert_eq!(
                    verifier_fingerprint.to_uppercase(),
                    verifier_fingerprint,
                    "verifier fingerprint must be uppercase",
                );
            }
            other => panic!("expected Good, got {other:?}"),
        }
    }

    /// Sign-then-encrypt where the resolver returns None for the issuer
    /// must surface UnknownKey with the issuer ids.
    #[test]
    fn decrypt_and_verify_unknown_signer() {
        let alice = create_key_simple("pw", &["Alice <a@example.com>"]).unwrap();
        let bob = create_key_simple("pw", &["Bob <b@example.com>"]).unwrap();

        let ct = sign_and_encrypt_to_multiple(
            &alice.secret_key,
            "pw",
            &[bob.public_key.as_bytes()],
            b"signed by alice",
            true,
        )
        .unwrap();

        let result = decrypt_and_verify(&bob.secret_key, &ct, "pw", |_| None).unwrap();

        assert_eq!(result.plaintext, b"signed by alice");
        match result.signature {
            DecryptVerifySignature::UnknownKey { issuer_ids } => {
                assert!(!issuer_ids.is_empty(), "must surface issuer ids for UI");
            }
            other => panic!("expected UnknownKey, got {other:?}"),
        }
    }

    /// If the resolver returns the WRONG key (well-formed but not the
    /// actual signer), the signature must fail to verify and we must
    /// report Bad — never Good.
    #[test]
    fn decrypt_and_verify_wrong_signer_key_is_bad() {
        let alice = create_key_simple("pw", &["Alice <a@example.com>"]).unwrap();
        let bob = create_key_simple("pw", &["Bob <b@example.com>"]).unwrap();
        let mallory = create_key_simple("pw", &["Mallory <m@example.com>"]).unwrap();

        let ct = sign_and_encrypt_to_multiple(
            &alice.secret_key,
            "pw",
            &[bob.public_key.as_bytes()],
            b"signed by alice",
            true,
        )
        .unwrap();

        // Resolver returns Mallory's key for whatever issuer ids. Because
        // the resolver returns Some(_), this exercises the "resolvable but
        // wrong key" path: verification must fail and must not report
        // "Good" for a substituted key.
        let result = decrypt_and_verify(&bob.secret_key, &ct, "pw", |_| {
            Some(mallory.public_key.as_bytes().to_vec())
        })
        .unwrap();

        assert!(
            !matches!(result.signature, DecryptVerifySignature::Good { .. }),
            "must not report Good when caller returns a non-matching key: {:?}",
            result.signature
        );
    }

    /// Wrong passphrase must surface a uniform "Decryption failed" so we
    /// don't leak which step failed.
    #[test]
    fn decrypt_and_verify_wrong_passphrase() {
        let alice = create_key_simple("pw", &["Alice <a@example.com>"]).unwrap();

        let ct = encrypt_bytes_to_multiple(&[alice.public_key.as_bytes()], b"hello", true).unwrap();

        let err = decrypt_and_verify(&alice.secret_key, &ct, "wrong-pw", |_| None).unwrap_err();
        assert!(err.to_string().contains("Decryption failed"), "got: {err}");
    }

    /// Standalone signed-not-encrypted message should error: this API is
    /// for ciphertext only. We expect a Crypto/Parse error rather than a
    /// "successful decrypt with Unsigned".
    #[test]
    fn decrypt_and_verify_rejects_non_ciphertext() {
        let alice = create_key_simple("pw", &["Alice <a@example.com>"]).unwrap();
        let signed = sign_bytes(&alice.secret_key, b"hello", "pw").unwrap();
        let err = decrypt_and_verify(&alice.secret_key, &signed, "pw", |_| None).unwrap_err();
        // Either decryption fails (it's not encrypted) or parsing fails;
        // either is fine, just must not silently succeed.
        let msg = err.to_string();
        assert!(
            msg.contains("Decryption failed") || msg.contains("parse"),
            "expected decrypt or parse error, got: {msg}",
        );
    }
}
