//! SSH public key conversion and signing functions.
//!
//! This module provides functions for converting OpenPGP authentication
//! keys to SSH public key format (RFC 4253) and for performing raw
//! cryptographic signatures suitable for SSH authentication.

use std::time::SystemTime;

use pgp::types::{KeyDetails, Password, PlainSecretParams, PublicParams};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::internal::{is_key_expired, is_subkey_valid, parse_public_key, parse_secret_key};
use crate::types::{RsaPublicKey, SigningPublicKey};

/// Convert a key's authentication key to SSH public key format.
///
/// # Arguments
/// * `key_data` - The key data
/// * `comment` - Optional comment to append (e.g., email address)
///
/// # Returns
/// SSH public key string (e.g., "ssh-rsa AAAA... comment").
///
/// # Example
/// ```ignore
/// // Ignored: illustrative example with placeholder file path
/// let key = std::fs::read("key.asc")?;
/// let ssh_key = get_ssh_pubkey(&key, Some("user@example.com"))?;
/// println!("{}", ssh_key);
/// ```
pub fn get_ssh_pubkey(key_data: &[u8], comment: Option<&str>) -> Result<String> {
    let public_key = parse_public_key(key_data)?;

    // Find an authentication-capable subkey
    let auth_subkey = public_key.public_subkeys.iter().find(|sk| {
        // Check if valid and has authentication flag
        if !is_subkey_valid(sk, false) {
            return false;
        }
        sk.signatures
            .iter()
            .any(|sig| sig.key_flags().authentication())
    });

    let params = match auth_subkey {
        Some(sk) => sk.key.public_params(),
        None => {
            // Fall back to primary key if it can be used for authentication
            return Err(Error::NoAuthenticationSubkey);
        }
    };

    // Convert public parameters to SSH format
    let (key_type, key_blob) = convert_params_to_ssh(params)?;

    // Format as SSH public key line (with trailing newline as per convention)
    let key_data = base64_encode(&key_blob);
    let ssh_line = match comment {
        Some(c) => format!("{} {} {}\n", key_type, key_data, c),
        None => format!("{} {}\n", key_type, key_data),
    };

    Ok(ssh_line)
}

/// Convert public key parameters to SSH wire format.
fn convert_params_to_ssh(params: &PublicParams) -> Result<(String, Vec<u8>)> {
    match params {
        PublicParams::RSA(rsa_params) => {
            use rsa::traits::PublicKeyParts;

            let e = rsa_params.key.e().to_bytes_be();
            let n = rsa_params.key.n().to_bytes_be();

            let mut blob = Vec::new();
            // SSH format: string "ssh-rsa" + mpint e + mpint n
            write_ssh_string(&mut blob, b"ssh-rsa");
            write_ssh_mpint(&mut blob, &e);
            write_ssh_mpint(&mut blob, &n);

            Ok(("ssh-rsa".to_string(), blob))
        }
        // RFC 9580 Ed25519 (v6 keys)
        PublicParams::Ed25519(ed_params) => {
            let key_bytes = ed_params.key.as_bytes();
            let mut blob = Vec::new();
            // SSH format: string "ssh-ed25519" + string key_data
            write_ssh_string(&mut blob, b"ssh-ed25519");
            write_ssh_string(&mut blob, key_bytes);

            Ok(("ssh-ed25519".to_string(), blob))
        }
        // Legacy EdDSA (v4 keys)
        PublicParams::EdDSALegacy(ed_params) => {
            use pgp::types::EddsaLegacyPublicParams;

            match ed_params {
                EddsaLegacyPublicParams::Ed25519 { key } => {
                    let key_bytes = key.as_bytes();
                    let mut blob = Vec::new();
                    write_ssh_string(&mut blob, b"ssh-ed25519");
                    write_ssh_string(&mut blob, key_bytes);

                    Ok(("ssh-ed25519".to_string(), blob))
                }
                _ => Err(Error::UnsupportedAlgorithm(
                    "Unsupported legacy EdDSA curve for SSH".to_string(),
                )),
            }
        }
        PublicParams::Ed448(_) => {
            // Ed448 is not commonly supported in SSH
            Err(Error::UnsupportedAlgorithm(
                "Ed448 SSH conversion not supported".to_string(),
            ))
        }
        PublicParams::ECDSA(ecdsa_params) => {
            use pgp::types::EcdsaPublicParams;

            match ecdsa_params {
                EcdsaPublicParams::P256 { key } => {
                    use p256::elliptic_curve::sec1::ToEncodedPoint;
                    let mut blob = Vec::new();
                    let curve_name = b"nistp256";
                    let key_type = "ecdsa-sha2-nistp256";

                    write_ssh_string(&mut blob, key_type.as_bytes());
                    write_ssh_string(&mut blob, curve_name);
                    // The key is the uncompressed point (0x04 || x || y)
                    let point = key.to_encoded_point(false);
                    write_ssh_string(&mut blob, point.as_bytes());

                    Ok((key_type.to_string(), blob))
                }
                EcdsaPublicParams::P384 { key } => {
                    use p384::elliptic_curve::sec1::ToEncodedPoint;
                    let mut blob = Vec::new();
                    let curve_name = b"nistp384";
                    let key_type = "ecdsa-sha2-nistp384";

                    write_ssh_string(&mut blob, key_type.as_bytes());
                    write_ssh_string(&mut blob, curve_name);
                    let point = key.to_encoded_point(false);
                    write_ssh_string(&mut blob, point.as_bytes());

                    Ok((key_type.to_string(), blob))
                }
                EcdsaPublicParams::P521 { key } => {
                    use p521::elliptic_curve::sec1::ToEncodedPoint;
                    let mut blob = Vec::new();
                    let curve_name = b"nistp521";
                    let key_type = "ecdsa-sha2-nistp521";

                    write_ssh_string(&mut blob, key_type.as_bytes());
                    write_ssh_string(&mut blob, curve_name);
                    let point = key.to_encoded_point(false);
                    write_ssh_string(&mut blob, point.as_bytes());

                    Ok((key_type.to_string(), blob))
                }
                _ => Err(Error::UnsupportedAlgorithm(
                    "Unsupported ECDSA curve for SSH".to_string(),
                )),
            }
        }
        PublicParams::ECDH(ecdh_params) => {
            use pgp::types::EcdhPublicParams;

            // ECDH keys with Curve25519 can be converted for SSH authentication
            match ecdh_params {
                EcdhPublicParams::Curve25519 { .. } => {
                    // Note: X25519 is typically used for key exchange, not authentication
                    Err(Error::UnsupportedAlgorithm(
                        "X25519 is for key exchange, not authentication".to_string(),
                    ))
                }
                _ => Err(Error::UnsupportedAlgorithm(
                    "ECDH keys cannot be used for SSH authentication".to_string(),
                )),
            }
        }
        _ => Err(Error::UnsupportedAlgorithm(
            "SSH conversion not supported for this key type".to_string(),
        )),
    }
}

/// Write a string in SSH wire format (4-byte big-endian length + data).
fn write_ssh_string(buf: &mut Vec<u8>, data: &[u8]) {
    let len = data.len() as u32;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
}

/// Write an mpint in SSH wire format.
/// SSH mpints are big-endian, with a leading zero byte if the high bit is set.
fn write_ssh_mpint(buf: &mut Vec<u8>, data: &[u8]) {
    // Skip leading zeros
    let data = data
        .iter()
        .skip_while(|&&b| b == 0)
        .copied()
        .collect::<Vec<_>>();

    if data.is_empty() {
        // Zero value
        buf.extend_from_slice(&[0, 0, 0, 0]);
        return;
    }

    // Check if we need a leading zero (high bit set)
    let needs_padding = data[0] & 0x80 != 0;
    let len = data.len() + if needs_padding { 1 } else { 0 };

    buf.extend_from_slice(&(len as u32).to_be_bytes());
    if needs_padding {
        buf.push(0);
    }
    buf.extend_from_slice(&data);
}

/// Get signing public key components for external verification.
///
/// # Arguments
/// * `key_data` - The key data
///
/// # Returns
/// Public key components in algorithm-specific format.
pub fn get_signing_pubkey(key_data: &[u8]) -> Result<SigningPublicKey> {
    let public_key = parse_public_key(key_data)?;

    // Find a signing-capable subkey
    let sign_subkey = public_key.public_subkeys.iter().find(|sk| {
        if !is_subkey_valid(sk, false) {
            return false;
        }
        sk.signatures.iter().any(|sig| sig.key_flags().sign())
    });

    // Check if primary can sign
    let primary_can_sign = public_key
        .details
        .users
        .iter()
        .any(|user| user.signatures.iter().any(|sig| sig.key_flags().sign()));

    // Get the public params from the appropriate key
    let params = if let Some(sk) = sign_subkey {
        sk.key.public_params()
    } else if primary_can_sign {
        public_key.primary_key.public_params()
    } else {
        return Err(Error::NoSigningSubkey);
    };

    // Extract actual key material
    match params {
        PublicParams::RSA(rsa_params) => {
            use rsa::traits::PublicKeyParts;

            let n = hex::encode_upper(rsa_params.key.n().to_bytes_be());
            let e = hex::encode_upper(rsa_params.key.e().to_bytes_be());

            Ok(SigningPublicKey::Rsa(RsaPublicKey { n, e }))
        }
        // RFC 9580 Ed25519 (v6 keys)
        PublicParams::Ed25519(ed_params) => {
            let public = hex::encode_upper(ed_params.key.as_bytes());
            Ok(SigningPublicKey::Ed25519 { public })
        }
        // Legacy EdDSA (v4 keys)
        PublicParams::EdDSALegacy(ed_params) => {
            use pgp::types::EddsaLegacyPublicParams;

            match ed_params {
                EddsaLegacyPublicParams::Ed25519 { key } => {
                    let public = hex::encode_upper(key.as_bytes());
                    Ok(SigningPublicKey::Ed25519 { public })
                }
                _ => Err(Error::UnsupportedAlgorithm(
                    "Unsupported legacy EdDSA variant".to_string(),
                )),
            }
        }
        PublicParams::ECDSA(ecdsa_params) => {
            use pgp::types::EcdsaPublicParams;

            let (curve, point) = match ecdsa_params {
                EcdsaPublicParams::P256 { key } => {
                    use p256::elliptic_curve::sec1::ToEncodedPoint;
                    let encoded = key.to_encoded_point(false);
                    ("P-256".to_string(), hex::encode_upper(encoded.as_bytes()))
                }
                EcdsaPublicParams::P384 { key } => {
                    use p384::elliptic_curve::sec1::ToEncodedPoint;
                    let encoded = key.to_encoded_point(false);
                    ("P-384".to_string(), hex::encode_upper(encoded.as_bytes()))
                }
                EcdsaPublicParams::P521 { key } => {
                    use p521::elliptic_curve::sec1::ToEncodedPoint;
                    let encoded = key.to_encoded_point(false);
                    ("P-521".to_string(), hex::encode_upper(encoded.as_bytes()))
                }
                _ => {
                    return Err(Error::UnsupportedAlgorithm(
                        "Unsupported ECDSA curve".to_string(),
                    ))
                }
            };

            Ok(SigningPublicKey::Ecdsa { curve, point })
        }
        _ => Err(Error::UnsupportedAlgorithm(
            "Signing key extraction not supported for this key type".to_string(),
        )),
    }
}

/// Simple base64 encoding (standard alphabet, no padding removal needed for SSH).
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::new();
    let mut i = 0;

    while i < data.len() {
        let b0 = data[i];
        let b1 = if i + 1 < data.len() { data[i + 1] } else { 0 };
        let b2 = if i + 2 < data.len() { data[i + 2] } else { 0 };

        let c0 = (b0 >> 2) as usize;
        let c1 = (((b0 & 0x03) << 4) | (b1 >> 4)) as usize;
        let c2 = (((b1 & 0x0f) << 2) | (b2 >> 6)) as usize;
        let c3 = (b2 & 0x3f) as usize;

        result.push(ALPHABET[c0] as char);
        result.push(ALPHABET[c1] as char);

        if i + 1 < data.len() {
            result.push(ALPHABET[c2] as char);
        } else {
            result.push('=');
        }

        if i + 2 < data.len() {
            result.push(ALPHABET[c3] as char);
        } else {
            result.push('=');
        }

        i += 3;
    }

    result
}

/// The algorithm and raw signature bytes from an SSH signing operation.
#[derive(Debug)]
pub enum SshSignResult {
    /// Ed25519 signature (64 bytes).
    Ed25519(Vec<u8>),
    /// ECDSA signature with named curve. Contains raw (r, s) scalars.
    Ecdsa {
        curve: String,
        r: Vec<u8>,
        s: Vec<u8>,
    },
    /// RSA signature bytes.
    Rsa(Vec<u8>),
}

/// Hash algorithm for SSH signing operations.
///
/// This tells `ssh_sign_raw` which PKCS#1v15 hash to use for RSA signing.
/// For Ed25519 and ECDSA the hash is determined by the key type, so this
/// value is only consulted for RSA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshHashAlgorithm {
    Sha256,
    Sha512,
}

/// Perform a raw SSH signature using a software authentication subkey.
///
/// This unlocks the secret key's authentication subkey and produces a raw
/// cryptographic signature suitable for the SSH agent protocol (not an
/// OpenPGP signature).
///
/// # Arguments
/// * `secret_key` - The secret key data (armored or binary)
/// * `data` - The data to sign (for Ed25519: the raw message; for ECDSA/RSA: the pre-hashed digest)
/// * `password` - Password to unlock the secret key
/// * `hash_alg` - Hash algorithm hint (used for RSA PKCS#1v15 signing)
///
/// # Returns
/// An `SshSignResult` containing the algorithm-specific signature.
pub fn ssh_sign_raw(
    secret_key: &[u8],
    data: &[u8],
    password: &str,
    hash_alg: SshHashAlgorithm,
) -> Result<SshSignResult> {
    let secret_key = parse_secret_key(secret_key)?;
    let pw: Password = password.into();

    // Find the authentication subkey
    for subkey in &secret_key.secret_subkeys {
        let is_auth = subkey
            .signatures
            .iter()
            .any(|sig| sig.key_flags().authentication());

        if !is_auth {
            continue;
        }

        // Check the subkey isn't revoked
        let is_revoked = subkey
            .signatures
            .iter()
            .any(|sig| sig.typ() == Some(pgp::packet::SignatureType::SubkeyRevocation));
        if is_revoked {
            continue;
        }

        // Check the subkey isn't expired
        if let Some(sig) = subkey.signatures.last() {
            if let Some(validity) = sig.key_expiration_time() {
                let creation_time: SystemTime = subkey.key.created_at().into();
                if is_key_expired(creation_time, Some(validity.as_secs() as u64)) {
                    continue;
                }
            }
        }

        // Unlock the subkey and perform raw signing
        let result = subkey.key.unlock(&pw, |pub_params, secret_params| {
            ssh_raw_sign_with_params(pub_params, secret_params, data, hash_alg).map_err(|e| {
                pgp::errors::Error::Message {
                    message: e.to_string(),
                    backtrace: Some(std::backtrace::Backtrace::capture()),
                }
            })
        });

        match result {
            Ok(Ok(sig)) => return Ok(sig),
            Ok(Err(e)) => return Err(Error::Crypto(e.to_string())),
            Err(e) => return Err(Error::Crypto(e.to_string())),
        }
    }

    Err(Error::NoAuthenticationSubkey)
}

/// Perform a raw cryptographic signature using unlocked key parameters.
fn ssh_raw_sign_with_params(
    pub_params: &PublicParams,
    secret_params: &PlainSecretParams,
    data: &[u8],
    hash_alg: SshHashAlgorithm,
) -> Result<SshSignResult> {
    match secret_params {
        // Ed25519 (RFC 9580) or legacy EdDSA
        PlainSecretParams::Ed25519(sk) | PlainSecretParams::Ed25519Legacy(sk) => {
            let key_bytes = sk.as_bytes();
            let signing_key = pgp::crypto::ed25519::SecretKey::try_from_bytes(
                *key_bytes,
                pgp::crypto::ed25519::Mode::Ed25519,
            )
            .map_err(|e| Error::Crypto(e.to_string()))?;
            use std::ops::Deref;
            let dalek_key: &ed25519_dalek::SigningKey = signing_key.deref();
            use ed25519_dalek::Signer;
            let signature = dalek_key.sign(data);
            Ok(SshSignResult::Ed25519(signature.to_bytes().to_vec()))
        }

        // ECDSA - determine curve from pub_params, not scalar length
        PlainSecretParams::ECDSA(ecdsa_sk) => {
            use pgp::types::EcdsaPublicParams;

            let scalar_bytes = Zeroizing::new(ecdsa_sk.to_bytes());

            match pub_params {
                PublicParams::ECDSA(EcdsaPublicParams::P256 { .. }) => {
                    use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
                    let signing_key =
                        SigningKey::from_bytes(p256::FieldBytes::from_slice(&scalar_bytes))
                            .map_err(|e| Error::Crypto(e.to_string()))?;
                    let sig: Signature = signing_key
                        .sign_prehash(data)
                        .map_err(|e| Error::Crypto(e.to_string()))?;
                    let (r, s) = sig.split_bytes();
                    Ok(SshSignResult::Ecdsa {
                        curve: "nistp256".to_string(),
                        r: r.to_vec(),
                        s: s.to_vec(),
                    })
                }
                PublicParams::ECDSA(EcdsaPublicParams::P384 { .. }) => {
                    use p384::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
                    let signing_key =
                        SigningKey::from_bytes(p384::FieldBytes::from_slice(&scalar_bytes))
                            .map_err(|e| Error::Crypto(e.to_string()))?;
                    let sig: Signature = signing_key
                        .sign_prehash(data)
                        .map_err(|e| Error::Crypto(e.to_string()))?;
                    let (r, s) = sig.split_bytes();
                    Ok(SshSignResult::Ecdsa {
                        curve: "nistp384".to_string(),
                        r: r.to_vec(),
                        s: s.to_vec(),
                    })
                }
                PublicParams::ECDSA(EcdsaPublicParams::P521 { .. }) => {
                    use p521::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
                    let signing_key =
                        SigningKey::from_bytes(p521::FieldBytes::from_slice(&scalar_bytes))
                            .map_err(|e| Error::Crypto(e.to_string()))?;
                    let sig: Signature = signing_key
                        .sign_prehash(data)
                        .map_err(|e| Error::Crypto(e.to_string()))?;
                    let (r, s) = sig.split_bytes();
                    Ok(SshSignResult::Ecdsa {
                        curve: "nistp521".to_string(),
                        r: r.to_vec(),
                        s: s.to_vec(),
                    })
                }
                _ => Err(Error::UnsupportedAlgorithm(
                    "Unsupported ECDSA curve for SSH signing (only P-256, P-384, P-521)"
                        .to_string(),
                )),
            }
        }

        // RSA - reconstruct the RsaPrivateKey from components and sign with PKCS#1v15
        PlainSecretParams::RSA(rsa_sk) => {
            use rsa::pkcs1v15::SigningKey as RsaSigningKey;
            use rsa::signature::{hazmat::PrehashSigner, SignatureEncoding};

            // Get d, p, q, u from the secret key (all zeroized on drop)
            let (d_bytes, p_bytes, q_bytes, u_bytes) = rsa_sk.to_bytes();
            let d_bytes = Zeroizing::new(d_bytes);
            let p_bytes = Zeroizing::new(p_bytes);
            let q_bytes = Zeroizing::new(q_bytes);
            let _u_bytes = Zeroizing::new(u_bytes);

            // Get n, e from the public params
            let (n, e) = match pub_params {
                PublicParams::RSA(rsa_pub) => {
                    use rsa::traits::PublicKeyParts;
                    (rsa_pub.key.n().clone(), rsa_pub.key.e().clone())
                }
                _ => {
                    return Err(Error::Crypto(
                        "RSA secret key with non-RSA public params".to_string(),
                    ));
                }
            };

            let private_key = rsa::RsaPrivateKey::from_components(
                n,
                e,
                rsa::BigUint::from_bytes_be(&d_bytes),
                vec![
                    rsa::BigUint::from_bytes_be(&p_bytes),
                    rsa::BigUint::from_bytes_be(&q_bytes),
                ],
            )
            .map_err(|e| Error::Crypto(format!("Failed to reconstruct RSA key: {}", e)))?;

            // Use the explicitly provided hash algorithm
            let sig_bytes = match hash_alg {
                SshHashAlgorithm::Sha256 => {
                    let signer = RsaSigningKey::<sha2::Sha256>::new(private_key);
                    signer
                        .sign_prehash(data)
                        .map_err(|e| Error::Crypto(format!("RSA signing failed: {}", e)))?
                        .to_vec()
                }
                SshHashAlgorithm::Sha512 => {
                    let signer = RsaSigningKey::<sha2::Sha512>::new(private_key);
                    signer
                        .sign_prehash(data)
                        .map_err(|e| Error::Crypto(format!("RSA signing failed: {}", e)))?
                        .to_vec()
                }
            };

            Ok(SshSignResult::Rsa(sig_bytes))
        }

        _ => Err(Error::UnsupportedAlgorithm(
            "Unsupported key type for SSH signing".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }
}
