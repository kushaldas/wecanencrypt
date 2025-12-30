//! SSH public key conversion functions.
//!
//! This module provides functions for converting OpenPGP authentication
//! keys to SSH public key format (RFC 4253).

use pgp::types::{KeyDetails, PublicParams};

use crate::error::{Error, Result};
use crate::internal::{is_subkey_valid, parse_public_key};
use crate::types::{RsaPublicKey, SigningPublicKey};

/// Convert a certificate's authentication key to SSH public key format.
///
/// # Arguments
/// * `cert_data` - The certificate data
/// * `comment` - Optional comment to append (e.g., email address)
///
/// # Returns
/// SSH public key string (e.g., "ssh-rsa AAAA... comment").
///
/// # Example
/// ```ignore
/// let cert = std::fs::read("key.asc")?;
/// let ssh_key = get_ssh_pubkey(&cert, Some("user@example.com"))?;
/// println!("{}", ssh_key);
/// ```
pub fn get_ssh_pubkey(cert_data: &[u8], comment: Option<&str>) -> Result<String> {
    let public_key = parse_public_key(cert_data)?;

    // Find an authentication-capable subkey
    let auth_subkey = public_key.public_subkeys.iter().find(|sk| {
        // Check if valid and has authentication flag
        if !is_subkey_valid(sk, false) {
            return false;
        }
        sk.signatures.iter().any(|sig| sig.key_flags().authentication())
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
    let data = data.iter().skip_while(|&&b| b == 0).copied().collect::<Vec<_>>();

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
/// * `cert_data` - The certificate data
///
/// # Returns
/// Public key components in algorithm-specific format.
pub fn get_signing_pubkey(cert_data: &[u8]) -> Result<SigningPublicKey> {
    let public_key = parse_public_key(cert_data)?;

    // Find a signing-capable subkey
    let sign_subkey = public_key.public_subkeys.iter().find(|sk| {
        if !is_subkey_valid(sk, false) {
            return false;
        }
        sk.signatures.iter().any(|sig| sig.key_flags().sign())
    });

    // Check if primary can sign
    let primary_can_sign = public_key.details.users.iter().any(|user| {
        user.signatures.iter().any(|sig| sig.key_flags().sign())
    });

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

/// Convert bytes to hexadecimal string.
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
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

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }
}
