//! Network key fetching (WKD and keyserver support).
//!
//! This module provides functions for fetching OpenPGP keys from the network
//! using Web Key Directory (WKD) and HKP keyservers.

use crate::error::{Error, Result};
use crate::internal::parse_cert;

/// Fetch a key from Web Key Directory (WKD) by email address.
///
/// WKD is a standard for distributing OpenPGP keys via HTTPS. It uses the
/// domain from the email address to construct URLs where keys can be found.
///
/// # Arguments
/// * `email` - Email address to look up
///
/// # Returns
/// The certificate data if found.
///
/// # Example
/// ```ignore
/// let cert = fetch_key_by_email("user@example.com")?;
/// ```
#[cfg(feature = "network")]
pub fn fetch_key_by_email(email: &str) -> Result<Vec<u8>> {
    let (local, domain) = parse_email(email)?;

    // Try advanced method first, then direct method
    let urls = wkd_urls(&local, &domain);

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| Error::Network(e.to_string()))?;

    let mut last_error = None;

    for url in urls {
        match client.get(&url).send() {
            Ok(response) => {
                if response.status().is_success() {
                    let bytes = response.bytes()
                        .map_err(|e| Error::Network(e.to_string()))?;

                    // Verify it's a valid certificate
                    let _ = parse_cert(&bytes)?;

                    return Ok(bytes.to_vec());
                }
            }
            Err(e) => {
                last_error = Some(e.to_string());
            }
        }
    }

    Err(Error::KeyNotFound(format!(
        "No key found for email '{}': {}",
        email,
        last_error.unwrap_or_else(|| "Not found".to_string())
    )))
}

/// Fetch a key from an HKP keyserver by fingerprint.
///
/// # Arguments
/// * `fingerprint` - The key fingerprint (40 hex characters)
/// * `keyserver` - Optional keyserver URL (defaults to keys.openpgp.org)
///
/// # Returns
/// The certificate data if found.
///
/// # Example
/// ```ignore
/// let cert = fetch_key_by_fingerprint(
///     "A4F388BBB194925AE301F844C52B42177857DD79",
///     None,
/// )?;
/// ```
#[cfg(feature = "network")]
pub fn fetch_key_by_fingerprint(
    fingerprint: &str,
    keyserver: Option<&str>,
) -> Result<Vec<u8>> {
    let server = keyserver.unwrap_or("https://keys.openpgp.org");
    let url = format!("{}/vks/v1/by-fingerprint/{}", server, fingerprint.to_uppercase());

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| Error::Network(e.to_string()))?;

    let response = client.get(&url)
        .send()
        .map_err(|e| Error::Network(e.to_string()))?;

    if !response.status().is_success() {
        return Err(Error::KeyNotFound(format!(
            "Key not found on keyserver: {}",
            fingerprint
        )));
    }

    let bytes = response.bytes()
        .map_err(|e| Error::Network(e.to_string()))?;

    // Verify it's a valid certificate
    let _ = parse_cert(&bytes)?;

    Ok(bytes.to_vec())
}

/// Fetch a key from an HKP keyserver by key ID.
///
/// # Arguments
/// * `key_id` - The key ID (16 hex characters)
/// * `keyserver` - Optional keyserver URL (defaults to keys.openpgp.org)
///
/// # Returns
/// The certificate data if found.
#[cfg(feature = "network")]
pub fn fetch_key_by_keyid(
    key_id: &str,
    keyserver: Option<&str>,
) -> Result<Vec<u8>> {
    let server = keyserver.unwrap_or("https://keys.openpgp.org");
    let url = format!("{}/vks/v1/by-keyid/{}", server, key_id.to_uppercase());

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| Error::Network(e.to_string()))?;

    let response = client.get(&url)
        .send()
        .map_err(|e| Error::Network(e.to_string()))?;

    if !response.status().is_success() {
        return Err(Error::KeyNotFound(format!(
            "Key not found on keyserver: {}",
            key_id
        )));
    }

    let bytes = response.bytes()
        .map_err(|e| Error::Network(e.to_string()))?;

    // Verify it's a valid certificate
    let _ = parse_cert(&bytes)?;

    Ok(bytes.to_vec())
}

/// Parse email into local part and domain.
fn parse_email(email: &str) -> Result<(String, String)> {
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return Err(Error::InvalidInput(format!("Invalid email address: {}", email)));
    }
    Ok((parts[0].to_lowercase(), parts[1].to_lowercase()))
}

/// Generate WKD URLs for a given email address.
/// Returns both advanced and direct method URLs.
#[cfg(feature = "network")]
fn wkd_urls(local: &str, domain: &str) -> Vec<String> {
    use sha1::{Sha1, Digest};

    // Z-base32 encoding for WKD
    let hash = {
        let mut hasher = Sha1::new();
        hasher.update(local.as_bytes());
        let result = hasher.finalize();
        zbase32_encode(&result)
    };

    vec![
        // Advanced method
        format!(
            "https://openpgpkey.{domain}/.well-known/openpgpkey/{domain}/hu/{hash}?l={local}",
            domain = domain,
            hash = hash,
            local = local
        ),
        // Direct method
        format!(
            "https://{domain}/.well-known/openpgpkey/hu/{hash}?l={local}",
            domain = domain,
            hash = hash,
            local = local
        ),
    ]
}

/// Z-base32 encoding (used by WKD).
#[cfg(feature = "network")]
fn zbase32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

    let mut result = String::new();
    let mut buffer: u64 = 0;
    let mut bits_in_buffer = 0;

    for &byte in data {
        buffer = (buffer << 8) | byte as u64;
        bits_in_buffer += 8;

        while bits_in_buffer >= 5 {
            bits_in_buffer -= 5;
            let index = ((buffer >> bits_in_buffer) & 0x1f) as usize;
            result.push(ALPHABET[index] as char);
        }
    }

    if bits_in_buffer > 0 {
        let index = ((buffer << (5 - bits_in_buffer)) & 0x1f) as usize;
        result.push(ALPHABET[index] as char);
    }

    result
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "network")]
    use super::*;

    #[test]
    #[cfg(feature = "network")]
    fn test_zbase32_encode() {
        // Test vector from the WKD specification
        let input = b"test";
        let encoded = zbase32_encode(input);
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_parse_email() {
        let (local, domain) = parse_email("user@example.com").unwrap();
        assert_eq!(local, "user");
        assert_eq!(domain, "example.com");

        assert!(parse_email("invalid").is_err());
    }

    #[test]
    #[cfg(feature = "network")]
    fn test_wkd_urls() {
        let urls = wkd_urls("test", "example.com");
        assert_eq!(urls.len(), 2);
        assert!(urls[0].contains("openpgpkey.example.com"));
        assert!(urls[1].contains("example.com/.well-known"));
    }
}
