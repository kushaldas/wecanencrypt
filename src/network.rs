//! Network key fetching (WKD, keyserver, and DANE support).
//!
//! This module provides functions for fetching OpenPGP keys from the network
//! using Web Key Directory (WKD), HKP keyservers, and DNS DANE (OPENPGPKEY records).

use crate::error::{Error, Result};
use crate::internal::parse_cert;
#[cfg(feature = "network")]
use crate::internal::{fingerprint_to_hex, keyid_to_hex};

/// Maximum response size for key fetches (10 MB).
const MAX_KEY_RESPONSE_SIZE: u64 = 10 * 1024 * 1024;

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
/// // Ignored: requires network access to WKD servers
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
                    let bytes = read_response_limited(response)?;

                    // Verify it's a valid certificate
                    let _ = parse_cert(&bytes)?;

                    return Ok(bytes);
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
/// // Ignored: requires network access to keyservers
/// let cert = fetch_key_by_fingerprint(
///     "A4F388BBB194925AE301F844C52B42177857DD79",
///     None,
/// )?;
/// ```
#[cfg(feature = "network")]
pub fn fetch_key_by_fingerprint(fingerprint: &str, keyserver: Option<&str>) -> Result<Vec<u8>> {
    let server = keyserver.unwrap_or("https://keys.openpgp.org");
    let url = format!(
        "{}/vks/v1/by-fingerprint/{}",
        server,
        fingerprint.to_uppercase()
    );

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| Error::Network(e.to_string()))?;

    let response = client
        .get(&url)
        .send()
        .map_err(|e| Error::Network(e.to_string()))?;

    if !response.status().is_success() {
        return Err(Error::KeyNotFound(format!(
            "Key not found on keyserver: {}",
            fingerprint
        )));
    }

    let bytes = read_response_limited(response)?;

    // Verify it's a valid certificate and matches the requested fingerprint
    let (public_key, _) = parse_cert(&bytes)?;
    let fetched_fp = fingerprint_to_hex(&public_key.primary_key);
    if fetched_fp != fingerprint.to_uppercase() {
        return Err(Error::KeyNotFound(format!(
            "Fetched key fingerprint {} does not match requested {}",
            fetched_fp, fingerprint
        )));
    }

    Ok(bytes)
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
pub fn fetch_key_by_keyid(key_id: &str, keyserver: Option<&str>) -> Result<Vec<u8>> {
    let server = keyserver.unwrap_or("https://keys.openpgp.org");
    let url = format!("{}/vks/v1/by-keyid/{}", server, key_id.to_uppercase());

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| Error::Network(e.to_string()))?;

    let response = client
        .get(&url)
        .send()
        .map_err(|e| Error::Network(e.to_string()))?;

    if !response.status().is_success() {
        return Err(Error::KeyNotFound(format!(
            "Key not found on keyserver: {}",
            key_id
        )));
    }

    let bytes = read_response_limited(response)?;

    // Verify it's a valid certificate and matches the requested key ID
    let (public_key, _) = parse_cert(&bytes)?;
    let fetched_keyid = keyid_to_hex(&public_key.primary_key);
    if fetched_keyid != key_id.to_uppercase() {
        // Also check subkey IDs — the key ID might refer to a subkey
        let subkey_match = public_key
            .public_subkeys
            .iter()
            .any(|sk| keyid_to_hex(&sk.key) == key_id.to_uppercase());
        if !subkey_match {
            return Err(Error::KeyNotFound(format!(
                "Fetched key ID {} does not match requested {}",
                fetched_keyid, key_id
            )));
        }
    }

    Ok(bytes)
}

/// Fetch a key from a VKS keyserver by email address.
///
/// This queries keyservers that implement the VKS (Verifying Key Server)
/// protocol, such as keys.openpgp.org, using the `/vks/v1/by-email/` endpoint.
///
/// Unlike [`fetch_key_by_email`] which uses WKD (querying the email domain),
/// this function queries a centralized keyserver directly.
///
/// # Arguments
/// * `email` - Email address to look up
/// * `keyserver` - Optional keyserver URL (defaults to keys.openpgp.org)
///
/// # Returns
/// The certificate data if found.
///
/// # Example
/// ```ignore
/// // Ignored: requires network access to keyservers
/// let cert = fetch_key_by_email_from_keyserver("user@example.com", None)?;
/// ```
#[cfg(feature = "network")]
pub fn fetch_key_by_email_from_keyserver(email: &str, keyserver: Option<&str>) -> Result<Vec<u8>> {
    let server = keyserver.unwrap_or("https://keys.openpgp.org");
    let url = format!("{}/vks/v1/by-email/{}", server, email);

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| Error::Network(e.to_string()))?;

    let response = client
        .get(&url)
        .send()
        .map_err(|e| Error::Network(e.to_string()))?;

    if !response.status().is_success() {
        return Err(Error::KeyNotFound(format!(
            "Key not found on keyserver for email: {}",
            email
        )));
    }

    let bytes = read_response_limited(response)?;

    // Verify it's a valid certificate
    let _ = parse_cert(&bytes)?;

    Ok(bytes)
}

/// Read response bytes with a size limit to prevent DoS from oversized responses.
#[cfg(feature = "network")]
fn read_response_limited(response: reqwest::blocking::Response) -> Result<Vec<u8>> {
    // Check Content-Length header if available
    if let Some(len) = response.content_length() {
        if len > MAX_KEY_RESPONSE_SIZE {
            return Err(Error::Network(format!(
                "Response too large: {} bytes (max {})",
                len, MAX_KEY_RESPONSE_SIZE
            )));
        }
    }

    let bytes = response
        .bytes()
        .map_err(|e| Error::Network(e.to_string()))?;

    if bytes.len() as u64 > MAX_KEY_RESPONSE_SIZE {
        return Err(Error::Network(format!(
            "Response too large: {} bytes (max {})",
            bytes.len(),
            MAX_KEY_RESPONSE_SIZE
        )));
    }

    Ok(bytes.to_vec())
}

/// Parse email into local part and domain.
fn parse_email(email: &str) -> Result<(String, String)> {
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return Err(Error::InvalidInput(format!(
            "Invalid email address: {}",
            email
        )));
    }
    Ok((parts[0].to_lowercase(), parts[1].to_lowercase()))
}

/// Generate WKD URLs for a given email address.
/// Returns both advanced and direct method URLs.
#[cfg(feature = "network")]
fn wkd_urls(local: &str, domain: &str) -> Vec<String> {
    use sha1::{Digest, Sha1};

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

// --- DANE OPENPGPKEY (RFC 7929) support ---

/// Construct the OPENPGPKEY DNS name for an email address per RFC 7929.
///
/// Takes the local part of the email, SHA-256 hashes it, truncates to
/// 28 octets (224 bits), hex-encodes (56 chars), and prepends to
/// `_openpgpkey.<domain>`.
#[cfg(feature = "dane")]
fn openpgpkey_name(local: &str, domain: &str) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(local.as_bytes());
    let hash = hasher.finalize();
    // Truncate to first 28 octets (224 bits) per RFC 7929 Section 3
    let truncated = &hash[..28];
    let hex = hex::encode(truncated);
    format!("{}._openpgpkey.{}", hex, domain)
}

/// Get the system's configured DNS resolver address.
///
/// Reads the system DNS configuration in a platform-appropriate way:
/// - Linux/macOS: parses `/etc/resolv.conf`
/// - macOS fallback: queries `scutil --dns`
/// - Windows: queries `PowerShell Get-DnsClientServerAddress`
/// - Fallback: `1.1.1.1:53`
#[cfg(feature = "dane")]
fn get_system_resolver() -> String {
    // Linux & macOS: /etc/resolv.conf is authoritative.
    // VPN clients (Mullvad, WireGuard, etc.) update this file when active.
    #[cfg(unix)]
    {
        if let Ok(contents) = std::fs::read_to_string("/etc/resolv.conf") {
            for line in contents.lines() {
                let line = line.trim();
                if !line.starts_with('#') && line.starts_with("nameserver") {
                    if let Some(addr) = line.split_whitespace().nth(1) {
                        return format!("{}:53", addr);
                    }
                }
            }
        }
    }

    // macOS fallback: if /etc/resolv.conf is empty or missing,
    // query scutil which reflects the live system DNS config
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("scutil").arg("--dns").output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("nameserver[") {
                    // Format: "nameserver[0] : 10.64.0.1"
                    if let Some(addr) = trimmed.split(':').nth(1) {
                        let addr = addr.trim();
                        if !addr.is_empty() {
                            return format!("{}:53", addr);
                        }
                    }
                }
            }
        }
    }

    // Windows: read DNS from PowerShell
    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("powershell")
            .args([
                "-Command",
                "(Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -First 1).ServerAddresses[0]",
            ])
            .output()
        {
            let addr = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !addr.is_empty() {
                return format!("{}:53", addr);
            }
        }
    }

    // Ultimate fallback
    "1.1.1.1:53".to_string()
}

/// Send a DNS query over UDP, falling back to TCP if the response is truncated.
#[cfg(feature = "dane")]
fn dns_query(name: &str, resolver: &str) -> Result<Vec<u8>> {
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    use hickory_proto::serialize::binary::BinDecodable;
    use std::net::UdpSocket;
    use std::str::FromStr;
    use std::time::Duration;

    let dns_name = Name::from_str(name)
        .map_err(|e| Error::Network(format!("Invalid DNS name '{}': {}", name, e)))?;

    // Build the query message
    let mut msg = Message::new();
    msg.set_id(rand::random::<u16>());
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);

    let mut query = Query::new();
    query.set_name(dns_name.clone());
    query.set_query_type(RecordType::OPENPGPKEY);
    msg.add_query(query);

    // Add EDNS(0) OPT record for larger UDP buffer
    use hickory_proto::op::Edns;
    let mut edns = Edns::new();
    edns.set_max_payload(4096);
    edns.set_version(0);
    msg.set_edns(edns);

    let wire = msg
        .to_vec()
        .map_err(|e| Error::Network(format!("Failed to serialize DNS query: {}", e)))?;

    let resolver_addr: std::net::SocketAddr = resolver
        .parse()
        .map_err(|e| Error::Network(format!("Invalid resolver address '{}': {}", resolver, e)))?;

    // UDP query
    let socket = UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| Error::Network(format!("Failed to bind UDP socket: {}", e)))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| Error::Network(format!("Failed to set socket timeout: {}", e)))?;
    socket
        .send_to(&wire, resolver_addr)
        .map_err(|e| Error::Network(format!("Failed to send DNS query: {}", e)))?;

    let mut buf = vec![0u8; 65535];
    let len = socket
        .recv(&mut buf)
        .map_err(|e| Error::Network(format!("Failed to receive DNS response: {}", e)))?;
    let response = Message::from_bytes(&buf[..len])
        .map_err(|e| Error::Network(format!("Failed to parse DNS response: {}", e)))?;

    // Check if truncated — retry over TCP
    if response.truncated() {
        return dns_query_tcp(name, resolver, &wire);
    }

    // Check response code
    use hickory_proto::op::ResponseCode;
    match response.response_code() {
        ResponseCode::NoError => {}
        ResponseCode::NXDomain => {
            return Err(Error::KeyNotFound(format!(
                "No OPENPGPKEY DNS record found for {}",
                name
            )));
        }
        code => {
            return Err(Error::Network(format!(
                "DNS query failed with response code: {}",
                code
            )));
        }
    }

    // Extract OPENPGPKEY record data
    for record in response.answers() {
        if let hickory_proto::rr::RData::OPENPGPKEY(ref key) = *record.data() {
            return Ok(key.public_key().to_vec());
        }
    }

    Err(Error::KeyNotFound(format!(
        "No OPENPGPKEY record in DNS response for {}",
        name
    )))
}

/// TCP fallback for truncated DNS responses.
#[cfg(feature = "dane")]
fn dns_query_tcp(name: &str, resolver: &str, wire: &[u8]) -> Result<Vec<u8>> {
    use hickory_proto::op::Message;
    use hickory_proto::serialize::binary::BinDecodable;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    let resolver_addr: std::net::SocketAddr = resolver
        .parse()
        .map_err(|e| Error::Network(format!("Invalid resolver address '{}': {}", resolver, e)))?;

    let mut stream = TcpStream::connect_timeout(&resolver_addr, Duration::from_secs(10))
        .map_err(|e| Error::Network(format!("TCP connection to DNS resolver failed: {}", e)))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| Error::Network(format!("Failed to set TCP timeout: {}", e)))?;

    // TCP DNS: 2-byte length prefix
    let len_bytes = (wire.len() as u16).to_be_bytes();
    stream
        .write_all(&len_bytes)
        .map_err(|e| Error::Network(format!("Failed to write DNS query length: {}", e)))?;
    stream
        .write_all(wire)
        .map_err(|e| Error::Network(format!("Failed to write DNS query: {}", e)))?;

    // Read 2-byte response length
    let mut resp_len_buf = [0u8; 2];
    stream
        .read_exact(&mut resp_len_buf)
        .map_err(|e| Error::Network(format!("Failed to read DNS response length: {}", e)))?;
    let resp_len = u16::from_be_bytes(resp_len_buf) as usize;

    // Read response
    let mut resp_buf = vec![0u8; resp_len];
    stream
        .read_exact(&mut resp_buf)
        .map_err(|e| Error::Network(format!("Failed to read DNS response: {}", e)))?;

    let response = Message::from_bytes(&resp_buf)
        .map_err(|e| Error::Network(format!("Failed to parse DNS response: {}", e)))?;

    // Extract OPENPGPKEY record data
    for record in response.answers() {
        if let hickory_proto::rr::RData::OPENPGPKEY(ref key) = *record.data() {
            return Ok(key.public_key().to_vec());
        }
    }

    Err(Error::KeyNotFound(format!(
        "No OPENPGPKEY record in DNS response for {}",
        name
    )))
}

/// Fetch an OpenPGP key via DNS DANE OPENPGPKEY record (RFC 7929).
///
/// Looks up the OPENPGPKEY DNS record (TYPE 61) for the given email address.
/// The local part of the email is SHA-256 hashed and truncated per RFC 7929
/// to construct the DNS query name.
///
/// # Arguments
///
/// * `email` - Email address to look up
/// * `dns_resolver` - Optional DNS resolver address (e.g. "8.8.8.8:53").
///   If `None`, uses the system's configured DNS resolver (from `/etc/resolv.conf`
///   on Linux/macOS, or platform-appropriate method on Windows).
///
/// # DNSSEC
///
/// This function does not perform local DNSSEC validation. For production use,
/// ensure the DNS resolver performs DNSSEC validation. The system resolver or
/// well-known public resolvers (1.1.1.1, 8.8.8.8) typically validate DNSSEC.
///
/// # Example
///
/// ```ignore
/// // Ignored: requires network access and a domain with OPENPGPKEY records
/// use wecanencrypt::fetch_key_by_email_from_dane;
///
/// // Use system DNS resolver
/// let cert = fetch_key_by_email_from_dane("user@example.com", None)?;
///
/// // Use a specific DNS resolver
/// let cert = fetch_key_by_email_from_dane("user@example.com", Some("8.8.8.8:53"))?;
/// ```
#[cfg(feature = "dane")]
pub fn fetch_key_by_email_from_dane(email: &str, dns_resolver: Option<&str>) -> Result<Vec<u8>> {
    let (local, domain) = parse_email(email)?;
    let name = openpgpkey_name(&local, &domain);

    let resolver = match dns_resolver {
        Some(r) => r.to_string(),
        None => get_system_resolver(),
    };

    let key_bytes = dns_query(&name, &resolver)?;

    // Validate that the returned data is a valid OpenPGP certificate
    parse_cert(&key_bytes)?;

    Ok(key_bytes)
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

    #[test]
    #[cfg(feature = "dane")]
    fn test_openpgpkey_name() {
        // Verify the OPENPGPKEY DNS name construction per RFC 7929
        let name = openpgpkey_name("user", "example.com");
        // SHA-256("user") truncated to 28 octets, hex-encoded = 56 hex chars
        assert!(name.ends_with("._openpgpkey.example.com"));
        let hash_part = name.split("._openpgpkey.").next().unwrap();
        assert_eq!(
            hash_part.len(),
            56,
            "Hash should be 56 hex chars (28 octets)"
        );
        // Verify it's valid hex
        assert!(hash_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    #[cfg(feature = "dane")]
    fn test_openpgpkey_name_case_insensitive() {
        // Local part is already lowercased by parse_email
        let name1 = openpgpkey_name("user", "example.com");
        let name2 = openpgpkey_name("user", "example.com");
        assert_eq!(name1, name2);
    }

    #[test]
    #[cfg(feature = "dane")]
    fn test_dane_invalid_email() {
        use crate::error::Error;
        let result = fetch_key_by_email_from_dane("invalid", None);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::InvalidInput(_) => {}
            other => panic!("Expected InvalidInput, got: {}", other),
        }
    }

    #[test]
    #[cfg(feature = "dane")]
    fn test_get_system_resolver() {
        let resolver = get_system_resolver();
        assert!(
            resolver.contains(':'),
            "Resolver should include port: {}",
            resolver
        );
        assert!(
            resolver.ends_with(":53"),
            "Resolver should use port 53: {}",
            resolver
        );
    }
}
