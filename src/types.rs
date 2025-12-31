//! Public type definitions for the wecanencrypt library.
//!
//! This module contains all the data structures used throughout the library
//! for representing certificates, keys, and their properties.

use chrono::{DateTime, Utc};

/// Cipher suite options for key generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CipherSuite {
    /// RSA with 2048-bit keys
    Rsa2k,
    /// RSA with 4096-bit keys
    Rsa4k,
    /// Curve25519 legacy format (EdDSA for signing, ECDH for encryption)
    /// This is the pre-RFC 9580 format, widely compatible.
    #[default]
    Cv25519,
    /// Modern Curve25519 (Ed25519 for signing, X25519 for encryption)
    /// RFC 9580 native format - better security properties but less compatible.
    Cv25519Modern,
    /// NIST P-256 curve (ECDSA for signing, ECDH for encryption)
    NistP256,
    /// NIST P-384 curve (ECDSA for signing, ECDH for encryption)
    NistP384,
    /// NIST P-521 curve (ECDSA for signing, ECDH for encryption)
    NistP521,
}

impl std::str::FromStr for CipherSuite {
    type Err = String;

    /// Parse cipher suite from string (case-insensitive).
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "rsa2k" | "rsa2048" => Ok(CipherSuite::Rsa2k),
            "rsa4k" | "rsa4096" => Ok(CipherSuite::Rsa4k),
            "cv25519" | "curve25519" | "ed25519" | "ed25519legacy" => Ok(CipherSuite::Cv25519),
            "cv25519modern" | "curve25519modern" | "x25519" => Ok(CipherSuite::Cv25519Modern),
            "nistp256" | "p256" | "secp256r1" => Ok(CipherSuite::NistP256),
            "nistp384" | "p384" | "secp384r1" => Ok(CipherSuite::NistP384),
            "nistp521" | "p521" | "secp521r1" => Ok(CipherSuite::NistP521),
            _ => Err(format!("unknown cipher suite: {}", s)),
        }
    }
}

impl CipherSuite {
    /// Get a human-readable name for the cipher suite.
    pub fn name(&self) -> &'static str {
        match self {
            CipherSuite::Rsa2k => "RSA 2048",
            CipherSuite::Rsa4k => "RSA 4096",
            CipherSuite::Cv25519 => "Curve25519 (Legacy)",
            CipherSuite::Cv25519Modern => "Curve25519 (Modern)",
            CipherSuite::NistP256 => "NIST P-256",
            CipherSuite::NistP384 => "NIST P-384",
            CipherSuite::NistP521 => "NIST P-521",
        }
    }
}

/// Flags indicating which subkeys to generate or operate on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubkeyFlags {
    /// Generate/use encryption subkey
    pub encryption: bool,
    /// Generate/use signing subkey
    pub signing: bool,
    /// Generate/use authentication subkey
    pub authentication: bool,
}

impl SubkeyFlags {
    /// Create flags with all subkeys enabled.
    pub fn all() -> Self {
        Self {
            encryption: true,
            signing: true,
            authentication: true,
        }
    }

    /// Create flags with only encryption enabled.
    pub fn encryption_only() -> Self {
        Self {
            encryption: true,
            signing: false,
            authentication: false,
        }
    }

    /// Create flags with only signing enabled.
    pub fn signing_only() -> Self {
        Self {
            encryption: false,
            signing: true,
            authentication: false,
        }
    }

    /// Create flags from a bitmask (1=encryption, 2=signing, 4=authentication).
    pub fn from_bitmask(mask: u8) -> Self {
        Self {
            encryption: (mask & 1) != 0,
            signing: (mask & 2) != 0,
            authentication: (mask & 4) != 0,
        }
    }

    /// Convert to bitmask representation.
    pub fn to_bitmask(&self) -> u8 {
        let mut mask = 0u8;
        if self.encryption {
            mask |= 1;
        }
        if self.signing {
            mask |= 2;
        }
        if self.authentication {
            mask |= 4;
        }
        mask
    }
}

impl Default for SubkeyFlags {
    fn default() -> Self {
        Self::all()
    }
}

/// The type/purpose of a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// Key can be used for encryption
    Encryption,
    /// Key can be used for signing
    Signing,
    /// Key can be used for authentication
    Authentication,
    /// Key can be used for certification (primary keys)
    Certification,
    /// Unknown or unrecognized key type
    Unknown,
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyType::Encryption => write!(f, "encryption"),
            KeyType::Signing => write!(f, "signing"),
            KeyType::Authentication => write!(f, "authentication"),
            KeyType::Certification => write!(f, "certification"),
            KeyType::Unknown => write!(f, "unknown"),
        }
    }
}

/// Information about a subkey.
#[derive(Debug, Clone)]
pub struct SubkeyInfo {
    /// Short key ID (last 16 hex characters of fingerprint)
    pub key_id: String,
    /// Full fingerprint as hex string
    pub fingerprint: String,
    /// When the subkey was created
    pub creation_time: DateTime<Utc>,
    /// When the subkey expires (None if never)
    pub expiration_time: Option<DateTime<Utc>>,
    /// The purpose of this subkey
    pub key_type: KeyType,
    /// Whether this subkey has been revoked
    pub is_revoked: bool,
    /// Algorithm name (e.g., "RSA", "EdDSA", "ECDH")
    pub algorithm: String,
    /// Key size in bits (e.g., 4096 for RSA, 256 for Curve25519)
    pub bit_length: usize,
}

/// Parsed certificate information.
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    /// List of User IDs associated with this certificate
    pub user_ids: Vec<String>,
    /// Primary key fingerprint as hex string
    pub fingerprint: String,
    /// Short key ID (last 16 hex characters)
    pub key_id: String,
    /// Whether this certificate contains secret key material
    pub is_secret: bool,
    /// When the certificate was created
    pub creation_time: DateTime<Utc>,
    /// When the certificate expires (None if never)
    pub expiration_time: Option<DateTime<Utc>>,
    /// Whether the primary key can sign
    pub can_primary_sign: bool,
    /// Information about all subkeys
    pub subkeys: Vec<SubkeyInfo>,
}

/// Detailed cipher information for a key component.
#[derive(Debug, Clone)]
pub struct KeyCipherDetails {
    /// Fingerprint of this key/subkey
    pub fingerprint: String,
    /// Algorithm name
    pub algorithm: String,
    /// Key size in bits
    pub bit_length: usize,
}

/// Result of key generation.
#[derive(Debug)]
pub struct GeneratedKey {
    /// ASCII-armored public key
    pub public_key: String,
    /// Binary secret key data
    pub secret_key: Vec<u8>,
    /// Key fingerprint as hex string
    pub fingerprint: String,
}

/// Certification types for key signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CertificationType {
    /// Generic certification (0x10)
    Generic = 0,
    /// Persona certification - no verification done (0x11)
    Persona = 1,
    /// Casual certification - some verification (0x12)
    Casual = 2,
    /// Positive certification - thorough verification (0x13)
    Positive = 3,
}

impl CertificationType {
    /// Convert to the OpenPGP signature type value.
    pub fn to_signature_type(self) -> u8 {
        match self {
            CertificationType::Generic => 0x10,
            CertificationType::Persona => 0x11,
            CertificationType::Casual => 0x12,
            CertificationType::Positive => 0x13,
        }
    }
}

/// RSA public key components for external verification.
#[derive(Debug, Clone)]
pub struct RsaPublicKey {
    /// Modulus as hex string
    pub n: String,
    /// Public exponent as hex string
    pub e: String,
}

/// Public key for signing verification (algorithm-specific).
#[derive(Debug, Clone)]
pub enum SigningPublicKey {
    /// RSA signing key
    Rsa(RsaPublicKey),
    /// Ed25519 signing key
    Ed25519 {
        /// Public key bytes as hex string
        public: String,
    },
    /// ECDSA signing key
    Ecdsa {
        /// Curve name (e.g., "nistp256", "nistp384")
        curve: String,
        /// Public point as hex string
        point: String,
    },
}

/// Information about an available (valid, non-expired, non-revoked) subkey.
#[derive(Debug, Clone)]
pub struct AvailableSubkey {
    /// Full fingerprint as hex string
    pub fingerprint: String,
    /// Short key ID (last 16 hex characters)
    pub key_id: String,
    /// When the subkey was created
    pub creation_time: DateTime<Utc>,
    /// When the subkey expires (None if never)
    pub expiration_time: Option<DateTime<Utc>>,
    /// The purpose of this subkey
    pub key_type: KeyType,
    /// Algorithm name
    pub algorithm: String,
    /// Key size in bits
    pub bit_length: usize,
}

// rpgp type conversions

impl CipherSuite {
    /// Get the rpgp KeyType for the primary key (signing/certification).
    pub fn primary_key_type(&self) -> crate::pgp::composed::KeyType {
        match self {
            CipherSuite::Rsa2k => crate::pgp::composed::KeyType::Rsa(2048),
            CipherSuite::Rsa4k => crate::pgp::composed::KeyType::Rsa(4096),
            CipherSuite::Cv25519 => crate::pgp::composed::KeyType::Ed25519Legacy,
            CipherSuite::Cv25519Modern => crate::pgp::composed::KeyType::Ed25519,
            CipherSuite::NistP256 => {
                crate::pgp::composed::KeyType::ECDSA(crate::pgp::crypto::ecc_curve::ECCCurve::P256)
            }
            CipherSuite::NistP384 => {
                crate::pgp::composed::KeyType::ECDSA(crate::pgp::crypto::ecc_curve::ECCCurve::P384)
            }
            CipherSuite::NistP521 => {
                crate::pgp::composed::KeyType::ECDSA(crate::pgp::crypto::ecc_curve::ECCCurve::P521)
            }
        }
    }

    /// Get the rpgp KeyType for encryption subkeys.
    pub fn encryption_key_type(&self) -> crate::pgp::composed::KeyType {
        match self {
            CipherSuite::Rsa2k => crate::pgp::composed::KeyType::Rsa(2048),
            CipherSuite::Rsa4k => crate::pgp::composed::KeyType::Rsa(4096),
            CipherSuite::Cv25519 => {
                crate::pgp::composed::KeyType::ECDH(crate::pgp::crypto::ecc_curve::ECCCurve::Curve25519)
            }
            CipherSuite::Cv25519Modern => crate::pgp::composed::KeyType::X25519,
            CipherSuite::NistP256 => {
                crate::pgp::composed::KeyType::ECDH(crate::pgp::crypto::ecc_curve::ECCCurve::P256)
            }
            CipherSuite::NistP384 => {
                crate::pgp::composed::KeyType::ECDH(crate::pgp::crypto::ecc_curve::ECCCurve::P384)
            }
            CipherSuite::NistP521 => {
                crate::pgp::composed::KeyType::ECDH(crate::pgp::crypto::ecc_curve::ECCCurve::P521)
            }
        }
    }
}
