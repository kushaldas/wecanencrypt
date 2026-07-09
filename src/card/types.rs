//! Data types returned by OpenPGP smart-card helpers.
//!
//! These structs and enums describe connected cards, slot matches, touch
//! policies, and card-specific errors without exposing `openpgp-card` internals
//! to callers. They are used by both desktop PC/SC transports and external
//! mobile/custom backends.

/// Key slot identifiers on an OpenPGP smart card.
///
/// Each slot can hold one key for a specific purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySlot {
    /// Signature key slot
    Signature,
    /// Encryption/Decryption key slot
    Encryption,
    /// Authentication key slot
    Authentication,
}

/// Touch policy modes for YubiKey operations.
///
/// These control whether physical touch is required for cryptographic operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchMode {
    /// Touch is not required
    Off,
    /// Touch is required for each operation
    On,
    /// Touch is required and cannot be changed
    Fixed,
    /// Touch is cached for 15 seconds
    Cached,
    /// Touch is cached and cannot be changed
    CachedFixed,
}

/// Brief summary of a connected card, returned by `list_all_cards()`.
#[derive(Debug, Clone)]
pub struct CardSummary {
    /// Unique identifier: "MANUFACTURER:SERIAL" (e.g. "0006:00000001")
    pub ident: String,
    /// Human-readable manufacturer name (e.g. "Yubico AB")
    pub manufacturer_name: String,
    /// Serial number as hex string
    pub serial_number: String,
    /// Cardholder name if set
    pub cardholder_name: Option<String>,
}

/// Information about a connected OpenPGP smart card.
#[derive(Debug, Clone, Default)]
pub struct CardInfo {
    /// Unique identifier: "MANUFACTURER:SERIAL" (e.g. "0006:00000001")
    pub ident: String,
    /// Serial number of the card
    pub serial_number: String,
    /// Cardholder name (if set)
    pub cardholder_name: Option<String>,
    /// URL for public key retrieval (if set)
    pub public_key_url: Option<String>,
    /// Fingerprint of the signature key (if present)
    pub signature_fingerprint: Option<String>,
    /// Fingerprint of the encryption key (if present)
    pub encryption_fingerprint: Option<String>,
    /// Fingerprint of the authentication key (if present)
    pub authentication_fingerprint: Option<String>,
    /// Number of signatures made with the signature key
    pub signature_counter: u32,
    /// Remaining PIN retry attempts for user PIN (PW1)
    pub pin_retry_counter: u8,
    /// Remaining retry attempts for reset code (RC)
    pub reset_code_retry_counter: u8,
    /// Remaining PIN retry attempts for admin PIN (PW3)
    pub admin_pin_retry_counter: u8,
    /// Card manufacturer code (hex)
    pub manufacturer: Option<String>,
    /// Human-readable manufacturer name
    pub manufacturer_name: Option<String>,
}

/// Describes which slot on a card matches a key fingerprint.
#[derive(Debug, Clone)]
pub struct SlotMatch {
    /// Which slot on the card holds a matching key
    pub slot: KeySlot,
    /// The fingerprint stored in that slot (lowercase hex)
    pub fingerprint: String,
}

/// A connected card that holds one or more keys from a key.
#[derive(Debug, Clone)]
pub struct CardKeyMatch {
    /// Full card details
    pub card: CardInfo,
    /// Slots that match fingerprints from the queried key
    pub matching_slots: Vec<SlotMatch>,
}

/// Errors specific to smart card operations.
#[derive(Debug, Clone)]
pub enum CardError {
    /// No smart card is connected
    NotConnected,
    /// Failed to select the OpenPGP applet
    SelectFailed,
    /// The PIN has been blocked due to too many failed attempts
    PinBlocked,
    /// The PIN is incorrect
    PinIncorrect {
        /// Number of retry attempts remaining
        retries_remaining: u8,
    },
    /// Admin PIN is required for this operation
    AdminPinRequired,
    /// The specified key slot is empty
    KeyNotPresent(KeySlot),
    /// The algorithm is not supported by the card
    UnsupportedAlgorithm(String),
    /// Communication error with the card
    CommunicationError(String),
    /// Invalid data received from the card
    InvalidData(String),
    /// Operation timed out (e.g., waiting for touch)
    Timeout,
    /// Card operation error
    CardError(String),
}

impl std::fmt::Display for CardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CardError::NotConnected => write!(f, "No smart card connected"),
            CardError::SelectFailed => write!(f, "Failed to select OpenPGP applet"),
            CardError::PinBlocked => write!(f, "PIN is blocked"),
            CardError::PinIncorrect { retries_remaining } => {
                write!(f, "PIN incorrect, {} retries remaining", retries_remaining)
            }
            CardError::AdminPinRequired => write!(f, "Admin PIN required"),
            CardError::KeyNotPresent(slot) => write!(f, "Key not present in slot {:?}", slot),
            CardError::UnsupportedAlgorithm(algo) => {
                write!(f, "Algorithm not supported: {}", algo)
            }
            CardError::CommunicationError(msg) => write!(f, "Communication error: {}", msg),
            CardError::InvalidData(msg) => write!(f, "Invalid data: {}", msg),
            CardError::Timeout => write!(f, "Operation timed out"),
            CardError::CardError(msg) => write!(f, "Card error: {}", msg),
        }
    }
}

impl std::error::Error for CardError {}

/// Convert openpgp-card errors to CardError
#[cfg(feature = "card")]
impl From<openpgp_card::Error> for CardError {
    fn from(err: openpgp_card::Error) -> Self {
        let msg = format!("{}", err);
        // Check for common PIN-related error patterns
        if msg.contains("6983") || msg.contains("blocked") {
            CardError::PinBlocked
        } else if msg.contains("63C") {
            // Try to extract retry count from error message
            CardError::PinIncorrect {
                retries_remaining: 3,
            }
        } else {
            CardError::CardError(msg)
        }
    }
}
