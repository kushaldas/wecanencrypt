//! Smart card support for OpenPGP operations.
//!
//! This module provides support for YubiKey and other OpenPGP-compatible smart cards.
//! It enables cryptographic operations (signing, decryption) using keys stored on
//! hardware tokens.
//!
//! # Features
//!
//! This module is only available when the `card` feature is enabled:
//!
//! ```toml
//! [dependencies]
//! wecanencrypt = { version = "0.3", features = ["card"] }
//! ```
//!
//! # Requirements
//!
//! - **Linux**: Install `libpcsclite-dev` (Debian/Ubuntu) or `pcsc-lite-devel` (Fedora)
//! - **macOS**: PC/SC framework is built-in
//! - **Windows**: WinSCard is built-in
//!
//! The `pcscd` daemon must be running for card communication.
//!
//! # Example
//!
//! ```no_run
//! use wecanencrypt::card::*;
//!
//! // Check if a card is connected
//! if is_card_connected() {
//!     // Get card details
//!     let info = get_card_details(None).unwrap();
//!     println!("Card serial: {}", info.serial_number);
//!
//!     // Sign data using the card
//!     let key = std::fs::read("pubkey.asc").unwrap();
//!     let signature = sign_bytes_detached_on_card(
//!         b"Hello, world!",
//!         &key,
//!         b"123456",  // User PIN
//!     ).unwrap();
//! }
//! ```
//!
//! # Touch Policy (YubiKey 4.2+)
//!
//! You can configure touch policies for cryptographic operations using [`set_touch_mode`].
//! This requires physical touch confirmation before each operation, providing additional
//! security against remote attackers.
//!
//! ```no_run
//! use wecanencrypt::card::{set_touch_mode, KeySlot, TouchMode};
//!
//! // Require touch for signing (can be changed later)
//! set_touch_mode(KeySlot::Signature, TouchMode::On, b"12345678", None).unwrap();
//!
//! // Permanently require touch for decryption (cannot be changed!)
//! set_touch_mode(KeySlot::Encryption, TouchMode::Fixed, b"12345678", None).unwrap();
//!
//! // Require touch for authentication
//! set_touch_mode(KeySlot::Authentication, TouchMode::On, b"12345678", None).unwrap();
//! ```
//!
//! **Warning**: Setting `TouchMode::Fixed` or `TouchMode::CachedFixed` is permanent
//! on some devices (like YubiKey) and cannot be changed even with a factory reset!

mod connection;
mod crypto;
#[cfg(feature = "card-external")]
pub mod external;
mod types;
pub mod upload;

pub use connection::{
    change_admin_pin, change_user_pin, get_card_details, get_card_serial, get_card_version,
    get_pin_retry_counters, get_touch_modes, reset_card, set_cardholder_name, set_public_key_url,
    set_touch_mode, verify_admin_pin, verify_user_pin,
};

// PCSC-only enumeration APIs. Mobile (`card-external`) builds omit these —
// the UI drives sessions explicitly through the backend provider.
#[cfg(feature = "card-pcsc")]
pub use connection::{find_cards_for_key, is_card_connected, list_all_cards};

pub use types::{CardError, CardInfo, CardKeyMatch, CardSummary, KeySlot, SlotMatch, TouchMode};
// Re-export get_card_backend for use by crypto module
pub(crate) use connection::get_card_backend;
pub use crypto::{
    decrypt_and_verify_on_card, decrypt_bytes_on_card, sign_and_encrypt_to_multiple_on_card,
    sign_bytes_detached_on_card, sign_text_cleartext_on_card, ssh_authenticate_for_hash_on_card,
    ssh_authenticate_on_card, update_primary_expiry_on_card, update_subkeys_expiry_on_card,
};
// Re-export Hash for callers of ssh_authenticate_for_hash_on_card
pub use openpgp_card::ocard::crypto::Hash as CardHash;
pub use upload::{
    upload_key_to_card, upload_primary_key_to_card, upload_subkey_by_fingerprint, CardKeySlot,
    KeySelection,
};
