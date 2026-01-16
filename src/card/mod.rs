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
//! wecanencrypt = { version = "0.1", features = ["card"] }
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
//!     let info = get_card_details().unwrap();
//!     println!("Card serial: {}", info.serial_number);
//!
//!     // Sign data using the card
//!     let cert = std::fs::read("pubkey.asc").unwrap();
//!     let signature = sign_bytes_detached_on_card(
//!         b"Hello, world!",
//!         &cert,
//!         b"123456",  // User PIN
//!     ).unwrap();
//! }
//! ```

mod types;
mod connection;
mod crypto;
pub mod upload;

pub use types::{KeySlot, TouchMode, CardInfo, CardError};
pub use connection::{
    is_card_connected,
    get_card_details,
    get_card_version,
    get_card_serial,
    verify_user_pin,
    verify_admin_pin,
    get_pin_retry_counters,
    reset_card,
    change_user_pin,
    change_admin_pin,
};
pub use crypto::{
    sign_bytes_detached_on_card,
    decrypt_bytes_on_card,
    update_primary_expiry_on_card,
    update_subkeys_expiry_on_card,
};
pub use upload::{
    upload_key_to_card,
    upload_primary_key_to_card,
    upload_subkey_by_fingerprint,
    CardKeySlot,
    KeySelection,
};
