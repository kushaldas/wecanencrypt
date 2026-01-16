//! Smart card connection and management functions.
//!
//! This module provides functions for connecting to and managing OpenPGP smart cards.

use card_backend_pcsc::PcscBackend;
use openpgp_card::Card;
use secrecy::SecretString;

use super::types::{CardError, CardInfo};
use crate::error::{Error, Result};

/// Check if an OpenPGP smart card is connected.
///
/// # Returns
///
/// `true` if at least one OpenPGP-compatible smart card is connected.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::card::is_card_connected;
///
/// if is_card_connected() {
///     println!("Smart card detected!");
/// }
/// ```
pub fn is_card_connected() -> bool {
    match PcscBackend::cards(None) {
        Ok(mut cards) => cards.next().is_some(),
        Err(_) => false,
    }
}

/// Get the first available card backend.
fn get_card_backend() -> Result<PcscBackend> {
    let mut cards = PcscBackend::cards(None)
        .map_err(|e| Error::Card(CardError::CommunicationError(e.to_string())))?;

    cards.next()
        .ok_or(Error::Card(CardError::NotConnected))?
        .map_err(|e| Error::Card(CardError::CommunicationError(e.to_string())))
}

/// Convert a PIN byte slice to SecretString.
fn pin_to_secret(pin: &[u8]) -> Result<SecretString> {
    let pin_str = std::str::from_utf8(pin)
        .map_err(|_| Error::Card(CardError::InvalidData("PIN must be valid UTF-8".to_string())))?;
    Ok(SecretString::new(pin_str.to_string()))
}

/// Get detailed information about the connected smart card.
///
/// # Returns
///
/// A [`CardInfo`] struct containing card details like serial number,
/// fingerprints, and retry counters.
///
/// # Errors
///
/// * [`CardError::NotConnected`] - If no card is connected
/// * [`CardError::SelectFailed`] - If the OpenPGP applet cannot be selected
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::card::get_card_details;
///
/// let info = get_card_details().unwrap();
/// println!("Card serial: {}", info.serial_number);
/// println!("PIN retries: {}", info.pin_retry_counter);
/// ```
pub fn get_card_details() -> Result<CardInfo> {
    let backend = get_card_backend()?;
    let mut card = Card::new(backend)
        .map_err(|e| Error::Card(CardError::from(e)))?;

    let mut tx = card.transaction()
        .map_err(|e| Error::Card(CardError::from(e)))?;

    let mut info = CardInfo::default();

    // Get application identifier (serial number and manufacturer)
    if let Ok(aid) = tx.application_identifier() {
        info.serial_number = format!("{:08X}", aid.serial());
        info.manufacturer = Some(format!("{:04X}", aid.manufacturer()));
    }

    // Key fingerprints
    if let Ok(fps) = tx.fingerprints() {
        if let Some(fp) = fps.signature() {
            info.signature_fingerprint = Some(hex::encode(fp.as_bytes()));
        }
        if let Some(fp) = fps.decryption() {
            info.encryption_fingerprint = Some(hex::encode(fp.as_bytes()));
        }
        if let Some(fp) = fps.authentication() {
            info.authentication_fingerprint = Some(hex::encode(fp.as_bytes()));
        }
    }

    // PIN retry counters
    if let Ok(status) = tx.pw_status_bytes() {
        info.pin_retry_counter = status.err_count_pw1();
        info.reset_code_retry_counter = status.err_count_rc();
        info.admin_pin_retry_counter = status.err_count_pw3();
    }

    // Cardholder name (may return empty string)
    if let Ok(name) = tx.cardholder_name() {
        if !name.is_empty() {
            info.cardholder_name = Some(name);
        }
    }

    // Public key URL (may return empty string)
    if let Ok(url) = tx.url() {
        if !url.is_empty() {
            info.public_key_url = Some(url);
        }
    }

    Ok(info)
}

/// Get the firmware version of the connected card.
///
/// # Returns
///
/// A version string like "5.4" for YubiKey.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::card::get_card_version;
///
/// let version = get_card_version().unwrap();
/// println!("Firmware: {}", version);
/// ```
pub fn get_card_version() -> Result<String> {
    let backend = get_card_backend()?;
    let mut card = Card::new(backend)
        .map_err(|e| Error::Card(CardError::from(e)))?;

    let tx = card.transaction()
        .map_err(|e| Error::Card(CardError::from(e)))?;

    let aid = tx.application_identifier()
        .map_err(|e| Error::Card(CardError::from(e)))?;

    // Version is packed as major.minor in a u16 (major in upper byte, minor in lower)
    let version = aid.version();
    let major = version >> 8;
    let minor = version & 0xFF;
    Ok(format!("{}.{}", major, minor))
}

/// Get the serial number of the connected card.
///
/// # Returns
///
/// The card's serial number as a hex string.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::card::get_card_serial;
///
/// let serial = get_card_serial().unwrap();
/// println!("Serial: {}", serial);
/// ```
pub fn get_card_serial() -> Result<String> {
    let backend = get_card_backend()?;
    let mut card = Card::new(backend)
        .map_err(|e| Error::Card(CardError::from(e)))?;

    let tx = card.transaction()
        .map_err(|e| Error::Card(CardError::from(e)))?;

    let aid = tx.application_identifier()
        .map_err(|e| Error::Card(CardError::from(e)))?;

    Ok(format!("{:08X}", aid.serial()))
}

/// Verify the user PIN (PW1) for signing operations.
///
/// # Arguments
///
/// * `pin` - The user PIN (typically 6-8 digits)
///
/// # Returns
///
/// `true` if the PIN is correct.
///
/// # Errors
///
/// * [`CardError::PinIncorrect`] - If the PIN is wrong (includes retry count)
/// * [`CardError::PinBlocked`] - If the PIN has been blocked
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::card::verify_user_pin;
///
/// match verify_user_pin(b"123456") {
///     Ok(true) => println!("PIN verified"),
///     Err(e) => println!("PIN error: {}", e),
///     _ => {}
/// }
/// ```
pub fn verify_user_pin(pin: &[u8]) -> Result<bool> {
    let backend = get_card_backend()?;
    let mut card = Card::new(backend)
        .map_err(|e| Error::Card(CardError::from(e)))?;

    let mut tx = card.transaction()
        .map_err(|e| Error::Card(CardError::from(e)))?;

    let secret_pin = pin_to_secret(pin)?;
    tx.verify_user_pin(secret_pin)
        .map_err(|e| Error::Card(CardError::from(e)))?;

    Ok(true)
}

/// Verify the admin PIN (PW3).
///
/// # Arguments
///
/// * `pin` - The admin PIN (typically 8 digits, default "12345678")
///
/// # Returns
///
/// `true` if the PIN is correct.
///
/// # Errors
///
/// * [`CardError::PinIncorrect`] - If the PIN is wrong
/// * [`CardError::PinBlocked`] - If the PIN has been blocked
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::card::verify_admin_pin;
///
/// match verify_admin_pin(b"12345678") {
///     Ok(true) => println!("Admin PIN verified"),
///     Err(e) => println!("Admin PIN error: {}", e),
///     _ => {}
/// }
/// ```
pub fn verify_admin_pin(pin: &[u8]) -> Result<bool> {
    let backend = get_card_backend()?;
    let mut card = Card::new(backend)
        .map_err(|e| Error::Card(CardError::from(e)))?;

    let mut tx = card.transaction()
        .map_err(|e| Error::Card(CardError::from(e)))?;

    let secret_pin = pin_to_secret(pin)?;
    tx.verify_admin_pin(secret_pin)
        .map_err(|e| Error::Card(CardError::from(e)))?;

    Ok(true)
}

/// Get the current PIN retry counters.
///
/// # Returns
///
/// A tuple of (user_pin_retries, reset_code_retries, admin_pin_retries).
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::card::get_pin_retry_counters;
///
/// let (user, reset, admin) = get_pin_retry_counters().unwrap();
/// println!("User PIN retries: {}", user);
/// println!("Admin PIN retries: {}", admin);
/// ```
pub fn get_pin_retry_counters() -> Result<(u8, u8, u8)> {
    let backend = get_card_backend()?;
    let mut card = Card::new(backend)
        .map_err(|e| Error::Card(CardError::from(e)))?;

    let mut tx = card.transaction()
        .map_err(|e| Error::Card(CardError::from(e)))?;

    let status = tx.pw_status_bytes()
        .map_err(|e| Error::Card(CardError::from(e)))?;

    Ok((
        status.err_count_pw1(),
        status.err_count_rc(),
        status.err_count_pw3(),
    ))
}

/// Reset the card to factory defaults.
///
/// This operation requires the admin PIN to be blocked first (by entering
/// it incorrectly 3 times), then the reset code or a factory reset command.
///
/// # Warning
///
/// This will erase all keys and reset all PINs to defaults.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::card::reset_card;
///
/// // Only works if admin PIN is blocked
/// reset_card().unwrap();
/// ```
pub fn reset_card() -> Result<()> {
    let backend = get_card_backend()?;
    let mut card = Card::new(backend)
        .map_err(|e| Error::Card(CardError::from(e)))?;

    let mut tx = card.transaction()
        .map_err(|e| Error::Card(CardError::from(e)))?;

    tx.factory_reset()
        .map_err(|e| Error::Card(CardError::from(e)))?;

    Ok(())
}

/// Change the user PIN (PW1).
///
/// # Arguments
///
/// * `old_pin` - The current user PIN
/// * `new_pin` - The new user PIN (must be 6-127 bytes)
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::card::change_user_pin;
///
/// change_user_pin(b"123456", b"654321").unwrap();
/// ```
pub fn change_user_pin(old_pin: &[u8], new_pin: &[u8]) -> Result<()> {
    let backend = get_card_backend()?;
    let mut card = Card::new(backend)
        .map_err(|e| Error::Card(CardError::from(e)))?;

    let mut tx = card.transaction()
        .map_err(|e| Error::Card(CardError::from(e)))?;

    let old_secret = pin_to_secret(old_pin)?;
    let new_secret = pin_to_secret(new_pin)?;
    tx.change_user_pin(old_secret, new_secret)
        .map_err(|e| Error::Card(CardError::from(e)))?;

    Ok(())
}

/// Change the admin PIN (PW3).
///
/// # Arguments
///
/// * `old_pin` - The current admin PIN
/// * `new_pin` - The new admin PIN (must be 8-127 bytes)
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::card::change_admin_pin;
///
/// change_admin_pin(b"12345678", b"87654321").unwrap();
/// ```
pub fn change_admin_pin(old_pin: &[u8], new_pin: &[u8]) -> Result<()> {
    let backend = get_card_backend()?;
    let mut card = Card::new(backend)
        .map_err(|e| Error::Card(CardError::from(e)))?;

    let mut tx = card.transaction()
        .map_err(|e| Error::Card(CardError::from(e)))?;

    let old_secret = pin_to_secret(old_pin)?;
    let new_secret = pin_to_secret(new_pin)?;
    tx.change_admin_pin(old_secret, new_secret)
        .map_err(|e| Error::Card(CardError::from(e)))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    // Tests require a physical card or virtual card via pcscd
    // Run with: cargo test --features card -- --ignored
}
