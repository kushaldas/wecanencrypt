//! Smart card connection and management functions.
//!
//! This module provides functions for connecting to and managing OpenPGP smart cards.
//! All functions accept an optional `ident` parameter to select a specific card
//! when multiple cards are connected. The ident format is `"MANUFACTURER:SERIAL"`
//! (e.g. `"0006:00000001"` for a Yubico card). If `None`, the first available card is used.

use card_backend::CardBackend;
#[cfg(feature = "card-pcsc")]
use card_backend_pcsc::PcscBackend;
use openpgp_card::ocard::{data::UserInteractionFlag, OpenPGP};
use openpgp_card::Card;
use secrecy::{SecretBox, SecretString};

#[allow(unused_imports)]
use super::types::{CardError, CardInfo, CardKeyMatch, CardSummary, KeySlot, SlotMatch, TouchMode};
use crate::error::{Error, Result};

/// Check if an OpenPGP smart card is connected.
///
/// **PCSC-only.** Enumeration is a desktop / PC/SC concept; mobile
/// (`card-external`) builds don't expose this function — they establish
/// card sessions explicitly via their registered backend provider.
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
#[cfg(feature = "card-pcsc")]
pub fn is_card_connected() -> bool {
    match PcscBackend::cards(None) {
        Ok(mut cards) => cards.next().is_some(),
        Err(_) => false,
    }
}

/// List all connected OpenPGP smart cards.
///
/// **PCSC-only.** See [`is_card_connected`] for the rationale.
///
/// Returns a summary for each connected card including the ident
/// (manufacturer:serial), manufacturer name, and serial number.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::card::list_all_cards;
///
/// let cards = list_all_cards().unwrap();
/// for card in &cards {
///     println!("{} ({})", card.manufacturer_name, card.ident);
/// }
/// ```
#[cfg(feature = "card-pcsc")]
pub fn list_all_cards() -> Result<Vec<CardSummary>> {
    let cards = PcscBackend::cards(None)
        .map_err(|e| Error::Card(CardError::CommunicationError(e.to_string())))?;

    let mut result = Vec::new();

    for backend in cards {
        let backend = match backend {
            Ok(b) => b,
            Err(_) => continue,
        };

        let mut card = match Card::new(backend) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let mut tx = match card.transaction() {
            Ok(t) => t,
            Err(_) => continue,
        };

        if let Ok(aid) = tx.application_identifier() {
            let ident = aid.ident();
            let manufacturer_name = aid.manufacturer_name().to_string();
            let serial_number = format!("{:08X}", aid.serial());
            let cardholder_name = tx.cardholder_name().ok().filter(|n| !n.is_empty());

            result.push(CardSummary {
                ident,
                manufacturer_name,
                serial_number,
                cardholder_name,
            });
        }
    }

    Ok(result)
}

/// Get a card backend, optionally selecting by ident.
///
/// If `ident` is `None`, returns the first available card. If `ident` is
/// `Some`, finds the card matching the given ident string.
///
/// The implementation dispatches on Cargo features:
///
/// - With `card-pcsc` — enumerate via PC/SC and box the selected
///   [`PcscBackend`] as [`Box<dyn CardBackend + Send + Sync>`].
/// - With `card-external` (and without `card-pcsc`) — call the provider
///   callback registered via
///   [`super::external::set_backend_provider`].
///
/// If both features are enabled, `card-pcsc` wins (desktop behavior).
pub(crate) fn get_card_backend(
    ident: Option<&str>,
) -> Result<Box<dyn CardBackend + Send + Sync>> {
    #[cfg(feature = "card-pcsc")]
    {
        return get_card_backend_pcsc(ident).map(|b| -> Box<dyn CardBackend + Send + Sync> {
            Box::new(b)
        });
    }
    #[cfg(all(feature = "card-external", not(feature = "card-pcsc")))]
    {
        return super::external::invoke_provider(ident);
    }
    #[cfg(not(any(feature = "card-pcsc", feature = "card-external")))]
    {
        let _ = ident;
        Err(Error::Card(CardError::CommunicationError(
            "no card transport enabled — build wecanencrypt with either \
             `card-pcsc` (desktop) or `card-external` (mobile) feature"
                .to_string(),
        )))
    }
}

/// PC/SC-backed card selection. Returns a concrete `PcscBackend` so the
/// caller can decide whether to box it or use it directly.
#[cfg(feature = "card-pcsc")]
fn get_card_backend_pcsc(ident: Option<&str>) -> Result<PcscBackend> {
    match ident {
        None => {
            let mut cards = PcscBackend::cards(None)
                .map_err(|e| Error::Card(CardError::CommunicationError(e.to_string())))?;
            cards
                .next()
                .ok_or(Error::Card(CardError::NotConnected))?
                .map_err(|e| Error::Card(CardError::CommunicationError(e.to_string())))
        }
        Some(target_ident) => {
            // Use PcscBackend::cards with ident filter
            // Iterate all cards, find the one with matching ident
            let target = target_ident.to_ascii_uppercase();
            let cards = PcscBackend::cards(None)
                .map_err(|e| Error::Card(CardError::CommunicationError(e.to_string())))?;

            for backend in cards {
                let backend = match backend {
                    Ok(b) => b,
                    Err(_) => continue,
                };

                // Probe this backend to check its ident
                let mut card = match Card::new(backend) {
                    Ok(c) => c,
                    Err(_) => continue,
                };

                let card_ident = {
                    let tx = match card.transaction() {
                        Ok(t) => t,
                        Err(_) => continue,
                    };
                    match tx.application_identifier() {
                        Ok(aid) => aid.ident(),
                        Err(_) => continue,
                    }
                };

                if card_ident == target {
                    // Found the matching card. Drop and re-open to get a fresh backend.
                    drop(card);
                    // Re-enumerate and find the same card
                    let cards2 = PcscBackend::cards(None)
                        .map_err(|e| Error::Card(CardError::CommunicationError(e.to_string())))?;
                    for b2 in cards2 {
                        let b2 = match b2 {
                            Ok(b) => b,
                            Err(_) => continue,
                        };
                        // Check this is the right one
                        let mut c2 = match Card::new(b2) {
                            Ok(c) => c,
                            Err(_) => continue,
                        };
                        let matches = {
                            let tx2 = match c2.transaction() {
                                Ok(t) => t,
                                Err(_) => continue,
                            };
                            tx2.application_identifier()
                                .map(|aid| aid.ident() == target)
                                .unwrap_or(false)
                        };
                        if matches {
                            // Drop Card so the backend is free, re-open one more time
                            drop(c2);
                            let cards3 = PcscBackend::cards(None).map_err(|e| {
                                Error::Card(CardError::CommunicationError(e.to_string()))
                            })?;
                            if let Some(b3) = cards3.flatten().next() {
                                return Ok(b3);
                            }
                        }
                    }
                    return Err(Error::Card(CardError::NotConnected));
                }
            }
            Err(Error::Card(CardError::CommunicationError(format!(
                "Card with ident '{}' not found",
                target_ident
            ))))
        }
    }
}

/// Convert a PIN byte slice to SecretString, zeroizing the intermediate allocation.
fn pin_to_secret(pin: &[u8]) -> Result<SecretString> {
    let pin_str = std::str::from_utf8(pin).map_err(|_| {
        Error::Card(CardError::InvalidData(
            "PIN must be valid UTF-8".to_string(),
        ))
    })?;
    let mut pin_owned = pin_str.to_string();
    let secret = pin_owned.clone().into();
    zeroize::Zeroize::zeroize(&mut pin_owned);
    Ok(secret)
}

/// Get detailed information about a connected smart card.
///
/// # Arguments
///
/// * `ident` - Optional card identifier (e.g. "0006:00000001"). If None, uses the first card.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::card::get_card_details;
///
/// // First card
/// let info = get_card_details(None).unwrap();
/// println!("Card: {}", info.ident);
///
/// // Specific card
/// let info = get_card_details(Some("0006:00000001")).unwrap();
/// ```
pub fn get_card_details(ident: Option<&str>) -> Result<CardInfo> {
    let backend = get_card_backend(ident)?;
    let mut card = Card::new(backend).map_err(|e| Error::Card(CardError::from(e)))?;

    let mut tx = card
        .transaction()
        .map_err(|e| Error::Card(CardError::from(e)))?;

    let mut info = CardInfo::default();

    if let Ok(aid) = tx.application_identifier() {
        info.serial_number = format!("{:08X}", aid.serial());
        info.manufacturer = Some(format!("{:04X}", aid.manufacturer()));
        info.manufacturer_name = Some(aid.manufacturer_name().to_string());
        info.ident = aid.ident();
    }

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

    if let Ok(status) = tx.pw_status_bytes() {
        info.pin_retry_counter = status.err_count_pw1();
        info.reset_code_retry_counter = status.err_count_rc();
        info.admin_pin_retry_counter = status.err_count_pw3();
    }

    if let Ok(name) = tx.cardholder_name() {
        if !name.is_empty() {
            info.cardholder_name = Some(name);
        }
    }

    if let Ok(url) = tx.url() {
        if !url.is_empty() {
            info.public_key_url = Some(url);
        }
    }

    if let Ok(count) = tx.digital_signature_count() {
        info.signature_counter = count;
    }

    Ok(info)
}

/// Get the firmware version of a connected card.
///
/// # Arguments
///
/// * `ident` - Optional card identifier. If None, uses the first card.
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
/// let version = get_card_version(None).unwrap();
/// println!("Firmware: {}", version);
/// ```
pub fn get_card_version(ident: Option<&str>) -> Result<String> {
    let backend = get_card_backend(ident)?;
    let mut card = Card::new(backend).map_err(|e| Error::Card(CardError::from(e)))?;

    let tx = card
        .transaction()
        .map_err(|e| Error::Card(CardError::from(e)))?;

    let aid = tx
        .application_identifier()
        .map_err(|e| Error::Card(CardError::from(e)))?;

    let version = aid.version();
    let major = version >> 8;
    let minor = version & 0xFF;
    Ok(format!("{}.{}", major, minor))
}

/// Get the serial number of a connected card.
///
/// # Arguments
///
/// * `ident` - Optional card identifier. If None, uses the first card.
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
/// let serial = get_card_serial(None).unwrap();
/// println!("Serial: {}", serial);
/// ```
pub fn get_card_serial(ident: Option<&str>) -> Result<String> {
    let backend = get_card_backend(ident)?;
    let mut card = Card::new(backend).map_err(|e| Error::Card(CardError::from(e)))?;

    let tx = card
        .transaction()
        .map_err(|e| Error::Card(CardError::from(e)))?;

    let aid = tx
        .application_identifier()
        .map_err(|e| Error::Card(CardError::from(e)))?;

    Ok(format!("{:08X}", aid.serial()))
}

/// Verify the user PIN (PW1) for signing operations.
///
/// # Arguments
///
/// * `pin` - The user PIN (typically 6-8 digits)
/// * `ident` - Optional card identifier. If None, uses the first card.
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
/// match verify_user_pin(b"123456", None) {
///     Ok(true) => println!("PIN verified"),
///     Err(e) => println!("PIN error: {}", e),
///     _ => {}
/// }
/// ```
pub fn verify_user_pin(pin: &[u8], ident: Option<&str>) -> Result<bool> {
    let backend = get_card_backend(ident)?;
    let mut card = Card::new(backend).map_err(|e| Error::Card(CardError::from(e)))?;

    let mut tx = card
        .transaction()
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
/// * `ident` - Optional card identifier. If None, uses the first card.
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
/// match verify_admin_pin(b"12345678", None) {
///     Ok(true) => println!("Admin PIN verified"),
///     Err(e) => println!("Admin PIN error: {}", e),
///     _ => {}
/// }
/// ```
pub fn verify_admin_pin(pin: &[u8], ident: Option<&str>) -> Result<bool> {
    let backend = get_card_backend(ident)?;
    let mut card = Card::new(backend).map_err(|e| Error::Card(CardError::from(e)))?;

    let mut tx = card
        .transaction()
        .map_err(|e| Error::Card(CardError::from(e)))?;

    let secret_pin = pin_to_secret(pin)?;
    tx.verify_admin_pin(secret_pin)
        .map_err(|e| Error::Card(CardError::from(e)))?;

    Ok(true)
}

/// Get the current PIN retry counters.
///
/// # Arguments
///
/// * `ident` - Optional card identifier. If None, uses the first card.
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
/// let (user, reset, admin) = get_pin_retry_counters(None).unwrap();
/// println!("User PIN retries: {}", user);
/// println!("Admin PIN retries: {}", admin);
/// ```
pub fn get_pin_retry_counters(ident: Option<&str>) -> Result<(u8, u8, u8)> {
    let backend = get_card_backend(ident)?;
    let mut card = Card::new(backend).map_err(|e| Error::Card(CardError::from(e)))?;

    let mut tx = card
        .transaction()
        .map_err(|e| Error::Card(CardError::from(e)))?;

    let status = tx
        .pw_status_bytes()
        .map_err(|e| Error::Card(CardError::from(e)))?;

    Ok((
        status.err_count_pw1(),
        status.err_count_rc(),
        status.err_count_pw3(),
    ))
}

/// Reset the card to factory defaults.
///
/// # Arguments
///
/// * `ident` - Optional card identifier. If None, uses the first card.
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
/// reset_card(None).unwrap();
/// ```
pub fn reset_card(ident: Option<&str>) -> Result<()> {
    let backend = get_card_backend(ident)?;
    let mut card = Card::new(backend).map_err(|e| Error::Card(CardError::from(e)))?;

    let mut tx = card
        .transaction()
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
/// * `ident` - Optional card identifier. If None, uses the first card.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::card::change_user_pin;
///
/// change_user_pin(b"123456", b"654321", None).unwrap();
/// ```
pub fn change_user_pin(old_pin: &[u8], new_pin: &[u8], ident: Option<&str>) -> Result<()> {
    let backend = get_card_backend(ident)?;
    let mut card = Card::new(backend).map_err(|e| Error::Card(CardError::from(e)))?;

    let mut tx = card
        .transaction()
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
/// * `ident` - Optional card identifier. If None, uses the first card.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::card::change_admin_pin;
///
/// change_admin_pin(b"12345678", b"87654321", None).unwrap();
/// ```
pub fn change_admin_pin(old_pin: &[u8], new_pin: &[u8], ident: Option<&str>) -> Result<()> {
    let backend = get_card_backend(ident)?;
    let mut card = Card::new(backend).map_err(|e| Error::Card(CardError::from(e)))?;

    let mut tx = card
        .transaction()
        .map_err(|e| Error::Card(CardError::from(e)))?;

    let old_secret = pin_to_secret(old_pin)?;
    let new_secret = pin_to_secret(new_pin)?;
    tx.change_admin_pin(old_secret, new_secret)
        .map_err(|e| Error::Card(CardError::from(e)))?;

    Ok(())
}

/// Get the current touch mode for all key slots.
///
/// Returns the touch policy for the Signature, Encryption, and Authentication
/// slots. Returns `None` for a slot if the card does not support UIF for that slot.
///
/// # Arguments
///
/// * `ident` - Optional card identifier. If None, uses the first card.
///
/// # Returns
///
/// A tuple of (signature, encryption, authentication) touch modes.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::card::get_touch_modes;
///
/// let (sig, enc, auth) = get_touch_modes(None).unwrap();
/// println!("Signature: {:?}, Encryption: {:?}, Auth: {:?}", sig, enc, auth);
/// ```
pub fn get_touch_modes(
    ident: Option<&str>,
) -> Result<(Option<TouchMode>, Option<TouchMode>, Option<TouchMode>)> {
    let backend = get_card_backend(ident)?;
    let mut card = Card::new(backend).map_err(|e| Error::Card(CardError::from(e)))?;

    let mut tx = card
        .transaction()
        .map_err(|e| Error::Card(CardError::from(e)))?;

    let convert = |policy: openpgp_card::ocard::data::TouchPolicy| -> TouchMode {
        match policy {
            openpgp_card::ocard::data::TouchPolicy::Off => TouchMode::Off,
            openpgp_card::ocard::data::TouchPolicy::On => TouchMode::On,
            openpgp_card::ocard::data::TouchPolicy::Fixed => TouchMode::Fixed,
            openpgp_card::ocard::data::TouchPolicy::Cached => TouchMode::Cached,
            openpgp_card::ocard::data::TouchPolicy::CachedFixed => TouchMode::CachedFixed,
            openpgp_card::ocard::data::TouchPolicy::Unknown(_) => TouchMode::Off,
        }
    };

    let sig = tx
        .user_interaction_flag(openpgp_card::ocard::KeyType::Signing)
        .ok()
        .flatten()
        .map(|uif| convert(uif.touch_policy()));

    let enc = tx
        .user_interaction_flag(openpgp_card::ocard::KeyType::Decryption)
        .ok()
        .flatten()
        .map(|uif| convert(uif.touch_policy()));

    let auth = tx
        .user_interaction_flag(openpgp_card::ocard::KeyType::Authentication)
        .ok()
        .flatten()
        .map(|uif| convert(uif.touch_policy()));

    Ok((sig, enc, auth))
}

/// Set the touch mode (User Interaction Flag) for a specific key slot.
///
/// This configures whether physical touch is required for cryptographic operations
/// on the specified key slot. This feature is available on YubiKey 4.2+ and some
/// other OpenPGP cards.
///
/// # Arguments
///
/// * `slot` - Which key slot to configure (Signature, Encryption, Authentication)
/// * `mode` - The touch policy to set
/// * `admin_pin` - The admin PIN for the card
/// * `ident` - Optional card identifier. If None, uses the first card.
///
/// # Warning
///
/// Setting `TouchMode::Fixed` or `TouchMode::CachedFixed` is **permanent** on some
/// devices (like YubiKey). It cannot be changed even with a factory reset!
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::card::{set_touch_mode, KeySlot, TouchMode};
///
/// // Require touch for signing operations (can be changed later)
/// set_touch_mode(KeySlot::Signature, TouchMode::On, b"12345678", None).unwrap();
///
/// // Permanently require touch for decryption
/// set_touch_mode(KeySlot::Encryption, TouchMode::Fixed, b"12345678", None).unwrap();
/// ```
pub fn set_touch_mode(
    slot: KeySlot,
    mode: TouchMode,
    admin_pin: &[u8],
    ident: Option<&str>,
) -> Result<()> {
    let backend = get_card_backend(ident)?;

    let mut opgp = OpenPGP::new(backend)
        .map_err(|e: openpgp_card::Error| Error::Card(CardError::CardError(e.to_string())))?;
    let mut tx = opgp
        .transaction()
        .map_err(|e: openpgp_card::Error| Error::Card(CardError::CardError(e.to_string())))?;

    let secret_pin = SecretBox::new(Box::from(admin_pin.to_vec()));
    tx.verify_pw3(secret_pin)
        .map_err(|e: openpgp_card::Error| Error::Card(CardError::CardError(e.to_string())))?;

    let policy_byte: u8 = match mode {
        TouchMode::Off => 0x00,
        TouchMode::On => 0x01,
        TouchMode::Fixed => 0x02,
        TouchMode::Cached => 0x03,
        TouchMode::CachedFixed => 0x04,
    };
    let uif_bytes = vec![policy_byte, 0x20];
    let uif = UserInteractionFlag::try_from(uif_bytes).map_err(|e: openpgp_card::Error| {
        Error::Card(CardError::CardError(format!("Failed to create UIF: {}", e)))
    })?;

    match slot {
        KeySlot::Signature => {
            tx.set_uif_pso_cds(&uif).map_err(|e: openpgp_card::Error| {
                Error::Card(CardError::CardError(e.to_string()))
            })?;
        }
        KeySlot::Encryption => {
            tx.set_uif_pso_dec(&uif).map_err(|e: openpgp_card::Error| {
                Error::Card(CardError::CardError(e.to_string()))
            })?;
        }
        KeySlot::Authentication => {
            tx.set_uif_pso_aut(&uif).map_err(|e: openpgp_card::Error| {
                Error::Card(CardError::CardError(e.to_string()))
            })?;
        }
    }

    Ok(())
}

/// Set the cardholder name on the card.
///
/// The name must be ASCII only and less than 40 characters.
///
/// Note: The OpenPGP card spec uses the format "Last<<First" for names,
/// but this function takes the raw name string. The caller is responsible
/// for any encoding if needed.
///
/// # Arguments
///
/// * `name` - The cardholder name (ASCII, max 39 chars)
/// * `admin_pin` - The admin PIN for the card
/// * `ident` - Optional card identifier. If None, uses the first card.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::card::set_cardholder_name;
///
/// set_cardholder_name("Doe<<Jane", b"12345678", None).unwrap();
/// ```
pub fn set_cardholder_name(name: &str, admin_pin: &[u8], ident: Option<&str>) -> Result<()> {
    let backend = get_card_backend(ident)?;
    let mut opgp = OpenPGP::new(backend)
        .map_err(|e: openpgp_card::Error| Error::Card(CardError::CardError(e.to_string())))?;
    let mut tx = opgp
        .transaction()
        .map_err(|e: openpgp_card::Error| Error::Card(CardError::CardError(e.to_string())))?;

    let secret_pin = SecretBox::new(Box::from(admin_pin.to_vec()));
    tx.verify_pw3(secret_pin)
        .map_err(|e: openpgp_card::Error| Error::Card(CardError::CardError(e.to_string())))?;

    tx.set_name(name.as_bytes())
        .map_err(|e: openpgp_card::Error| Error::Card(CardError::CardError(e.to_string())))?;

    Ok(())
}

/// Set the public key URL on the card.
///
/// The URL must be ASCII only. The maximum length depends on the card's
/// extended capabilities.
///
/// # Arguments
///
/// * `url` - The public key URL (ASCII)
/// * `admin_pin` - The admin PIN for the card
/// * `ident` - Optional card identifier. If None, uses the first card.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::card::set_public_key_url;
///
/// set_public_key_url("https://keys.openpgp.org/vks/v1/by-fingerprint/ABCD1234", b"12345678", None).unwrap();
/// ```
pub fn set_public_key_url(url: &str, admin_pin: &[u8], ident: Option<&str>) -> Result<()> {
    let backend = get_card_backend(ident)?;
    let mut opgp = OpenPGP::new(backend)
        .map_err(|e: openpgp_card::Error| Error::Card(CardError::CardError(e.to_string())))?;
    let mut tx = opgp
        .transaction()
        .map_err(|e: openpgp_card::Error| Error::Card(CardError::CardError(e.to_string())))?;

    let secret_pin = SecretBox::new(Box::from(admin_pin.to_vec()));
    tx.verify_pw3(secret_pin)
        .map_err(|e: openpgp_card::Error| Error::Card(CardError::CardError(e.to_string())))?;

    tx.set_url(url.as_bytes())
        .map_err(|e: openpgp_card::Error| Error::Card(CardError::CardError(e.to_string())))?;

    Ok(())
}

/// Find all connected smart cards that hold subkeys belonging to a given OpenPGP key.
///
/// **PCSC-only.** See [`is_card_connected`] for the rationale.
///
/// Parses the key, enumerates all connected cards, and checks each card's
/// three key slots (signature, encryption, authentication) against the key's
/// primary key fingerprint and all subkey fingerprints.
///
/// # Arguments
///
/// * `key_data` - The public key data (armored or binary)
///
/// # Returns
///
/// A list of `CardKeyMatch` entries, one for each card that has at least one
/// matching fingerprint. Returns an empty vector if no cards are connected
/// or no cards match the key.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::card::find_cards_for_key;
///
/// let key = std::fs::read("pubkey.asc").unwrap();
/// let matches = find_cards_for_key(&key).unwrap();
/// for m in &matches {
///     println!("Card {} has {} matching slots", m.card.ident, m.matching_slots.len());
///     for slot in &m.matching_slots {
///         println!("  {:?} slot: {}", slot.slot, slot.fingerprint);
///     }
/// }
/// ```
#[cfg(feature = "card-pcsc")]
pub fn find_cards_for_key(key_data: &[u8]) -> Result<Vec<CardKeyMatch>> {
    // Parse the key to extract all fingerprints
    let cert_info = crate::parse_key_bytes(key_data, true)?;

    // Build a list of all fingerprints (primary + subkeys), normalized to lowercase
    let mut key_fingerprints: Vec<String> = Vec::new();
    key_fingerprints.push(cert_info.fingerprint.to_lowercase());
    for subkey in &cert_info.subkeys {
        key_fingerprints.push(subkey.fingerprint.to_lowercase());
    }

    // Enumerate all connected cards
    let cards = PcscBackend::cards(None)
        .map_err(|e| Error::Card(CardError::CommunicationError(e.to_string())))?;

    let mut results = Vec::new();

    for backend in cards {
        let backend = match backend {
            Ok(b) => b,
            Err(_) => continue,
        };

        let mut card = match Card::new(backend) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let mut tx = match card.transaction() {
            Ok(t) => t,
            Err(_) => continue,
        };

        let mut info = CardInfo::default();

        if let Ok(aid) = tx.application_identifier() {
            info.serial_number = format!("{:08X}", aid.serial());
            info.manufacturer = Some(format!("{:04X}", aid.manufacturer()));
            info.manufacturer_name = Some(aid.manufacturer_name().to_string());
            info.ident = aid.ident();
        }

        let mut matching_slots = Vec::new();

        if let Ok(fps) = tx.fingerprints() {
            if let Some(fp) = fps.signature() {
                let fp_hex = hex::encode(fp.as_bytes());
                info.signature_fingerprint = Some(fp_hex.clone());
                if key_fingerprints.contains(&fp_hex) {
                    matching_slots.push(SlotMatch {
                        slot: KeySlot::Signature,
                        fingerprint: fp_hex,
                    });
                }
            }
            if let Some(fp) = fps.decryption() {
                let fp_hex = hex::encode(fp.as_bytes());
                info.encryption_fingerprint = Some(fp_hex.clone());
                if key_fingerprints.contains(&fp_hex) {
                    matching_slots.push(SlotMatch {
                        slot: KeySlot::Encryption,
                        fingerprint: fp_hex,
                    });
                }
            }
            if let Some(fp) = fps.authentication() {
                let fp_hex = hex::encode(fp.as_bytes());
                info.authentication_fingerprint = Some(fp_hex.clone());
                if key_fingerprints.contains(&fp_hex) {
                    matching_slots.push(SlotMatch {
                        slot: KeySlot::Authentication,
                        fingerprint: fp_hex,
                    });
                }
            }
        }

        // Fill remaining CardInfo fields
        if let Ok(status) = tx.pw_status_bytes() {
            info.pin_retry_counter = status.err_count_pw1();
            info.reset_code_retry_counter = status.err_count_rc();
            info.admin_pin_retry_counter = status.err_count_pw3();
        }

        if let Ok(name) = tx.cardholder_name() {
            if !name.is_empty() {
                info.cardholder_name = Some(name);
            }
        }

        if let Ok(url) = tx.url() {
            if !url.is_empty() {
                info.public_key_url = Some(url);
            }
        }

        if let Ok(count) = tx.digital_signature_count() {
            info.signature_counter = count;
        }

        // Only include cards with at least one match
        if !matching_slots.is_empty() {
            results.push(CardKeyMatch {
                card: info,
                matching_slots,
            });
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    // Tests require a physical card or virtual card via pcscd
    // Run with: cargo test --features card -- --ignored
}
