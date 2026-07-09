//! Externally-provided card transport (mobile / custom backends).
//!
//! This module is active under the `card-external` feature. Consumers
//! register a callback that, given an optional `ident`, returns a
//! `Box<dyn CardBackend + Send + Sync>` for use by the rest of
//! `wecanencrypt::card`. The intended use case is mobile apps that
//! bridge APDU I/O to native Android/iOS code over an IPC channel (for
//! example libtumpa's `MobileCardBackend`, which routes through the
//! `tauri-plugin-tumpa-card` plugin and ultimately speaks to the
//! smartcard over NFC or USB via generic ISO-DEP / ISO 7816-4 APIs -
//! working with any OpenPGP v3 compliant card, not just YubiKey).
//!
//! Enumeration (`is_card_connected`, `list_all_cards`, `find_cards_for_key`)
//! is *not* exposed here - on mobile there is typically at most one
//! active card session at a time (NFC tap / plugged-in USB reader) and
//! session acquisition is explicit in the UI. Callers that want
//! "is a card available?" semantics should model that at the app layer.

use card_backend::CardBackend;
use std::sync::OnceLock;

use super::types::CardError;
use crate::error::{Error, Result};

/// A card backend provider.
///
/// Called each time `wecanencrypt::card` needs a fresh backend (for a
/// single operation - a PIN verify, a signature, a key upload). The
/// provider is responsible for: starting a card session on the
/// underlying transport (NFC tap / USB plug), selecting the OpenPGP
/// applet (AID `D2760001240103040000000000000000`), and returning a
/// `CardBackend` implementation that speaks APDUs to the card.
///
/// `ident` is a tumpa/wecanencrypt card ident string
/// (`"MANUFACTURER:SERIAL"`, uppercase). On mobile, the provider is
/// typically free to ignore it when only one card can be connected at a
/// time.
pub type BackendProvider =
    Box<dyn Fn(Option<&str>) -> Result<Box<dyn CardBackend + Send + Sync>> + Send + Sync + 'static>;

static PROVIDER: OnceLock<BackendProvider> = OnceLock::new();

/// Register the backend provider used by this process.
///
/// Call once at application startup. Subsequent calls are ignored (the
/// first successful registration wins). Returns an error if the
/// provider was already registered.
///
/// # Example
///
/// ```no_run
/// # #[cfg(feature = "card-external")]
/// # {
/// use openpgp_card::CardBackend;
/// use wecanencrypt::card::external::set_backend_provider;
/// use wecanencrypt::Result;
///
/// fn my_provider(_ident: Option<&str>) -> Result<Box<dyn CardBackend + Send + Sync>> {
///     // Open an NFC / USB session and return a CardBackend.
///     unimplemented!()
/// }
///
/// set_backend_provider(my_provider).unwrap();
/// # }
/// ```
pub fn set_backend_provider<F>(f: F) -> std::result::Result<(), AlreadyRegistered>
where
    F: Fn(Option<&str>) -> Result<Box<dyn CardBackend + Send + Sync>> + Send + Sync + 'static,
{
    PROVIDER.set(Box::new(f)).map_err(|_| AlreadyRegistered)
}

/// Error returned by [`set_backend_provider`] when a provider was
/// already registered in this process.
#[derive(Debug, Clone, Copy)]
pub struct AlreadyRegistered;

impl std::fmt::Display for AlreadyRegistered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("wecanencrypt::card::external: backend provider already registered")
    }
}

impl std::error::Error for AlreadyRegistered {}

/// Invoke the registered provider. Returns `CardError::NotConnected` if
/// no provider has been registered yet.
///
/// Only called from [`super::connection::get_card_backend`] when
/// `card-external` is enabled and `card-pcsc` is not (PCSC wins when
/// both are enabled, which is the all-features case). Hence the
/// `dead_code` suppression when both features are active.
#[cfg_attr(feature = "card-pcsc", allow(dead_code))]
pub(crate) fn invoke_provider(ident: Option<&str>) -> Result<Box<dyn CardBackend + Send + Sync>> {
    let provider = PROVIDER.get().ok_or(Error::Card(CardError::NotConnected))?;
    provider(ident)
}
