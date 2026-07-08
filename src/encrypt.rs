//! OpenPGP encryption helpers.
//!
//! The primary entry points are [`encrypt_bytes`] for a single recipient and
//! [`encrypt_bytes_to_multiple`] for a recipient set. Both accept public
//! certificate bytes in ASCII armor or binary form. The default helpers inspect
//! the recipient key version and choose the compliant encrypted-data packet:
//! SEIPD v1 for V4 recipients and SEIPD v2 with AEAD for V6 recipients.
//!
//! Recipient lists must be version-homogeneous. Mixing V4 and V6 certificates
//! in one call returns [`crate::Error::KeyVersionMismatch`] instead of producing
//! a message with ambiguous packet framing.

use std::io::{BufReader, Cursor, Read};
use std::path::Path;

use pgp::armor::Dearmor;
use pgp::composed::{MessageBuilder, SignedPublicKey};
use pgp::crypto::aead::{AeadAlgorithm, ChunkSize};
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::{Packet, PacketParser, PublicKeyEncryptedSessionKey};
use pgp::types::{KeyDetails, KeyVersion, Password};
use rand::thread_rng;

use crate::error::{Error, Result};
use crate::internal::{
    can_details_sign, can_subkey_encrypt, is_subkey_valid, parse_public_key, parse_secret_key,
    validate_secret_signing_usage, SigningKeyUsage,
};
use crate::sign::{find_signing_subkey, select_hash_for_params};

/// Encrypt bytes to a single recipient.
///
/// Uses SEIPD v1 (RFC 4880, integrity-protected with MDC) for V4 recipients and
/// SEIPD v2 (RFC 9580, AEAD) for V6 recipients. For callers that need to force
/// the V6 packet shape directly, use [`encrypt_bytes_v2`].
///
/// Encrypts the plaintext to the recipient's public key. The message can only
/// be decrypted by someone with the corresponding secret key.
///
/// # Arguments
/// * `recipient_key` - The recipient's public key (armored or binary)
/// * `plaintext` - The data to encrypt
/// * `armor` - If true, output ASCII-armored; otherwise binary
///
/// # Returns
/// The encrypted message.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{create_key_simple, encrypt_bytes, decrypt_bytes, get_pub_key};
///
/// // Create a V4 key pair and extract the public certificate.
/// let key = create_key_simple("password", &["Alice <alice@example.com>"]).unwrap();
/// let public_key = get_pub_key(&key.secret_key).unwrap();
///
/// // Encrypt an ASCII-armored message.
/// let ciphertext = encrypt_bytes(public_key.as_bytes(), b"Secret message", true).unwrap();
///
/// // Decrypt it
/// let plaintext = decrypt_bytes(&key.secret_key, &ciphertext, "password").unwrap();
/// assert_eq!(plaintext, b"Secret message");
/// ```
pub fn encrypt_bytes(recipient_key: &[u8], plaintext: &[u8], armor: bool) -> Result<Vec<u8>> {
    encrypt_bytes_to_multiple(&[recipient_key], plaintext, armor)
}

/// Encrypt bytes to a single recipient using SEIPD v2 (RFC 9580, AEAD).
///
/// Like [`encrypt_bytes`], but uses SEIPD v2 (AES-256-OCB) for AEAD-based
/// authenticated encryption. Prefer [`encrypt_bytes`] for general use; it
/// already selects SEIPD v2 for V6 recipients.
///
/// # Arguments
/// * `recipient_key` - The recipient's public key (armored or binary)
/// * `plaintext` - The data to encrypt
/// * `armor` - If true, output ASCII-armored; otherwise binary
pub fn encrypt_bytes_v2(recipient_key: &[u8], plaintext: &[u8], armor: bool) -> Result<Vec<u8>> {
    encrypt_bytes_to_multiple_v2(&[recipient_key], plaintext, armor)
}

/// Encrypt bytes to multiple recipients.
///
/// Automatically selects SEIPD v1 (RFC 4880, MDC) for V4-recipient lists and
/// SEIPD v2 (RFC 9580, AEAD with AES-256-OCB) for V6-recipient lists. All
/// recipients must share the same key version; a mixed list returns
/// [`Error::KeyVersionMismatch`] to prevent accidentally producing a message
/// whose ESK/SEIPD framing is disallowed by RFC 9580 §5.1.2 / §5.3.2.
///
/// Each recipient only needs their own secret key to decrypt. If you pass V6
/// recipients, the output uses SEIPD v2 automatically.
///
/// # Arguments
/// * `recipient_keys` - Slice of recipient public keys (armored or binary)
/// * `plaintext` - The data to encrypt
/// * `armor` - If true, output ASCII-armored; otherwise binary
///
/// # Returns
/// The encrypted message that can be decrypted by any of the recipients.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{create_key_simple, encrypt_bytes_to_multiple, decrypt_bytes, get_pub_key};
///
/// // Create two recipients
/// let alice = create_key_simple("alice_pw", &["Alice <alice@example.com>"]).unwrap();
/// let bob = create_key_simple("bob_pw", &["Bob <bob@example.com>"]).unwrap();
///
/// let alice_pub = get_pub_key(&alice.secret_key).unwrap();
/// let bob_pub = get_pub_key(&bob.secret_key).unwrap();
///
/// // Encrypt to both
/// let ciphertext = encrypt_bytes_to_multiple(
///     &[alice_pub.as_bytes(), bob_pub.as_bytes()],
///     b"Group message",
///     true,
/// ).unwrap();
///
/// // Either can decrypt
/// let plain_alice = decrypt_bytes(&alice.secret_key, &ciphertext, "alice_pw").unwrap();
/// let plain_bob = decrypt_bytes(&bob.secret_key, &ciphertext, "bob_pw").unwrap();
/// assert_eq!(plain_alice, plain_bob);
/// ```
pub fn encrypt_bytes_to_multiple(
    recipient_keys: &[&[u8]],
    plaintext: &[u8],
    armor: bool,
) -> Result<Vec<u8>> {
    encrypt_bytes_to_multiple_with_algo(
        recipient_keys,
        plaintext,
        armor,
        SymmetricKeyAlgorithm::AES256,
    )
}

/// Encrypt bytes to multiple recipients using SEIPD v2 (RFC 9580, AEAD).
///
/// Like [`encrypt_bytes_to_multiple`], but uses SEIPD v2 (AES-256-OCB) for
/// AEAD-based authenticated encryption. Requires recipients with V6 key support.
///
/// # Arguments
/// * `recipient_keys` - Slice of recipient public keys (armored or binary)
/// * `plaintext` - The data to encrypt
/// * `armor` - If true, output ASCII-armored; otherwise binary
///
/// # Returns
/// The encrypted message using SEIPD v2 format.
pub fn encrypt_bytes_to_multiple_v2(
    recipient_keys: &[&[u8]],
    plaintext: &[u8],
    armor: bool,
) -> Result<Vec<u8>> {
    encrypt_bytes_to_multiple_seipd_v2(
        recipient_keys,
        plaintext,
        armor,
        SymmetricKeyAlgorithm::AES256,
    )
}

/// Encrypt bytes to multiple recipients with a specific symmetric algorithm.
///
/// Uses SEIPD v1 (RFC 4880, integrity-protected with MDC).
/// Like [`encrypt_bytes_to_multiple`], but allows choosing the symmetric cipher.
/// RFC 9580 requires implementations to support both AES-128 and AES-256.
///
/// # Arguments
/// * `recipient_keys` - Slice of recipient public keys (armored or binary)
/// * `plaintext` - The data to encrypt
/// * `armor` - If true, output ASCII-armored; otherwise binary
/// * `sym_algo` - The symmetric algorithm to use (e.g., AES128, AES256)
///
/// # Returns
/// The encrypted message that can be decrypted by any of the recipients.
pub fn encrypt_bytes_to_multiple_with_algo(
    recipient_keys: &[&[u8]],
    plaintext: &[u8],
    armor: bool,
    sym_algo: SymmetricKeyAlgorithm,
) -> Result<Vec<u8>> {
    validate_sym_algo(sym_algo)?;

    if recipient_keys.is_empty() {
        return Err(Error::InvalidInput("No recipients specified".to_string()));
    }

    let (encryption_keys, recipients_version) = collect_encryption_keys(recipient_keys)?;

    // RFC 9580 §5.1.2 / §5.3.2: V6 PKESKs must precede a V2 SEIPD. Route V6
    // recipient lists to the AEAD path automatically so callers using the
    // plain `encrypt_*` entry points still get a compliant message.
    if recipients_version == KeyVersion::V6 {
        return encrypt_with_seipd_v2(&encryption_keys, plaintext, armor, sym_algo);
    }

    let mut rng = thread_rng();

    // Build the encrypted message using SEIPD v1 (MDC)
    let mut builder =
        MessageBuilder::from_bytes("", plaintext.to_vec()).seipd_v1(&mut rng, sym_algo);

    // Add all encryption keys as recipients
    for key in &encryption_keys {
        builder
            .encrypt_to_key(&mut rng, key)
            .map_err(|e| Error::Crypto(e.to_string()))?;
    }

    // Produce the output
    if armor {
        let armored = builder
            .to_armored_string(&mut rng, None.into())
            .map_err(|e| Error::Crypto(e.to_string()))?;
        Ok(armored.into_bytes())
    } else {
        builder
            .to_vec(&mut rng)
            .map_err(|e| Error::Crypto(e.to_string()))
    }
}

/// Encrypt bytes to multiple recipients using SEIPD v2 (RFC 9580, AEAD) with a
/// specific symmetric algorithm.
///
/// Uses AEAD with OCB mode for authenticated encryption. Requires recipients
/// with V6 key support.
///
/// # Arguments
/// * `recipient_keys` - Slice of recipient public keys (armored or binary)
/// * `plaintext` - The data to encrypt
/// * `armor` - If true, output ASCII-armored; otherwise binary
/// * `sym_algo` - The symmetric algorithm to use (e.g., AES128, AES256)
///
/// # Returns
/// The encrypted message using SEIPD v2 format.
pub fn encrypt_bytes_to_multiple_seipd_v2(
    recipient_keys: &[&[u8]],
    plaintext: &[u8],
    armor: bool,
    sym_algo: SymmetricKeyAlgorithm,
) -> Result<Vec<u8>> {
    validate_sym_algo(sym_algo)?;

    if recipient_keys.is_empty() {
        return Err(Error::InvalidInput("No recipients specified".to_string()));
    }

    let (encryption_keys, _version) = collect_encryption_keys(recipient_keys)?;
    encrypt_with_seipd_v2(&encryption_keys, plaintext, armor, sym_algo)
}

/// Sign and encrypt bytes to one or more recipients in a single OpenPGP
/// message (sign-then-encrypt).
///
/// The output is a regular PGP encrypted message; after decryption, the
/// recipient sees an inner signature over the plaintext. This is the shape
/// of message that PGP/MIME `multipart/encrypted` parts produced by
/// Thunderbird, Proton Mail, GPG Suite, etc. carry when "sign and encrypt"
/// is checked.
///
/// Auto-routes to SEIPD v1 (V4 recipients) or SEIPD v2 (V6 recipients), the
/// same way [`encrypt_bytes_to_multiple`] does. A mixed V4/V6 recipient list
/// is rejected.
///
/// # Arguments
/// * `signer_secret_key` - The signer's secret key (armored or binary)
/// * `signer_password` - Password to unlock the signing key
/// * `recipient_keys` - Slice of recipient public keys (armored or binary)
/// * `plaintext` - The data to sign and encrypt
/// * `armor` - If true, output ASCII-armored; otherwise binary
pub fn sign_and_encrypt_to_multiple(
    signer_secret_key: &[u8],
    signer_password: &str,
    recipient_keys: &[&[u8]],
    plaintext: &[u8],
    armor: bool,
) -> Result<Vec<u8>> {
    if recipient_keys.is_empty() {
        return Err(Error::InvalidInput("No recipients specified".to_string()));
    }

    let secret_key = parse_secret_key(signer_secret_key)?;
    validate_secret_signing_usage(&secret_key, SigningKeyUsage::DataSignature)?;

    let (encryption_keys, recipients_version) = collect_encryption_keys(recipient_keys)?;

    // Pick the signing key once so both seipd-v1 and seipd-v2 branches use
    // the same selection rule as `sign_bytes`. The chosen `&dyn SigningKey`
    // is borrowed from `secret_key` for the rest of this function.
    let (signing_key, hash_alg): (&dyn pgp::types::SigningKey, _) =
        if let Some(subkey) = find_signing_subkey(&secret_key) {
            let h = select_hash_for_params(subkey.key.public_params());
            (&subkey.key, h)
        } else if can_details_sign(&secret_key.details) {
            let h = select_hash_for_params(secret_key.primary_key.public_params());
            (&secret_key.primary_key, h)
        } else {
            return Err(Error::NoSigningSubkey);
        };

    let mut rng = thread_rng();
    let signer_pwd: Password = signer_password.into();

    // The SEIPD-typed MessageBuilder's `sign` and `encrypt_to_key` methods
    // are split across two type states; the cleanest way to share the body
    // is two parallel branches that each produce the final bytes.
    if recipients_version == KeyVersion::V6 {
        let mut builder = MessageBuilder::from_bytes("", plaintext.to_vec()).seipd_v2(
            &mut rng,
            SymmetricKeyAlgorithm::AES256,
            AeadAlgorithm::Ocb,
            ChunkSize::default(),
        );
        builder.sign(signing_key, signer_pwd, hash_alg);
        for key in &encryption_keys {
            builder
                .encrypt_to_key(&mut rng, key)
                .map_err(|e| Error::Crypto(e.to_string()))?;
        }
        if armor {
            builder
                .to_armored_string(&mut rng, None.into())
                .map(|s| s.into_bytes())
                .map_err(|e| Error::Crypto(e.to_string()))
        } else {
            builder
                .to_vec(&mut rng)
                .map_err(|e| Error::Crypto(e.to_string()))
        }
    } else {
        let mut builder = MessageBuilder::from_bytes("", plaintext.to_vec())
            .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
        builder.sign(signing_key, signer_pwd, hash_alg);
        for key in &encryption_keys {
            builder
                .encrypt_to_key(&mut rng, key)
                .map_err(|e| Error::Crypto(e.to_string()))?;
        }
        if armor {
            builder
                .to_armored_string(&mut rng, None.into())
                .map(|s| s.into_bytes())
                .map_err(|e| Error::Crypto(e.to_string()))
        } else {
            builder
                .to_vec(&mut rng)
                .map_err(|e| Error::Crypto(e.to_string()))
        }
    }
}

/// Sign-and-encrypt to a mixed set of "visible" and "hidden" recipients.
///
/// Visible recipients are added with `encrypt_to_key` (standard PKESK
/// carrying the recipient's identifier). Hidden recipients are added with
/// `encrypt_to_key_anonymous` (a.k.a. RFC 4880 `throw-keyid` /
/// `--hidden-recipient`):
///
/// * On V3 PKESK (used with V4 recipient keys), the 8-byte recipient
///   key-id field is set to the all-zero wildcard.
/// * On V6 PKESK (used with V6 recipient keys, RFC 9580), the optional
///   recipient fingerprint field is omitted entirely (encoded as `None`).
///
/// Either form makes the PKESK packet reveal only that an extra
/// recipient exists, not who.
///
/// This is the primitive that PGP/MIME mail clients use to deliver
/// "Bcc with encryption" without leaking Bcc identities to the To/Cc
/// recipients. The full ciphertext is still a single OpenPGP message
/// (efficient on the wire); every recipient — visible or hidden — sees the
/// same plaintext after decryption.
///
/// At least one recipient (visible OR hidden) must be supplied; both
/// lists may not be empty simultaneously. All recipients must share a
/// single key version (V4 or V6); a mixed list is rejected per
/// [`Error::KeyVersionMismatch`].
///
/// # Arguments
/// * `signer_secret_key` - Signer's secret key bytes (armored or binary).
/// * `signer_password` - Passphrase that unlocks the signing key.
/// * `visible_recipient_keys` - Public keys whose identifiers ARE exposed
///   in the PKESK packets.
/// * `hidden_recipient_keys` - Public keys whose PKESK identifier is
///   suppressed (V4: wildcard key id; V6: omitted fingerprint).
/// * `plaintext` - Bytes to sign and encrypt.
/// * `armor` - If true, ASCII-armored output; otherwise binary.
pub fn sign_and_encrypt_to_multiple_with_hidden(
    signer_secret_key: &[u8],
    signer_password: &str,
    visible_recipient_keys: &[&[u8]],
    hidden_recipient_keys: &[&[u8]],
    plaintext: &[u8],
    armor: bool,
) -> Result<Vec<u8>> {
    let secret_key = parse_secret_key(signer_secret_key)?;
    validate_secret_signing_usage(&secret_key, SigningKeyUsage::DataSignature)?;

    // Single-pass-per-side: each recipient key is parsed exactly once.
    // The helper also catches both empty-empty and mixed V4/V6 splits.
    let (visible_subkeys, hidden_subkeys, recipients_version) =
        collect_visible_and_hidden_keys(visible_recipient_keys, hidden_recipient_keys)?;

    let (signing_key, hash_alg): (&dyn pgp::types::SigningKey, _) =
        if let Some(subkey) = find_signing_subkey(&secret_key) {
            let h = select_hash_for_params(subkey.key.public_params());
            (&subkey.key, h)
        } else if can_details_sign(&secret_key.details) {
            let h = select_hash_for_params(secret_key.primary_key.public_params());
            (&secret_key.primary_key, h)
        } else {
            return Err(Error::NoSigningSubkey);
        };

    let mut rng = thread_rng();
    let signer_pwd: Password = signer_password.into();

    if recipients_version == KeyVersion::V6 {
        let mut builder = MessageBuilder::from_bytes("", plaintext.to_vec()).seipd_v2(
            &mut rng,
            SymmetricKeyAlgorithm::AES256,
            AeadAlgorithm::Ocb,
            ChunkSize::default(),
        );
        builder.sign(signing_key, signer_pwd, hash_alg);
        for key in &visible_subkeys {
            builder
                .encrypt_to_key(&mut rng, key)
                .map_err(|e| Error::Crypto(e.to_string()))?;
        }
        for key in &hidden_subkeys {
            builder
                .encrypt_to_key_anonymous(&mut rng, key)
                .map_err(|e| Error::Crypto(e.to_string()))?;
        }
        if armor {
            builder
                .to_armored_string(&mut rng, None.into())
                .map(|s| s.into_bytes())
                .map_err(|e| Error::Crypto(e.to_string()))
        } else {
            builder
                .to_vec(&mut rng)
                .map_err(|e| Error::Crypto(e.to_string()))
        }
    } else {
        let mut builder = MessageBuilder::from_bytes("", plaintext.to_vec())
            .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
        builder.sign(signing_key, signer_pwd, hash_alg);
        for key in &visible_subkeys {
            builder
                .encrypt_to_key(&mut rng, key)
                .map_err(|e| Error::Crypto(e.to_string()))?;
        }
        for key in &hidden_subkeys {
            builder
                .encrypt_to_key_anonymous(&mut rng, key)
                .map_err(|e| Error::Crypto(e.to_string()))?;
        }
        if armor {
            builder
                .to_armored_string(&mut rng, None.into())
                .map(|s| s.into_bytes())
                .map_err(|e| Error::Crypto(e.to_string()))
        } else {
            builder
                .to_vec(&mut rng)
                .map_err(|e| Error::Crypto(e.to_string()))
        }
    }
}

/// Encrypt to a mixed set of "visible" and "hidden" recipients (no
/// signature). Sibling of [`sign_and_encrypt_to_multiple_with_hidden`].
///
/// Hidden recipients receive a PKESK whose recipient identifier is
/// suppressed: V3 PKESK (used with V4 keys) carries an all-zero wildcard
/// 8-byte key id; V6 PKESK (used with V6 keys, RFC 9580) omits the
/// optional fingerprint field. Either way the PKESK leaks no identifier
/// for the recipient (RFC 4880 `throw-keyid` / `--hidden-recipient`).
pub fn encrypt_bytes_to_multiple_with_hidden(
    visible_recipient_keys: &[&[u8]],
    hidden_recipient_keys: &[&[u8]],
    plaintext: &[u8],
    armor: bool,
) -> Result<Vec<u8>> {
    let (visible_subkeys, hidden_subkeys, recipients_version) =
        collect_visible_and_hidden_keys(visible_recipient_keys, hidden_recipient_keys)?;

    let mut rng = thread_rng();

    if recipients_version == KeyVersion::V6 {
        let mut builder = MessageBuilder::from_bytes("", plaintext.to_vec()).seipd_v2(
            &mut rng,
            SymmetricKeyAlgorithm::AES256,
            AeadAlgorithm::Ocb,
            ChunkSize::default(),
        );
        for key in &visible_subkeys {
            builder
                .encrypt_to_key(&mut rng, key)
                .map_err(|e| Error::Crypto(e.to_string()))?;
        }
        for key in &hidden_subkeys {
            builder
                .encrypt_to_key_anonymous(&mut rng, key)
                .map_err(|e| Error::Crypto(e.to_string()))?;
        }
        if armor {
            builder
                .to_armored_string(&mut rng, None.into())
                .map(|s| s.into_bytes())
                .map_err(|e| Error::Crypto(e.to_string()))
        } else {
            builder
                .to_vec(&mut rng)
                .map_err(|e| Error::Crypto(e.to_string()))
        }
    } else {
        let mut builder = MessageBuilder::from_bytes("", plaintext.to_vec())
            .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
        for key in &visible_subkeys {
            builder
                .encrypt_to_key(&mut rng, key)
                .map_err(|e| Error::Crypto(e.to_string()))?;
        }
        for key in &hidden_subkeys {
            builder
                .encrypt_to_key_anonymous(&mut rng, key)
                .map_err(|e| Error::Crypto(e.to_string()))?;
        }
        if armor {
            builder
                .to_armored_string(&mut rng, None.into())
                .map(|s| s.into_bytes())
                .map_err(|e| Error::Crypto(e.to_string()))
        } else {
            builder
                .to_vec(&mut rng)
                .map_err(|e| Error::Crypto(e.to_string()))
        }
    }
}

/// Two-list variant of [`collect_encryption_keys`]: parse the visible and
/// hidden recipient lists exactly once each, then validate they share a
/// single [`KeyVersion`]. Returns `(visible_subkeys, hidden_subkeys, version)`.
///
/// At least one of the two lists must be non-empty; an empty-empty call
/// is rejected with [`Error::InvalidInput`]. A mixed V4/V6 split between
/// the two sides surfaces as [`Error::KeyVersionMismatch`] — RFC 9580
/// forbids V6 ESK packets preceding a V1 SEIPD and vice versa, so the
/// caller could not route the message down a single SEIPD path.
pub(crate) fn collect_visible_and_hidden_keys(
    visible_recipient_keys: &[&[u8]],
    hidden_recipient_keys: &[&[u8]],
) -> Result<(
    Vec<pgp::composed::SignedPublicSubKey>,
    Vec<pgp::composed::SignedPublicSubKey>,
    KeyVersion,
)> {
    if visible_recipient_keys.is_empty() && hidden_recipient_keys.is_empty() {
        return Err(Error::InvalidInput("No recipients specified".to_string()));
    }

    // Walk each side at most once. Each call validates intra-list version
    // consistency. Comparing the two per-side versions afterwards catches
    // a cross-side V4/V6 split.
    let visible_result = if visible_recipient_keys.is_empty() {
        None
    } else {
        Some(collect_encryption_keys(visible_recipient_keys)?)
    };
    let hidden_result = if hidden_recipient_keys.is_empty() {
        None
    } else {
        Some(collect_encryption_keys(hidden_recipient_keys)?)
    };

    match (visible_result, hidden_result) {
        (Some((v, ver_v)), Some((h, ver_h))) => {
            if ver_v != ver_h {
                return Err(Error::KeyVersionMismatch {
                    existing: ver_v,
                    incoming: ver_h,
                });
            }
            Ok((v, h, ver_v))
        }
        (Some((v, ver)), None) => Ok((v, Vec::new(), ver)),
        (None, Some((h, ver))) => Ok((Vec::new(), h, ver)),
        (None, None) => unreachable!("empty-empty was rejected above"),
    }
}

/// Reject deprecated/insecure symmetric algorithms per RFC 9580 §9.3.
fn validate_sym_algo(sym_algo: SymmetricKeyAlgorithm) -> Result<()> {
    match sym_algo {
        SymmetricKeyAlgorithm::AES128
        | SymmetricKeyAlgorithm::AES192
        | SymmetricKeyAlgorithm::AES256
        | SymmetricKeyAlgorithm::Twofish
        | SymmetricKeyAlgorithm::Camellia128
        | SymmetricKeyAlgorithm::Camellia192
        | SymmetricKeyAlgorithm::Camellia256 => Ok(()),
        _ => Err(Error::InvalidInput(format!(
            "Symmetric algorithm {:?} is not allowed for encryption per RFC 9580",
            sym_algo
        ))),
    }
}

/// Parse recipient keys, verify all share a single key version, and collect
/// valid encryption subkeys.
///
/// Returns `(subkeys, version)` where `version` is the key version shared by
/// every recipient's primary key. A mixed V4/V6 recipient list is rejected
/// with [`Error::KeyVersionMismatch`] since RFC 9580 forbids V6 ESK packets
/// preceding a V1 SEIPD and vice versa.
pub(crate) fn collect_encryption_keys(
    recipient_keys: &[&[u8]],
) -> Result<(Vec<pgp::composed::SignedPublicSubKey>, KeyVersion)> {
    let mut encryption_keys = Vec::new();
    let mut recipients_version: Option<KeyVersion> = None;

    for key_data in recipient_keys {
        let public_key = parse_public_key(key_data)?;
        let primary_version = public_key.primary_key.version();
        match recipients_version {
            None => recipients_version = Some(primary_version),
            Some(existing) if existing != primary_version => {
                return Err(Error::KeyVersionMismatch {
                    existing,
                    incoming: primary_version,
                });
            }
            Some(_) => {}
        }

        let subkeys = find_valid_encryption_subkeys(&public_key)?;

        // RFC 9580 §10.1.1: every subkey of a V6 primary must be V6, and a V4
        // primary must not carry V6 subkeys. rpgp 0.19 already rejects
        // mismatched keys at parse (`SignedPublicKey::from_bytes` errors with
        // "Illegal public subkey V4 in v6 key"), so in practice this guard is
        // defense-in-depth: it covers in-memory-constructed keys that bypass
        // parse, and protects against any future relaxation of rpgp's parser.
        // If it ever fires we still want a precise `KeyVersionMismatch`
        // instead of dispatching down the wrong SEIPD path.
        for subkey in &subkeys {
            let subkey_version = subkey.key.version();
            if subkey_version != primary_version {
                return Err(Error::KeyVersionMismatch {
                    existing: primary_version,
                    incoming: subkey_version,
                });
            }
        }

        encryption_keys.extend(subkeys);
    }

    if encryption_keys.is_empty() {
        return Err(Error::NoEncryptionSubkey);
    }

    // `recipients_version` is Some here because `recipient_keys` was non-empty
    // at the call site and the loop would have set it on the first iteration.
    let version = recipients_version.expect("non-empty recipient list sets the version");
    Ok((encryption_keys, version))
}

/// Shared SEIPDv2 message-assembly used by both the explicit `*_seipd_v2`
/// public entry points and the auto-dispatch path in
/// [`encrypt_bytes_to_multiple_with_algo`] for V6 recipients.
fn encrypt_with_seipd_v2(
    encryption_keys: &[pgp::composed::SignedPublicSubKey],
    plaintext: &[u8],
    armor: bool,
    sym_algo: SymmetricKeyAlgorithm,
) -> Result<Vec<u8>> {
    let mut rng = thread_rng();

    let mut builder = MessageBuilder::from_bytes("", plaintext.to_vec()).seipd_v2(
        &mut rng,
        sym_algo,
        AeadAlgorithm::Ocb,
        ChunkSize::default(),
    );

    for key in encryption_keys {
        builder
            .encrypt_to_key(&mut rng, key)
            .map_err(|e| Error::Crypto(e.to_string()))?;
    }

    if armor {
        let armored = builder
            .to_armored_string(&mut rng, None.into())
            .map_err(|e| Error::Crypto(e.to_string()))?;
        Ok(armored.into_bytes())
    } else {
        builder
            .to_vec(&mut rng)
            .map_err(|e| Error::Crypto(e.to_string()))
    }
}

/// Encrypt a file to a single recipient.
///
/// Reads the input file, encrypts it, and writes the result to the output file.
///
/// # Arguments
/// * `recipient_key` - The recipient's public key (armored or binary)
/// * `input` - Path to the input file
/// * `output` - Path to the output file
/// * `armor` - If true, output ASCII-armored; otherwise binary
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::encrypt_file;
///
/// let public_key = std::fs::read("recipient.asc").unwrap();
/// encrypt_file(&public_key, "document.pdf", "document.pdf.gpg", true).unwrap();
/// ```
pub fn encrypt_file(
    recipient_key: &[u8],
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    armor: bool,
) -> Result<()> {
    encrypt_file_to_multiple(&[recipient_key], input, output, armor)
}

/// Encrypt a file to multiple recipients.
///
/// # Arguments
/// * `recipient_keys` - Slice of recipient public keys (armored or binary)
/// * `input` - Path to the input file
/// * `output` - Path to the output file
/// * `armor` - If true, output ASCII-armored; otherwise binary
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::encrypt_file_to_multiple;
///
/// let alice_key = std::fs::read("alice.asc").unwrap();
/// let bob_key = std::fs::read("bob.asc").unwrap();
///
/// encrypt_file_to_multiple(
///     &[&alice_key, &bob_key],
///     "document.pdf",
///     "document.pdf.gpg",
///     true,
/// ).unwrap();
/// ```
pub fn encrypt_file_to_multiple(
    recipient_keys: &[&[u8]],
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    armor: bool,
) -> Result<()> {
    let plaintext = std::fs::read(input.as_ref())?;
    let ciphertext = encrypt_bytes_to_multiple(recipient_keys, &plaintext, armor)?;
    std::fs::write(output.as_ref(), ciphertext)?;
    Ok(())
}

/// Encrypt data from a reader to a file.
///
/// # Arguments
/// * `recipient_keys` - Slice of recipient public keys
/// * `reader` - Source of plaintext data
/// * `output` - Path to the output file
/// * `armor` - If true, output ASCII-armored
pub fn encrypt_reader_to_file<R: Read>(
    recipient_keys: &[&[u8]],
    mut reader: R,
    output: impl AsRef<Path>,
    armor: bool,
) -> Result<()> {
    let mut plaintext = Vec::new();
    reader.read_to_end(&mut plaintext)?;
    let ciphertext = encrypt_bytes_to_multiple(recipient_keys, &plaintext, armor)?;
    std::fs::write(output.as_ref(), ciphertext)?;
    Ok(())
}

/// Get the key IDs that a message was encrypted for.
///
/// # Arguments
/// * `ciphertext` - The encrypted message (armored or binary)
///
/// # Returns
/// A list of key IDs (hex strings) that can decrypt this message.
pub fn bytes_encrypted_for(ciphertext: &[u8]) -> Result<Vec<String>> {
    let mut key_ids = Vec::new();

    // Try to dearmor if it looks armored
    let data = if ciphertext.starts_with(b"-----BEGIN PGP") {
        let cursor = Cursor::new(ciphertext);
        let dearmor = Dearmor::new(cursor);
        let mut buf = Vec::new();
        let mut reader = BufReader::new(dearmor);
        reader.read_to_end(&mut buf)?;
        buf
    } else {
        ciphertext.to_vec()
    };

    // Parse packets and look for PKESK
    let parser = PacketParser::new(Cursor::new(&data));

    for packet_result in parser {
        match packet_result {
            Ok(packet) => {
                if let Packet::PublicKeyEncryptedSessionKey(pkesk) = packet {
                    let key_id = match pkesk {
                        PublicKeyEncryptedSessionKey::V3 { id, .. } => {
                            // KeyId uses Display with lowercase hex, convert to uppercase
                            format!("{}", id).to_uppercase()
                        }
                        PublicKeyEncryptedSessionKey::V6 { fingerprint, .. } => {
                            // V6 PKESK uses fingerprint
                            if let Some(fp) = fingerprint {
                                format!("{}", fp).to_uppercase()
                            } else {
                                // Anonymous recipient
                                continue;
                            }
                        }
                        PublicKeyEncryptedSessionKey::Other { .. } => {
                            // Unknown version, skip
                            continue;
                        }
                    };
                    key_ids.push(key_id);
                }
            }
            Err(_) => {
                // Stop on parsing error (we've probably hit encrypted data)
                break;
            }
        }
    }

    Ok(key_ids)
}

/// Get the key IDs that a file was encrypted for.
///
/// # Arguments
/// * `path` - Path to the encrypted file
///
/// # Returns
/// A list of key IDs (hex strings) that can decrypt this file.
pub fn file_encrypted_for(path: impl AsRef<Path>) -> Result<Vec<String>> {
    let ciphertext = std::fs::read(path.as_ref())?;
    bytes_encrypted_for(&ciphertext)
}

/// Helper to find valid encryption subkeys from a public key.
fn find_valid_encryption_subkeys(
    key: &SignedPublicKey,
) -> Result<Vec<pgp::composed::SignedPublicSubKey>> {
    let mut valid_keys = Vec::new();

    for subkey in &key.public_subkeys {
        // Check if the subkey can encrypt
        if !subkey.key.algorithm().can_encrypt() {
            continue;
        }

        // Check key flags in most recent binding signature (RFC 4880 §5.2.3.3)
        if !can_subkey_encrypt(&key.primary_key, subkey) {
            continue;
        }

        // Check if subkey is valid (not revoked, not expired)
        if !is_subkey_valid(&key.primary_key, subkey, false) {
            continue;
        }

        valid_keys.push(subkey.clone());
    }

    if valid_keys.is_empty() {
        return Err(Error::NoEncryptionSubkey);
    }

    Ok(valid_keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{create_key_simple, create_key_v6_simple, decrypt_bytes, get_pub_key, CipherSuite};

    /// Walk every PKESK packet in a (possibly armored) ciphertext and
    /// return the parsed enum values. Unlike [`bytes_encrypted_for`],
    /// which formats and drops anonymous V6 PKESKs, this helper preserves
    /// every PKESK so tests can match on the exact variant shape — in
    /// particular `V6 { fingerprint: None, .. }` for V6 hidden recipients.
    fn parse_pkesks(ciphertext: &[u8]) -> Vec<PublicKeyEncryptedSessionKey> {
        let data = if ciphertext.starts_with(b"-----BEGIN PGP") {
            let cursor = Cursor::new(ciphertext);
            let dearmor = Dearmor::new(cursor);
            let mut buf = Vec::new();
            let mut reader = BufReader::new(dearmor);
            reader.read_to_end(&mut buf).expect("dearmor");
            buf
        } else {
            ciphertext.to_vec()
        };
        let parser = PacketParser::new(Cursor::new(&data));
        let mut out = Vec::new();
        for packet_result in parser {
            match packet_result {
                Ok(Packet::PublicKeyEncryptedSessionKey(pkesk)) => out.push(pkesk),
                Ok(_) => {}
                // Stop walking at the first parse error — usually the
                // ciphertext body, which we can't decode without the key.
                Err(_) => break,
            }
        }
        out
    }

    /// `sign_and_encrypt_to_multiple_with_hidden` must emit at least one
    /// PKESK that exposes the visible recipient's identifier and at least
    /// one PKESK that hides the hidden recipient. This V4-keys test covers
    /// the V3 wildcard form; the V6 omitted-fingerprint form is covered
    /// separately by
    /// [`sign_encrypt_v6_with_hidden_omits_fingerprint_in_pkesk`]. Both
    /// recipients must still decrypt the same plaintext.
    ///
    /// The assertions deliberately AVOID pinning the PKESK count: a
    /// recipient key with multiple encryption-capable subkeys legitimately
    /// produces multiple PKESKs (one per subkey). Asserting an exact count
    /// would break the test the day someone adds a second encryption
    /// subkey to `create_key_simple`'s output.
    #[test]
    fn sign_encrypt_with_hidden_emits_wildcard_keyid_for_hidden_recipients() {
        let alice = create_key_simple("alice-pw", &["Alice <alice@example.com>"]).unwrap();
        let bob = create_key_simple("bob-pw", &["Bob <bob@example.com>"]).unwrap();
        let carol = create_key_simple("carol-pw", &["Carol <carol@example.com>"]).unwrap();

        let bob_pub = get_pub_key(&bob.secret_key).unwrap();
        let carol_pub = get_pub_key(&carol.secret_key).unwrap();

        let ct = sign_and_encrypt_to_multiple_with_hidden(
            &alice.secret_key,
            "alice-pw",
            &[bob_pub.as_bytes()],
            &[carol_pub.as_bytes()],
            b"the secret is forty-two",
            true,
        )
        .expect("encrypt with hidden recipients");

        // PKESK enumeration: at least one wildcard (Carol, hidden) and at
        // least one non-wildcard (Bob, visible). Note: `bytes_encrypted_for`
        // emits the wildcard key id for V3 PKESK anonymous recipients and
        // *skips* V6 PKESK anonymous recipients — these tests use V4 keys
        // (the default of `create_key_simple`) so the wildcard form is
        // what shows up.
        let key_ids = bytes_encrypted_for(&ct).expect("enumerate PKESKs");
        let wildcard = "0000000000000000";
        assert!(
            key_ids.iter().any(|id| id.eq_ignore_ascii_case(wildcard)),
            "expected at least one wildcard PKESK id (Carol hidden), got {:?}",
            key_ids
        );
        assert!(
            key_ids.iter().any(|id| !id.eq_ignore_ascii_case(wildcard)),
            "expected at least one non-wildcard PKESK id (Bob visible), got {:?}",
            key_ids
        );

        // Both recipients still decrypt to the same plaintext.
        let pt_bob = decrypt_bytes(&bob.secret_key, &ct, "bob-pw").unwrap();
        let pt_carol = decrypt_bytes(&carol.secret_key, &ct, "carol-pw").unwrap();
        assert_eq!(pt_bob, b"the secret is forty-two");
        assert_eq!(pt_bob, pt_carol);
    }

    /// `encrypt_bytes_to_multiple_with_hidden` (no signer) is the
    /// equivalent primitive for encrypt-only PGP/MIME messages. Same
    /// wildcard-PKESK behaviour, same dual decryptability.
    ///
    /// Assertions are presence-based (at least one wildcard + at least
    /// one non-wildcard PKESK), not count-based — see the sibling test
    /// above for the rationale.
    #[test]
    fn encrypt_only_with_hidden_emits_wildcard_keyid_for_hidden_recipients() {
        let bob = create_key_simple("bob-pw", &["Bob <bob@example.com>"]).unwrap();
        let carol = create_key_simple("carol-pw", &["Carol <carol@example.com>"]).unwrap();
        let bob_pub = get_pub_key(&bob.secret_key).unwrap();
        let carol_pub = get_pub_key(&carol.secret_key).unwrap();

        let ct = encrypt_bytes_to_multiple_with_hidden(
            &[bob_pub.as_bytes()],
            &[carol_pub.as_bytes()],
            b"no signer",
            true,
        )
        .expect("encrypt-only with hidden");

        let key_ids = bytes_encrypted_for(&ct).expect("enumerate PKESKs");
        let wildcard = "0000000000000000";
        assert!(
            key_ids.iter().any(|id| id.eq_ignore_ascii_case(wildcard)),
            "expected at least one wildcard PKESK id (Carol hidden), got {:?}",
            key_ids
        );
        assert!(
            key_ids.iter().any(|id| !id.eq_ignore_ascii_case(wildcard)),
            "expected at least one non-wildcard PKESK id (Bob visible), got {:?}",
            key_ids
        );

        // Bob and Carol both decrypt.
        assert_eq!(
            decrypt_bytes(&bob.secret_key, &ct, "bob-pw").unwrap(),
            b"no signer"
        );
        assert_eq!(
            decrypt_bytes(&carol.secret_key, &ct, "carol-pw").unwrap(),
            b"no signer"
        );
    }

    /// At least one recipient must be supplied across the two lists —
    /// both empty is rejected. Prevents accidentally producing a
    /// "header-only" OpenPGP message that no-one can decrypt.
    #[test]
    fn sign_encrypt_with_hidden_rejects_empty_recipient_lists() {
        let alice = create_key_simple("alice-pw", &["Alice <alice@example.com>"]).unwrap();
        let err = sign_and_encrypt_to_multiple_with_hidden(
            &alice.secret_key,
            "alice-pw",
            &[],
            &[],
            b"nope",
            true,
        )
        .unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)));
    }

    /// A hidden-only recipient list is accepted: the entire send is Bcc.
    /// This pins that the implementation doesn't accidentally require at
    /// least one visible recipient (chithi may need this for newsletter-
    /// style sends where every recipient is anonymised).
    ///
    /// Assertion shape: at least one PKESK is present and *every* PKESK is
    /// a wildcard (no visible recipient leaked any identifier). Robust to
    /// recipient keys that carry more than one encryption subkey.
    #[test]
    fn sign_encrypt_with_hidden_accepts_hidden_only() {
        let alice = create_key_simple("alice-pw", &["Alice <alice@example.com>"]).unwrap();
        let bob = create_key_simple("bob-pw", &["Bob <bob@example.com>"]).unwrap();
        let bob_pub = get_pub_key(&bob.secret_key).unwrap();

        let ct = sign_and_encrypt_to_multiple_with_hidden(
            &alice.secret_key,
            "alice-pw",
            &[],
            &[bob_pub.as_bytes()],
            b"hidden-only",
            true,
        )
        .expect("encrypt with only hidden recipients");

        let key_ids = bytes_encrypted_for(&ct).expect("enumerate PKESKs");
        let wildcard = "0000000000000000";
        assert!(
            !key_ids.is_empty(),
            "expected at least one PKESK; got an empty enumeration"
        );
        assert!(
            key_ids.iter().all(|id| id.eq_ignore_ascii_case(wildcard)),
            "expected every PKESK to be a wildcard (hidden-only send), got {:?}",
            key_ids
        );
        let pt = decrypt_bytes(&bob.secret_key, &ct, "bob-pw").unwrap();
        assert_eq!(pt, b"hidden-only");
    }

    /// V6 keys exercise the SEIPD-v2 / `encrypt_to_key_anonymous` path —
    /// hidden recipients receive a V6 PKESK whose optional `fingerprint`
    /// field is `None` (RFC 9580 §5.1.2). Pin both the packet shape and
    /// that both recipients still decrypt to the same plaintext.
    ///
    /// `bytes_encrypted_for` skips anonymous V6 PKESKs (no identifier to
    /// report), so we walk the packet stream directly via `parse_pkesks`.
    #[test]
    fn sign_encrypt_v6_with_hidden_omits_fingerprint_in_pkesk() {
        let alice = create_key_v6_simple(
            "alice-pw",
            &["Alice <alice@example.com>"],
            CipherSuite::Cv25519Modern,
        )
        .unwrap();
        let bob = create_key_v6_simple(
            "bob-pw",
            &["Bob <bob@example.com>"],
            CipherSuite::Cv25519Modern,
        )
        .unwrap();
        let carol = create_key_v6_simple(
            "carol-pw",
            &["Carol <carol@example.com>"],
            CipherSuite::Cv25519Modern,
        )
        .unwrap();
        let bob_pub = get_pub_key(&bob.secret_key).unwrap();
        let carol_pub = get_pub_key(&carol.secret_key).unwrap();

        let ct = sign_and_encrypt_to_multiple_with_hidden(
            &alice.secret_key,
            "alice-pw",
            &[bob_pub.as_bytes()],
            &[carol_pub.as_bytes()],
            b"v6 hidden bcc",
            true,
        )
        .expect("v6 encrypt with hidden recipients");

        let pkesks = parse_pkesks(&ct);
        assert!(
            !pkesks.is_empty(),
            "expected at least one PKESK in the V6 ciphertext"
        );
        // Every PKESK must be V6 (the recipients are V6 keys).
        for p in &pkesks {
            assert!(
                matches!(p, PublicKeyEncryptedSessionKey::V6 { .. }),
                "expected V6 PKESK packets, got {:?}",
                p
            );
        }
        // At least one V6 PKESK has fingerprint = None (Carol, hidden).
        assert!(
            pkesks.iter().any(|p| matches!(
                p,
                PublicKeyEncryptedSessionKey::V6 {
                    fingerprint: None,
                    ..
                }
            )),
            "expected at least one V6 PKESK with omitted fingerprint (Carol hidden), got {:?}",
            pkesks
        );
        // At least one V6 PKESK has fingerprint = Some(_) (Bob, visible).
        assert!(
            pkesks.iter().any(|p| matches!(
                p,
                PublicKeyEncryptedSessionKey::V6 {
                    fingerprint: Some(_),
                    ..
                }
            )),
            "expected at least one V6 PKESK with a fingerprint (Bob visible), got {:?}",
            pkesks
        );

        // Both recipients still decrypt to the same plaintext.
        let pt_bob = decrypt_bytes(&bob.secret_key, &ct, "bob-pw").unwrap();
        let pt_carol = decrypt_bytes(&carol.secret_key, &ct, "carol-pw").unwrap();
        assert_eq!(pt_bob, b"v6 hidden bcc");
        assert_eq!(pt_bob, pt_carol);
    }

    /// Encrypt-only V6 sibling of the test above: no signer, same V6
    /// PKESK shape assertion (hidden ⇒ `fingerprint: None`; visible ⇒
    /// `fingerprint: Some(_)`).
    #[test]
    fn encrypt_only_v6_with_hidden_omits_fingerprint_in_pkesk() {
        let bob = create_key_v6_simple(
            "bob-pw",
            &["Bob <bob@example.com>"],
            CipherSuite::Cv25519Modern,
        )
        .unwrap();
        let carol = create_key_v6_simple(
            "carol-pw",
            &["Carol <carol@example.com>"],
            CipherSuite::Cv25519Modern,
        )
        .unwrap();
        let bob_pub = get_pub_key(&bob.secret_key).unwrap();
        let carol_pub = get_pub_key(&carol.secret_key).unwrap();

        let ct = encrypt_bytes_to_multiple_with_hidden(
            &[bob_pub.as_bytes()],
            &[carol_pub.as_bytes()],
            b"v6 no signer",
            true,
        )
        .expect("v6 encrypt-only with hidden");

        let pkesks = parse_pkesks(&ct);
        assert!(!pkesks.is_empty());
        for p in &pkesks {
            assert!(
                matches!(p, PublicKeyEncryptedSessionKey::V6 { .. }),
                "expected V6 PKESK packets in V6 encrypt-only ciphertext, got {:?}",
                p
            );
        }
        assert!(
            pkesks.iter().any(|p| matches!(
                p,
                PublicKeyEncryptedSessionKey::V6 {
                    fingerprint: None,
                    ..
                }
            )),
            "expected at least one V6 PKESK with omitted fingerprint (Carol hidden), got {:?}",
            pkesks
        );
        assert!(
            pkesks.iter().any(|p| matches!(
                p,
                PublicKeyEncryptedSessionKey::V6 {
                    fingerprint: Some(_),
                    ..
                }
            )),
            "expected at least one V6 PKESK with a fingerprint (Bob visible), got {:?}",
            pkesks
        );

        assert_eq!(
            decrypt_bytes(&bob.secret_key, &ct, "bob-pw").unwrap(),
            b"v6 no signer"
        );
        assert_eq!(
            decrypt_bytes(&carol.secret_key, &ct, "carol-pw").unwrap(),
            b"v6 no signer"
        );
    }

    /// `collect_visible_and_hidden_keys` rejects a cross-list V4/V6 split:
    /// a V4 visible recipient + V6 hidden recipient (or vice versa) must
    /// surface as [`Error::KeyVersionMismatch`] before any encryption
    /// happens, because RFC 9580 §5.1.2 / §5.3.2 forbid V6 PKESKs
    /// preceding a V1 SEIPD and V3 PKESKs preceding a V2 SEIPD. Without
    /// this guard the caller could not route the message down a single
    /// SEIPD path.
    ///
    /// One V4 key + one V6 key cover all four permutations (two public
    /// entry points × two orderings) without paying the V6-keygen cost
    /// more than once.
    #[test]
    fn with_hidden_rejects_cross_list_v4_v6_split() {
        let alice_v4 = create_key_simple("alice-pw", &["Alice <alice@example.com>"]).unwrap();
        let bob_v4 = create_key_simple("bob-pw", &["Bob <bob@example.com>"]).unwrap();
        let carol_v6 = create_key_v6_simple(
            "carol-pw",
            &["Carol <carol@example.com>"],
            CipherSuite::Cv25519Modern,
        )
        .unwrap();
        let bob_v4_pub = get_pub_key(&bob_v4.secret_key).unwrap();
        let carol_v6_pub = get_pub_key(&carol_v6.secret_key).unwrap();

        let assert_mismatch = |err: Error, label: &str| {
            assert!(
                matches!(err, Error::KeyVersionMismatch { .. }),
                "{label}: expected KeyVersionMismatch, got {err:?}",
            );
        };

        // sign_and_encrypt_to_multiple_with_hidden: V4 visible + V6 hidden.
        assert_mismatch(
            sign_and_encrypt_to_multiple_with_hidden(
                &alice_v4.secret_key,
                "alice-pw",
                &[bob_v4_pub.as_bytes()],
                &[carol_v6_pub.as_bytes()],
                b"payload",
                true,
            )
            .unwrap_err(),
            "sign+encrypt V4-visible + V6-hidden",
        );

        // sign_and_encrypt_to_multiple_with_hidden: V6 visible + V4 hidden
        // (swap the two sides — the guard must fire either way).
        assert_mismatch(
            sign_and_encrypt_to_multiple_with_hidden(
                &alice_v4.secret_key,
                "alice-pw",
                &[carol_v6_pub.as_bytes()],
                &[bob_v4_pub.as_bytes()],
                b"payload",
                true,
            )
            .unwrap_err(),
            "sign+encrypt V6-visible + V4-hidden",
        );

        // encrypt_bytes_to_multiple_with_hidden: V4 visible + V6 hidden.
        assert_mismatch(
            encrypt_bytes_to_multiple_with_hidden(
                &[bob_v4_pub.as_bytes()],
                &[carol_v6_pub.as_bytes()],
                b"payload",
                true,
            )
            .unwrap_err(),
            "encrypt-only V4-visible + V6-hidden",
        );

        // encrypt_bytes_to_multiple_with_hidden: V6 visible + V4 hidden.
        assert_mismatch(
            encrypt_bytes_to_multiple_with_hidden(
                &[carol_v6_pub.as_bytes()],
                &[bob_v4_pub.as_bytes()],
                b"payload",
                true,
            )
            .unwrap_err(),
            "encrypt-only V6-visible + V4-hidden",
        );
    }
}
