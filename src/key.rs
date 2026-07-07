//! OpenPGP key generation and key-management helpers.
//!
//! [`create_key_simple`] creates the default V4 certificate for broad
//! compatibility. [`create_key_v6_simple`] creates an RFC 9580 V6 certificate
//! and requires a V6-compatible [`CipherSuite`], such as
//! [`CipherSuite::Cv25519Modern`] or [`CipherSuite::Cv448Modern`].
//!
//! Management helpers operate on armored or binary key bytes. They preserve the
//! original key packet version when adding or revoking user IDs, updating
//! expiration, changing passwords, and merging public/secret key material.

use chrono::{DateTime, Utc};
use pgp::composed::{
    EncryptionCaps, SecretKeyParamsBuilder, SignedKeyDetails, SignedPublicKey, SignedSecretKey,
    SubkeyParamsBuilder,
};
use pgp::packet::{PacketTrait, SignatureConfig, SignatureType, Subpacket, SubpacketData, UserId};
use pgp::types::{KeyDetails, KeyVersion, PacketHeaderVersion, Password, SignedUser, Timestamp};
use rand::thread_rng;
use std::time::SystemTime;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::internal::{
    extract_uid_email, fingerprint_to_hex, is_primary_secret_key_revoked, parse_key,
    parse_public_key, parse_secret_key, public_key_to_armored, secret_key_to_bytes,
    validate_secret_signing_usage, SigningKeyUsage,
};
use crate::types::{CertificationType, CipherSuite, GeneratedKey, SubkeyFlags};

fn ensure_secret_primary_not_revoked(secret_key: &SignedSecretKey) -> Result<()> {
    if is_primary_secret_key_revoked(secret_key) {
        return Err(Error::KeyRevoked);
    }
    Ok(())
}

fn ensure_secret_primary_usable_for_external_certification(
    secret_key: &SignedSecretKey,
) -> Result<()> {
    validate_secret_signing_usage(secret_key, SigningKeyUsage::DataSignature)
}

/// Shared key-generation implementation used by every public `create_key*`
/// entry point. Accepts the OpenPGP key packet version explicitly so the
/// public V4 and V6 variants remain slim, single-purpose wrappers.
///
/// Kept private: callers pick the versioned wrapper that matches their intent.
#[allow(clippy::too_many_arguments)]
fn create_key_internal(
    password: &str,
    user_ids: &[&str],
    cipher: CipherSuite,
    creation_time: Option<DateTime<Utc>>,
    expiration_time: Option<DateTime<Utc>>,
    subkeys_expiration: Option<DateTime<Utc>>,
    which_keys: SubkeyFlags,
    can_primary_sign: bool,
    can_primary_expire: bool,
    key_version: KeyVersion,
) -> Result<GeneratedKey> {
    if user_ids.is_empty() {
        return Err(Error::InvalidInput(
            "At least one user ID is required".to_string(),
        ));
    }

    // RFC 9580 §9.2 forbids Ed25519Legacy + ECDH(Curve25519) under V6. Reject
    // the combo up front so the error message points at the mistake.
    if key_version == KeyVersion::V6 && !cipher.is_allowed_for_v6() {
        return Err(Error::InvalidInput(format!(
            "Cipher suite {} is not permitted for V6 keys — use Cv25519Modern or Cv448Modern",
            cipher.name()
        )));
    }

    let mut rng = thread_rng();

    // Get key types for primary and subkeys
    let primary_key_type = cipher.primary_key_type();
    let encryption_key_type = cipher.encryption_key_type();

    // Note: Key expiration is set via self-signatures after generation in pgp 0.19.
    // The builder does not support setting expiration during key creation,
    // but creation time CAN be set via the created_at field.
    let creation_timestamp = match creation_time {
        Some(dt) => {
            let systime: SystemTime = dt.into();
            Some(
                Timestamp::try_from(systime)
                    .map_err(|e| Error::InvalidInput(format!("Invalid creation time: {}", e)))?,
            )
        }
        None => None,
    };

    // Build subkeys based on flags
    let mut subkeys = Vec::new();

    if which_keys.encryption {
        let mut enc_builder = SubkeyParamsBuilder::default();
        enc_builder
            .version(key_version)
            .key_type(encryption_key_type)
            .can_encrypt(EncryptionCaps::All)
            .can_sign(false)
            .can_authenticate(false);

        if let Some(ts) = creation_timestamp {
            enc_builder.created_at(ts);
        }

        if !password.is_empty() {
            enc_builder.passphrase(Some(password.to_string()));
        }

        subkeys.push(
            enc_builder
                .build()
                .map_err(|e| Error::Crypto(e.to_string()))?,
        );
    }

    if which_keys.signing {
        let mut sign_builder = SubkeyParamsBuilder::default();
        sign_builder
            .version(key_version)
            .key_type(primary_key_type.clone())
            .can_encrypt(EncryptionCaps::None)
            .can_sign(true)
            .can_authenticate(false);

        if let Some(ts) = creation_timestamp {
            sign_builder.created_at(ts);
        }

        if !password.is_empty() {
            sign_builder.passphrase(Some(password.to_string()));
        }

        subkeys.push(
            sign_builder
                .build()
                .map_err(|e| Error::Crypto(e.to_string()))?,
        );
    }

    if which_keys.authentication {
        let mut auth_builder = SubkeyParamsBuilder::default();
        auth_builder
            .version(key_version)
            .key_type(primary_key_type.clone())
            .can_encrypt(EncryptionCaps::None)
            .can_sign(false)
            .can_authenticate(true);

        if let Some(ts) = creation_timestamp {
            auth_builder.created_at(ts);
        }

        if !password.is_empty() {
            auth_builder.passphrase(Some(password.to_string()));
        }

        subkeys.push(
            auth_builder
                .build()
                .map_err(|e| Error::Crypto(e.to_string()))?,
        );
    }

    // Build primary key params
    let mut key_params = SecretKeyParamsBuilder::default();
    key_params
        .version(key_version)
        .key_type(primary_key_type)
        .can_certify(true)
        .can_sign(can_primary_sign)
        .can_encrypt(EncryptionCaps::None)
        .primary_user_id(user_ids[0].to_string());

    if let Some(ts) = creation_timestamp {
        key_params.created_at(ts);
    }

    // Add additional user IDs
    if user_ids.len() > 1 {
        let additional_uids: Vec<String> = user_ids[1..].iter().map(|s| s.to_string()).collect();
        key_params.user_ids(additional_uids);
    }

    if !password.is_empty() {
        key_params.passphrase(Some(password.to_string()));
    }

    key_params.subkeys(subkeys);

    // Generate the key
    let secret_key_params = key_params
        .build()
        .map_err(|e| Error::Crypto(e.to_string()))?;

    let secret_key = secret_key_params
        .generate(&mut rng)
        .map_err(|e| Error::Crypto(e.to_string()))?;

    // Get fingerprint from the public key's primary key
    let public_key = secret_key.to_public_key();
    let fingerprint = fingerprint_to_hex(&public_key.primary_key);

    // Export secret key (binary, zeroized on drop)
    let mut final_secret_key_bytes: Zeroizing<Vec<u8>> = secret_key_to_bytes(&secret_key)?;

    // Apply primary key expiration if requested
    if can_primary_expire {
        if let Some(exp_time) = expiration_time {
            final_secret_key_bytes = Zeroizing::new(update_primary_expiry(
                &final_secret_key_bytes,
                exp_time,
                password,
            )?);
        }
    }

    // Apply subkey expiration if requested
    if let Some(subkey_exp_time) = subkeys_expiration {
        let current_info = crate::parse::parse_key_bytes(&final_secret_key_bytes, true)?;
        let subkey_fps: Vec<String> = current_info
            .subkeys
            .iter()
            .map(|s| s.fingerprint.clone())
            .collect();
        let subkey_fp_refs: Vec<&str> = subkey_fps.iter().map(|s| s.as_str()).collect();
        if !subkey_fp_refs.is_empty() {
            final_secret_key_bytes = Zeroizing::new(update_subkeys_expiry(
                &final_secret_key_bytes,
                &subkey_fp_refs,
                subkey_exp_time,
                password,
            )?);
        }
    }

    // Re-derive public key from potentially-updated secret key
    let final_secret = parse_secret_key(&final_secret_key_bytes)?;
    let final_public = final_secret.to_public_key();
    let public_key_armored = public_key_to_armored(&final_public)?;

    Ok(GeneratedKey {
        public_key: public_key_armored,
        secret_key: final_secret_key_bytes,
        fingerprint,
    })
}

/// Generate a V4 (RFC 4880) OpenPGP key pair.
///
/// This is the compatibility-first entry point: it produces the key format
/// that every existing OpenPGP implementation understands. For V6 (RFC 9580)
/// use [`create_key_v6`]; both share the same parameter list so call sites
/// can switch versions by changing one function name.
///
/// # Arguments
/// * `password` - Password to protect the secret key
/// * `user_ids` - List of user IDs (e.g., "Name <email@example.com>")
/// * `cipher` - Cipher suite to use (see [`CipherSuite`] for options)
/// * `creation_time` - Optional creation time (defaults to now)
/// * `expiration_time` - Optional expiration time for the primary key
/// * `subkeys_expiration` - Optional expiration time for subkeys
/// * `which_keys` - Which subkeys to generate (see [`SubkeyFlags`])
/// * `can_primary_sign` - Whether the primary key can sign
/// * `can_primary_expire` - Whether the primary key can expire
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{create_key, CipherSuite, SubkeyFlags};
///
/// let key = create_key(
///     "my_password",
///     &["Alice <alice@example.com>"],
///     CipherSuite::Cv25519,
///     None, None, None,
///     SubkeyFlags::all(),
///     false,
///     true,
/// ).unwrap();
/// ```
#[allow(clippy::too_many_arguments)]
pub fn create_key(
    password: &str,
    user_ids: &[&str],
    cipher: CipherSuite,
    creation_time: Option<DateTime<Utc>>,
    expiration_time: Option<DateTime<Utc>>,
    subkeys_expiration: Option<DateTime<Utc>>,
    which_keys: SubkeyFlags,
    can_primary_sign: bool,
    can_primary_expire: bool,
) -> Result<GeneratedKey> {
    create_key_internal(
        password,
        user_ids,
        cipher,
        creation_time,
        expiration_time,
        subkeys_expiration,
        which_keys,
        can_primary_sign,
        can_primary_expire,
        KeyVersion::V4,
    )
}

/// Generate a V6 (RFC 9580) OpenPGP key pair.
///
/// Parameter list mirrors [`create_key`] exactly; the only difference is the
/// packet version produced. The legacy [`CipherSuite::Cv25519`] is forbidden
/// under V6 (RFC 9580 §9.2) and returns `Error::InvalidInput`; use
/// [`CipherSuite::Cv25519Modern`] or [`CipherSuite::Cv448Modern`] instead.
/// All subkeys are V6 to satisfy the primary/subkey version-parity rule in
/// RFC 9580 §10.1.1.
///
/// Password-protected V6 secret keys use rpgp's V6 defaults (Argon2id S2K +
/// AES-256 + OCB) per RFC 9580 §3.7.2.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{create_key_v6, CipherSuite, SubkeyFlags};
///
/// let key = create_key_v6(
///     "my_password",
///     &["Alice <alice@example.com>"],
///     CipherSuite::Cv25519Modern,
///     None, None, None,
///     SubkeyFlags::all(),
///     false,
///     true,
/// ).unwrap();
/// ```
#[allow(clippy::too_many_arguments)]
pub fn create_key_v6(
    password: &str,
    user_ids: &[&str],
    cipher: CipherSuite,
    creation_time: Option<DateTime<Utc>>,
    expiration_time: Option<DateTime<Utc>>,
    subkeys_expiration: Option<DateTime<Utc>>,
    which_keys: SubkeyFlags,
    can_primary_sign: bool,
    can_primary_expire: bool,
) -> Result<GeneratedKey> {
    create_key_internal(
        password,
        user_ids,
        cipher,
        creation_time,
        expiration_time,
        subkeys_expiration,
        which_keys,
        can_primary_sign,
        can_primary_expire,
        KeyVersion::V6,
    )
}

/// Generate a V4 key with default settings (Cv25519, all subkeys).
///
/// Convenience wrapper around [`create_key`] for the common case.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::create_key_simple;
///
/// let key = create_key_simple("my_password", &["Alice <alice@example.com>"]).unwrap();
/// println!("Fingerprint: {}", key.fingerprint);
/// ```
pub fn create_key_simple(password: &str, user_ids: &[&str]) -> Result<GeneratedKey> {
    create_key(
        password,
        user_ids,
        CipherSuite::Cv25519,
        None,
        None,
        None,
        SubkeyFlags::all(),
        false,
        true,
    )
}

/// Generate a V6 (RFC 9580) key with default settings.
///
/// Convenience wrapper around [`create_key`] that produces a V6 key with all
/// subkeys and no expiration. Unlike [`create_key_simple`], V6 cannot use the
/// legacy [`CipherSuite::Cv25519`] suite — callers must pick one of the modern
/// suites. The default here is [`CipherSuite::Cv25519Modern`] (Ed25519 + X25519).
///
/// # Arguments
/// * `password` - Password to protect the secret key
/// * `user_ids` - List of user IDs (e.g., "Name <email@example.com>")
/// * `cipher` - Cipher suite to use. Must satisfy [`CipherSuite::is_allowed_for_v6`];
///   `Cv25519` is rejected.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{create_key_v6_simple, CipherSuite};
///
/// let key = create_key_v6_simple(
///     "my_password",
///     &["Alice <alice@example.com>"],
///     CipherSuite::Cv25519Modern,
/// ).unwrap();
/// ```
pub fn create_key_v6_simple(
    password: &str,
    user_ids: &[&str],
    cipher: CipherSuite,
) -> Result<GeneratedKey> {
    create_key_v6(
        password,
        user_ids,
        cipher,
        None,
        None,
        None,
        SubkeyFlags::all(),
        false,
        true,
    )
}

/// Export the public key as ASCII armor.
///
/// Extracts the public key portion from a key (which may contain
/// secret key material) and returns it as ASCII-armored text.
///
/// # Arguments
/// * `key_data` - The key data (public or secret key)
///
/// # Returns
/// ASCII-armored public key suitable for sharing.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{create_key_simple, get_pub_key};
///
/// let key = create_key_simple("password", &["Alice <alice@example.com>"]).unwrap();
///
/// // Extract public key from the secret key
/// let public_key = get_pub_key(&key.secret_key).unwrap();
/// println!("Share this public key:\n{}", public_key);
/// ```
pub fn get_pub_key(key_data: &[u8]) -> Result<String> {
    let secret_key = parse_secret_key(key_data)?;
    let public_key = SignedPublicKey::from(secret_key);
    public_key_to_armored(&public_key)
}

/// Export an Autocrypt-Level-1-compliant transferable public key (binary).
///
/// Returns the binary OpenPGP bytes the caller should base64-encode into the
/// `keydata=` attribute of the `Autocrypt:` mail header (RFC-ish — see
/// https://autocrypt.org/level1.html#openpgp-based-key-data). The bytes are
/// a minimised transferable public key per Autocrypt §5.2:
///
/// - the primary public-key packet
/// - **exactly one** User ID packet whose email address matches `addr`
///   (other UIDs and User Attribute packets are stripped — Autocrypt is
///   per-address, and every mail carries this header, so size matters)
/// - the subkey packets, each followed only by its **self**-signatures
/// - no third-party certifications anywhere — including no third-party
///   key-revocation signatures from a designated revoker (RFC 4880
///   §5.2.3.15); only self-revocations from the primary are kept
///
/// Self-signatures are kept on revoked components so receivers can still
/// honour primary-key and subkey revocations the primary issued itself.
///
/// If more than one UID matches `addr` (e.g. a key with two UIDs sharing
/// the same email but different display names), exactly one is selected
/// deterministically. Only UIDs with at least one cryptographically
/// verified self-cert are eligible. Among those, the UID flagged as
/// primary (`PrimaryUserId` subpacket on a verified self-cert) wins;
/// otherwise the first matching UID in packet order. Checking
/// `PrimaryUserId` only on verified signatures means an attacker who can
/// splice packets cannot force selection by adding a forged "primary"
/// flag — the flag is meaningless unless the signature it sits in
/// actually verifies. This also keeps the on-the-wire bytes stable
/// across export calls and avoids leaking an alternate display name
/// into every outbound message.
///
/// # Arguments
/// * `key_data` - Key data (armored or binary), public or secret. If a
///   secret key is provided, the public material is extracted from it.
/// * `addr` - Email address selecting which UID to keep (e.g.
///   `"alice@example.com"`). Comparison is case-insensitive on the local
///   and domain parts.
///
/// # Errors
/// Returns [`Error::InvalidInput`] if:
/// - `addr` doesn't match any UID on the key, or
/// - the matching UID has no cryptographically valid self-signature
///   (RFC 4880 §11.1 requires at least one signature after each UID
///   packet — producing a UID with zero self-sigs would emit
///   structurally-invalid Autocrypt keydata that every receiving MUA
///   would reject).
///
/// Subkeys without a verified `SubkeyBinding` signature are silently
/// dropped from the output (also per §11.1: a subkey packet must be
/// followed by a binding signature, or it isn't part of the
/// transferable public key).
pub fn export_public_for_autocrypt(key_data: &[u8], addr: &str) -> Result<Vec<u8>> {
    use pgp::ser::Serialize;

    let (public_key, _) = parse_key(key_data)?;
    let primary = &public_key.primary_key;
    let addr_lc = addr.trim().to_ascii_lowercase();

    // Pick exactly ONE UID matching `addr` (Autocrypt §2.1.1: "exactly one
    // user id packet"). Multiple UIDs can carry the same email address —
    // an extra UID with a different display name, an `add_uid` mistake,
    // etc. — so select deterministically among UIDs that have at least
    // one cryptographically valid self-cert:
    //   1. prefer a matching UID where a verified self-cert carries the
    //      PrimaryUserId subpacket (RFC 4880 §5.2.3.19);
    //   2. otherwise the first matching UID in packet order.
    // The PrimaryUserId flag is only meaningful when it appears on a
    // signature the primary actually issued — an attacker who can splice
    // packets could otherwise force selection of a UID with no usable
    // self-cert by marking it "primary" via a forged signature. Verifying
    // first defeats that.
    let matches_addr = |u: &SignedUser| {
        let uid_str = String::from_utf8_lossy(u.id.id());
        extract_uid_email(&uid_str)
            .map(|e| e.to_ascii_lowercase() == addr_lc)
            .unwrap_or(false)
    };

    // Precompute (uid, verified_self_sigs) for every UID matching `addr`,
    // dropping the ones whose verified self-sig list is empty.
    let candidates: Vec<(&SignedUser, Vec<pgp::packet::Signature>)> = public_key
        .details
        .users
        .iter()
        .filter(|u| matches_addr(u))
        .map(|u| {
            let verified: Vec<pgp::packet::Signature> = u
                .signatures
                .iter()
                .filter(|sig| is_verified_self_uid_signature(sig, primary, u))
                .cloned()
                .collect();
            (u, verified)
        })
        .filter(|(_, sigs)| !sigs.is_empty())
        .collect();

    // RFC 4880 §11.1: a transferable public key requires at least one
    // signature following each User ID packet. If NO matching UID has a
    // verified self-cert we'd be forced to emit a packet sequence that
    // isn't a valid transferable public key; refuse rather than produce
    // keydata every receiving MUA will reject. The distinction between
    // "no UID matches" and "matching UID(s) but none verified" matters
    // for debugging, so the two paths report different messages.
    if candidates.is_empty() {
        let any_matching_uid = public_key.details.users.iter().any(matches_addr);
        return Err(Error::InvalidInput(if any_matching_uid {
            format!(
                "no User ID matching {addr} has a verified self-signature; \
                 cannot produce a structurally-valid Autocrypt key"
            )
        } else {
            format!("no User ID on key matches address {addr}")
        }));
    }

    // Pick by primary-from-verified-sig, else first.
    let (picked_user, user_self_sigs) = candidates
        .iter()
        .find(|(_, sigs)| sigs.iter().any(|s| s.is_primary()))
        .cloned()
        .unwrap_or_else(|| candidates[0].clone());
    let matching_users = vec![SignedUser::new(picked_user.id.clone(), user_self_sigs)];

    // Subkey binding/revocation signatures: keep sigs that verify against
    // the primary, and DROP any subkey that ends up with no verified
    // SubkeyBinding (0x18). RFC 4880 §11.1 requires a binding signature
    // after each subkey packet — a subkey without one isn't part of the
    // transferable public key and any receiving MUA would either ignore
    // it or reject the whole import. Autocrypt is fine with signing
    // subkeys present, and downstream MUAs may need them to verify the
    // sender's signatures, so we don't filter by capability here.
    let stripped_subkeys: Vec<pgp::composed::SignedPublicSubKey> = public_key
        .public_subkeys
        .iter()
        .filter_map(|sk| {
            let self_sigs: Vec<pgp::packet::Signature> = sk
                .signatures
                .iter()
                .filter(|sig| is_verified_self_subkey_signature(sig, primary, &sk.key))
                .cloned()
                .collect();
            let has_binding = self_sigs
                .iter()
                .any(|sig| sig.typ() == Some(SignatureType::SubkeyBinding));
            if !has_binding {
                return None;
            }
            Some(pgp::composed::SignedPublicSubKey {
                key: sk.key.clone(),
                signatures: self_sigs,
            })
        })
        .collect();

    // Direct-key signatures (V6 keys carry capability/expiration in
    // direct sigs, type 0x1F). Keep only those that verify against the
    // primary.
    let direct_sigs: Vec<pgp::packet::Signature> = public_key
        .details
        .direct_signatures
        .iter()
        .filter(|sig| is_verified_self_primary_signature(sig, primary))
        .cloned()
        .collect();

    // Primary-key revocation signatures (type 0x20). RFC 4880 §5.2.3.15
    // lets a designated revoker issue KeyRevocation signatures from a
    // different key; those are conceptually third-party assertions and
    // don't belong in a minimised Autocrypt header. Verifying against
    // the primary keeps only the primary's own self-revocations.
    let revocation_sigs: Vec<pgp::packet::Signature> = public_key
        .details
        .revocation_signatures
        .iter()
        .filter(|sig| is_verified_self_primary_signature(sig, primary))
        .cloned()
        .collect();

    let minimised = SignedPublicKey {
        primary_key: primary.clone(),
        details: SignedKeyDetails::new(
            revocation_sigs,
            direct_sigs,
            matching_users,
            // User Attributes (notably image packets) are large and not
            // useful per-message — Autocrypt strips them.
            Vec::new(),
        ),
        public_subkeys: stripped_subkeys,
    };

    minimised
        .to_bytes()
        .map_err(|e| Error::Crypto(e.to_string()))
}

/// True if `sig` is a UID self-signature (certification or self-revocation)
/// that cryptographically verifies against `primary` over `user.id`.
///
/// Verification is the only sound test of "did this primary actually
/// issue this signature": the issuer-fingerprint subpacket is unsigned
/// metadata an attacker can spoof, and legitimate self-sigs sometimes
/// omit it entirely (V6 and some older V4 producers).
fn is_verified_self_uid_signature(
    sig: &pgp::packet::Signature,
    primary: &pgp::packet::PublicKey,
    user: &SignedUser,
) -> bool {
    matches!(
        sig.typ(),
        Some(SignatureType::CertGeneric)
            | Some(SignatureType::CertPersona)
            | Some(SignatureType::CertCasual)
            | Some(SignatureType::CertPositive)
            | Some(SignatureType::CertRevocation)
    ) && sig
        .verify_certification(primary, pgp::types::Tag::UserId, &user.id)
        .is_ok()
}

/// True if `sig` is a subkey binding or subkey revocation that
/// cryptographically verifies against `primary` over `subkey_key`.
/// `verify_subkey_binding` hashes `primary || subkey`, which is the
/// hash input for both SubkeyBinding (0x18) and SubkeyRevocation (0x28).
fn is_verified_self_subkey_signature<K>(
    sig: &pgp::packet::Signature,
    primary: &pgp::packet::PublicKey,
    subkey_key: &K,
) -> bool
where
    K: pgp::types::KeyDetails + pgp::ser::Serialize,
{
    matches!(
        sig.typ(),
        Some(SignatureType::SubkeyBinding) | Some(SignatureType::SubkeyRevocation)
    ) && sig.verify_subkey_binding(primary, subkey_key).is_ok()
}

/// True if `sig` is a direct-key signature (0x1F) or self key-revocation
/// (0x20) that cryptographically verifies against `primary`.
/// `verify_key` is documented to handle both.
fn is_verified_self_primary_signature(
    sig: &pgp::packet::Signature,
    primary: &pgp::packet::PublicKey,
) -> bool {
    matches!(
        sig.typ(),
        Some(SignatureType::Key) | Some(SignatureType::KeyRevocation)
    ) && sig.verify_key(primary).is_ok()
}

/// Update the expiration time for specific subkeys.
///
/// Creates new subkey binding signatures (signature type 0x18) for the
/// specified subkeys with the updated expiration time.
///
/// # Signature Details
///
/// Subkey binding signatures are created by the primary key to bind a subkey
/// to the key and define its properties (capabilities, expiration).
/// This function creates new binding signatures with:
///
/// - **Key flags** - Preserved from existing signature to maintain capabilities
/// - **Signature creation time** - Set to current time
/// - **Key expiration time** - Set to the specified expiry time
/// - **Issuer fingerprint** - Set to the primary key fingerprint
///
/// Non-binding signatures (like revocations) are preserved unchanged.
///
/// # Fingerprint Matching
///
/// Fingerprints are matched case-insensitively. Partial fingerprint matches
/// are supported (useful for matching by short key ID), but providing full
/// 40-character fingerprints is recommended for accuracy.
///
/// # Arguments
///
/// * `key_data` - The key data (with secret key, armored or binary)
/// * `fingerprints` - Fingerprints of subkeys to update (hex strings)
/// * `expiry_time` - New expiration time as `DateTime<Utc>`
/// * `password` - Password to unlock the secret key
///
/// # Returns
///
/// The updated key with new binding signatures (binary format).
///
/// # Errors
///
/// Returns an error if:
/// - The secret key password is incorrect
/// - The expiry time is before the subkey creation time
/// - A specified subkey fingerprint is not found in the key
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{create_key_simple, update_subkeys_expiry, parse_key_bytes};
/// use chrono::{Utc, Duration};
///
/// let key = create_key_simple("password", &["Alice <alice@example.com>"]).unwrap();
///
/// // Get subkey fingerprints
/// let info = parse_key_bytes(&key.secret_key, true).unwrap();
/// let subkey_fps: Vec<&str> = info.subkeys.iter()
///     .map(|s| s.fingerprint.as_str())
///     .collect();
///
/// // Update expiration to 1 year from now
/// let new_expiry = Utc::now() + Duration::days(365);
/// let updated = update_subkeys_expiry(
///     &key.secret_key,
///     &subkey_fps,
///     new_expiry,
///     "password",
/// ).unwrap();
/// ```
pub fn update_subkeys_expiry(
    key_data: &[u8],
    fingerprints: &[&str],
    expiry_time: DateTime<Utc>,
    password: &str,
) -> Result<Vec<u8>> {
    let mut rng = thread_rng();
    let secret_key = parse_secret_key(key_data)?;
    ensure_secret_primary_not_revoked(&secret_key)?;
    let password = Password::from(password);

    // Normalize fingerprints for comparison (uppercase, no spaces)
    let normalized_fps: Vec<String> = fingerprints
        .iter()
        .map(|fp| fp.to_uppercase().replace(" ", ""))
        .collect();

    // Update public subkeys
    let mut new_public_subkeys = Vec::new();
    for subkey in &secret_key.public_subkeys {
        let subkey_fp = fingerprint_to_hex(&subkey.key);
        let should_update = normalized_fps
            .iter()
            .any(|fp| subkey_fp.contains(fp) || fp.contains(&subkey_fp));

        if should_update {
            // Calculate duration from subkey creation to expiry
            let creation_systime: SystemTime = subkey.key.created_at().into();
            let subkey_creation: DateTime<Utc> = creation_systime.into();
            let duration = expiry_time.signed_duration_since(subkey_creation);
            if duration.num_seconds() <= 0 {
                return Err(Error::InvalidInput(
                    "Expiry time must be after subkey creation time".to_string(),
                ));
            }
            let expiry_duration = pgp::types::Duration::from_secs(duration.num_seconds() as u32);

            // Get existing key flags
            let key_flags = subkey
                .signatures
                .first()
                .map(|sig| sig.key_flags())
                .unwrap_or_default();

            // Build new binding signature
            let hashed_subpackets = vec![
                Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))
                    .map_err(|e| Error::Crypto(e.to_string()))?,
                Subpacket::regular(SubpacketData::IssuerFingerprint(
                    secret_key.primary_key.fingerprint(),
                ))
                .map_err(|e| Error::Crypto(e.to_string()))?,
                Subpacket::regular(SubpacketData::KeyFlags(key_flags))
                    .map_err(|e| Error::Crypto(e.to_string()))?,
                Subpacket::regular(SubpacketData::KeyExpirationTime(expiry_duration))
                    .map_err(|e| Error::Crypto(e.to_string()))?,
            ];

            let mut config = SignatureConfig::from_key(
                &mut rng,
                &secret_key.primary_key,
                SignatureType::SubkeyBinding,
            )
            .map_err(|e| Error::Crypto(e.to_string()))?;

            config.hashed_subpackets = hashed_subpackets;

            if secret_key.primary_key.version() <= KeyVersion::V4 {
                config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
                    secret_key.primary_key.legacy_key_id(),
                ))
                .map_err(|e| Error::Crypto(e.to_string()))?];
            }

            let sig = config
                .sign_subkey_binding(
                    &secret_key.primary_key,
                    &secret_key.primary_key.public_key(),
                    &password,
                    &subkey.key,
                )
                .map_err(|e| Error::Crypto(e.to_string()))?;

            // Create new subkey with updated signature
            let mut new_sigs = vec![sig];
            // Keep any non-binding signatures (like revocations)
            for existing_sig in &subkey.signatures {
                if existing_sig.typ() != Some(SignatureType::SubkeyBinding) {
                    new_sigs.push(existing_sig.clone());
                }
            }

            new_public_subkeys.push(pgp::composed::SignedPublicSubKey {
                key: subkey.key.clone(),
                signatures: new_sigs,
            });
        } else {
            new_public_subkeys.push(subkey.clone());
        }
    }

    // Update secret subkeys similarly
    let mut new_secret_subkeys = Vec::new();
    for subkey in &secret_key.secret_subkeys {
        let subkey_fp = fingerprint_to_hex(&subkey.key);
        let should_update = normalized_fps
            .iter()
            .any(|fp| subkey_fp.contains(fp) || fp.contains(&subkey_fp));

        if should_update {
            // Calculate duration from subkey creation to expiry
            let creation_systime: SystemTime = subkey.key.created_at().into();
            let subkey_creation: DateTime<Utc> = creation_systime.into();
            let duration = expiry_time.signed_duration_since(subkey_creation);
            if duration.num_seconds() <= 0 {
                return Err(Error::InvalidInput(
                    "Expiry time must be after subkey creation time".to_string(),
                ));
            }
            let expiry_duration = pgp::types::Duration::from_secs(duration.num_seconds() as u32);

            // Get existing key flags
            let key_flags = subkey
                .signatures
                .first()
                .map(|sig| sig.key_flags())
                .unwrap_or_default();

            // Build new binding signature
            let hashed_subpackets = vec![
                Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))
                    .map_err(|e| Error::Crypto(e.to_string()))?,
                Subpacket::regular(SubpacketData::IssuerFingerprint(
                    secret_key.primary_key.fingerprint(),
                ))
                .map_err(|e| Error::Crypto(e.to_string()))?,
                Subpacket::regular(SubpacketData::KeyFlags(key_flags))
                    .map_err(|e| Error::Crypto(e.to_string()))?,
                Subpacket::regular(SubpacketData::KeyExpirationTime(expiry_duration))
                    .map_err(|e| Error::Crypto(e.to_string()))?,
            ];

            let mut config = SignatureConfig::from_key(
                &mut rng,
                &secret_key.primary_key,
                SignatureType::SubkeyBinding,
            )
            .map_err(|e| Error::Crypto(e.to_string()))?;

            config.hashed_subpackets = hashed_subpackets;

            if secret_key.primary_key.version() <= KeyVersion::V4 {
                config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
                    secret_key.primary_key.legacy_key_id(),
                ))
                .map_err(|e| Error::Crypto(e.to_string()))?];
            }

            let sig = config
                .sign_subkey_binding(
                    &secret_key.primary_key,
                    &secret_key.primary_key.public_key(),
                    &password,
                    &subkey.key.public_key(),
                )
                .map_err(|e| Error::Crypto(e.to_string()))?;

            // Create new subkey with updated signature
            let mut new_sigs = vec![sig];
            for existing_sig in &subkey.signatures {
                if existing_sig.typ() != Some(SignatureType::SubkeyBinding) {
                    new_sigs.push(existing_sig.clone());
                }
            }

            new_secret_subkeys.push(pgp::composed::SignedSecretSubKey {
                key: subkey.key.clone(),
                signatures: new_sigs,
            });
        } else {
            new_secret_subkeys.push(subkey.clone());
        }
    }

    // Rebuild the secret key with updated subkeys
    let updated_key = SignedSecretKey::new(
        secret_key.primary_key.clone(),
        secret_key.details.clone(),
        new_public_subkeys,
        new_secret_subkeys,
    );

    Ok(secret_key_to_bytes(&updated_key)?.to_vec())
}

/// Update the primary key expiration time.
///
/// Updates all signatures that contain key expiration information.
///
/// # Signatures Updated
///
/// This function updates two types of signatures that can contain key expiration:
///
/// 1. **Direct key signatures (signature type 0x1f)** - These are signatures
///    directly on the primary key itself. GPG uses these as the authoritative
///    source for primary key expiration when present.
///
/// 2. **User ID self-certifications (signature type 0x13)** - These are
///    self-signatures on each user ID that also contain key expiration.
///
/// Both signature types must be updated for GPG to correctly recognize the
/// new expiration date. Key flags and other important subpackets are preserved
/// from the existing signatures.
///
/// # Arguments
///
/// * `key_data` - The key data (with secret key, armored or binary)
/// * `expiry_time` - New expiration time as `DateTime<Utc>`
/// * `password` - Password to unlock the secret key
///
/// # Returns
///
/// The updated key with new expiration signatures (binary format).
///
/// # Errors
///
/// Returns an error if:
/// - The secret key password is incorrect
/// - The expiry time is before the key creation time
/// - The key has no self-certification signatures
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{create_key_simple, update_primary_expiry};
/// use chrono::{Utc, Duration};
///
/// let key = create_key_simple("password", &["Alice <alice@example.com>"]).unwrap();
///
/// // Set primary key to expire in 2 years
/// let new_expiry = Utc::now() + Duration::days(730);
/// let updated = update_primary_expiry(&key.secret_key, new_expiry, "password").unwrap();
/// ```
pub fn update_primary_expiry(
    key_data: &[u8],
    expiry_time: DateTime<Utc>,
    password: &str,
) -> Result<Vec<u8>> {
    let mut rng = thread_rng();
    let secret_key = parse_secret_key(key_data)?;
    ensure_secret_primary_not_revoked(&secret_key)?;
    let password = Password::from(password);

    // Calculate the duration from key creation to expiry
    let creation_systime: SystemTime = secret_key.primary_key.created_at().into();
    let key_creation: DateTime<Utc> = creation_systime.into();
    let duration = expiry_time.signed_duration_since(key_creation);
    if duration.num_seconds() <= 0 {
        return Err(Error::InvalidInput(
            "Expiry time must be after key creation time".to_string(),
        ));
    }
    let expiry_duration = pgp::types::Duration::from_secs(duration.num_seconds() as u32);

    // Update direct key signatures (sigclass 0x1f) - GPG uses these for expiration
    let mut new_direct_signatures: Vec<pgp::packet::Signature> = Vec::new();
    for existing_sig in &secret_key.details.direct_signatures {
        // Only update direct key signatures (0x1f), not revocations
        if existing_sig.typ() == Some(SignatureType::Key) {
            // Preserve existing subpackets, updating only creation time and expiry
            let existing_config = existing_sig.config().ok_or_else(|| {
                Error::Crypto("Cannot read existing direct signature config".to_string())
            })?;

            let mut new_hashed_subpackets: Vec<Subpacket> = Vec::new();
            let mut has_creation_time = false;
            let mut has_expiry_time = false;

            for subpacket in existing_config.hashed_subpackets() {
                match &subpacket.data {
                    SubpacketData::SignatureCreationTime(_) => {
                        new_hashed_subpackets.push(
                            Subpacket::regular(SubpacketData::SignatureCreationTime(
                                Timestamp::now(),
                            ))
                            .map_err(|e| Error::Crypto(e.to_string()))?,
                        );
                        has_creation_time = true;
                    }
                    SubpacketData::KeyExpirationTime(_) => {
                        new_hashed_subpackets.push(
                            Subpacket::regular(SubpacketData::KeyExpirationTime(expiry_duration))
                                .map_err(|e| Error::Crypto(e.to_string()))?,
                        );
                        has_expiry_time = true;
                    }
                    _ => {
                        new_hashed_subpackets.push(subpacket.clone());
                    }
                }
            }

            if !has_creation_time {
                new_hashed_subpackets.push(
                    Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))
                        .map_err(|e| Error::Crypto(e.to_string()))?,
                );
            }

            if !has_expiry_time {
                new_hashed_subpackets.push(
                    Subpacket::regular(SubpacketData::KeyExpirationTime(expiry_duration))
                        .map_err(|e| Error::Crypto(e.to_string()))?,
                );
            }

            let new_unhashed_subpackets: Vec<Subpacket> =
                existing_config.unhashed_subpackets().cloned().collect();

            let mut config =
                SignatureConfig::from_key(&mut rng, &secret_key.primary_key, SignatureType::Key)
                    .map_err(|e| Error::Crypto(e.to_string()))?;
            config.hashed_subpackets = new_hashed_subpackets;
            config.unhashed_subpackets = new_unhashed_subpackets;

            let sig = config
                .sign_key(
                    &secret_key.primary_key,
                    &password,
                    &secret_key.primary_key.public_key(),
                )
                .map_err(|e| Error::Crypto(e.to_string()))?;

            new_direct_signatures.push(sig);
        } else {
            // Keep revocation signatures unchanged
            new_direct_signatures.push(existing_sig.clone());
        }
    }

    // Create new self-certification signatures for each user ID
    let mut new_users: Vec<SignedUser> = Vec::new();

    for signed_user in &secret_key.details.users {
        // Build the hashed subpackets including expiry
        let mut hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))
                .map_err(|e| Error::Crypto(e.to_string()))?,
            Subpacket::regular(SubpacketData::IssuerFingerprint(
                secret_key.primary_key.fingerprint(),
            ))
            .map_err(|e| Error::Crypto(e.to_string()))?,
            Subpacket::regular(SubpacketData::KeyExpirationTime(expiry_duration))
                .map_err(|e| Error::Crypto(e.to_string()))?,
        ];

        // Copy key flags from existing signature if present
        if let Some(existing_sig) = signed_user.signatures.first() {
            let flags = existing_sig.key_flags();
            hashed_subpackets.push(
                Subpacket::regular(SubpacketData::KeyFlags(flags))
                    .map_err(|e| Error::Crypto(e.to_string()))?,
            );
        }

        // Create the signature config
        let mut config = SignatureConfig::from_key(
            &mut rng,
            &secret_key.primary_key,
            SignatureType::CertPositive,
        )
        .map_err(|e| Error::Crypto(e.to_string()))?;

        config.hashed_subpackets = hashed_subpackets;

        if secret_key.primary_key.version() <= KeyVersion::V4 {
            config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
                secret_key.primary_key.legacy_key_id(),
            ))
            .map_err(|e| Error::Crypto(e.to_string()))?];
        }

        // Sign the user ID
        let sig = config
            .sign_certification(
                &secret_key.primary_key,
                &secret_key.primary_key.public_key(),
                &password,
                signed_user.id.tag(),
                &signed_user.id,
            )
            .map_err(|e| Error::Crypto(e.to_string()))?;

        // Combine with existing signatures (add new sig, keep existing third-party certs)
        let mut combined_sigs = vec![sig];
        // Keep third-party certifications but not old self-signatures
        for existing_sig in &signed_user.signatures {
            if existing_sig.typ() != Some(SignatureType::CertPositive) {
                combined_sigs.push(existing_sig.clone());
            }
        }

        new_users.push(SignedUser::new(signed_user.id.clone(), combined_sigs));
    }

    // Rebuild the secret key with new signatures
    let updated_key = SignedSecretKey::new(
        secret_key.primary_key.clone(),
        pgp::composed::SignedKeyDetails::new(
            secret_key.details.revocation_signatures.clone(),
            new_direct_signatures,
            new_users,
            secret_key.details.user_attributes.clone(),
        ),
        secret_key.public_subkeys.clone(),
        secret_key.secret_subkeys.clone(),
    );

    Ok(secret_key_to_bytes(&updated_key)?.to_vec())
}

/// Add a new User ID to a key.
///
/// Creates a new self-certification signature binding the new User ID
/// to the primary key.
///
/// # Arguments
/// * `key_data` - The key data (with secret key)
/// * `uid` - The new user ID string (e.g., "Name <email@example.com>")
/// * `password` - Password to unlock the secret key
///
/// # Returns
/// The updated key with the new User ID.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{create_key_simple, add_uid, parse_key_bytes};
///
/// let key = create_key_simple("password", &["Alice <alice@example.com>"]).unwrap();
///
/// // Add a second email address
/// let updated = add_uid(&key.secret_key, "Alice Work <alice@work.com>", "password").unwrap();
///
/// // Verify the new UID was added
/// let info = parse_key_bytes(&updated, true).unwrap();
/// assert_eq!(info.user_ids.len(), 2);
/// ```
pub fn add_uid(key_data: &[u8], uid: &str, password: &str) -> Result<Vec<u8>> {
    let mut rng = thread_rng();
    let secret_key = parse_secret_key(key_data)?;
    ensure_secret_primary_not_revoked(&secret_key)?;
    let password = Password::from(password);

    // Create a new UserId packet
    let new_uid = UserId::from_str(PacketHeaderVersion::New, uid)
        .map_err(|e| Error::Crypto(e.to_string()))?;

    // Sign the new user ID (self-certification)
    let signed_user = new_uid
        .sign(
            &mut rng,
            &secret_key.primary_key,
            secret_key.primary_key.public_key(),
            &password,
        )
        .map_err(|e| Error::Crypto(e.to_string()))?;

    // Reconstruct the key with the new user ID
    let mut users = secret_key.details.users.clone();
    users.push(signed_user);

    let new_details = SignedKeyDetails::new(
        secret_key.details.revocation_signatures.clone(),
        secret_key.details.direct_signatures.clone(),
        users,
        secret_key.details.user_attributes.clone(),
    );

    let new_secret_key = SignedSecretKey::new(
        secret_key.primary_key.clone(),
        new_details,
        secret_key.public_subkeys.clone(),
        secret_key.secret_subkeys.clone(),
    );

    Ok(secret_key_to_bytes(&new_secret_key)?.to_vec())
}

/// Revoke a User ID on a key.
///
/// Adds a revocation signature to the specified User ID. The UID remains
/// in the key but is marked as revoked.
///
/// # Arguments
/// * `key_data` - The key data (with secret key)
/// * `uid` - The exact user ID string to revoke
/// * `password` - Password to unlock the secret key
///
/// # Returns
/// The updated key with the revocation signature.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{create_key_simple, add_uid, revoke_uid};
///
/// let key = create_key_simple("password", &["Alice <alice@example.com>"]).unwrap();
///
/// // Add and then revoke a UID
/// let with_uid = add_uid(&key.secret_key, "Old Email <old@example.com>", "password").unwrap();
/// let revoked = revoke_uid(&with_uid, "Old Email <old@example.com>", "password").unwrap();
/// ```
pub fn revoke_uid(key_data: &[u8], uid: &str, password: &str) -> Result<Vec<u8>> {
    let mut rng = thread_rng();
    let secret_key = parse_secret_key(key_data)?;
    ensure_secret_primary_not_revoked(&secret_key)?;
    let password = Password::from(password);

    // Find the user ID to revoke
    let uid_bytes = uid.as_bytes();
    let uid_index = secret_key
        .details
        .users
        .iter()
        .position(|u| u.id.id() == uid_bytes)
        .ok_or_else(|| Error::InvalidInput(format!("User ID '{}' not found in key", uid)))?;

    // Create a revocation signature for this user ID
    let mut config = SignatureConfig::from_key(
        &mut rng,
        &secret_key.primary_key,
        SignatureType::CertRevocation,
    )
    .map_err(|e| Error::Crypto(e.to_string()))?;

    config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))
            .map_err(|e| Error::Crypto(e.to_string()))?,
        Subpacket::regular(SubpacketData::IssuerFingerprint(
            secret_key.primary_key.fingerprint(),
        ))
        .map_err(|e| Error::Crypto(e.to_string()))?,
    ];

    if secret_key.primary_key.version() <= KeyVersion::V4 {
        config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
            secret_key.primary_key.legacy_key_id(),
        ))
        .map_err(|e| Error::Crypto(e.to_string()))?];
    }

    let user_to_revoke = &secret_key.details.users[uid_index];
    let revocation_sig = config
        .sign_certification_third_party(
            &secret_key.primary_key,
            &password,
            secret_key.primary_key.public_key(),
            user_to_revoke.id.tag(),
            &user_to_revoke.id,
        )
        .map_err(|e| Error::Crypto(e.to_string()))?;

    // Reconstruct the users list with the revocation signature added
    let mut users = secret_key.details.users.clone();
    users[uid_index].signatures.push(revocation_sig);

    let new_details = SignedKeyDetails::new(
        secret_key.details.revocation_signatures.clone(),
        secret_key.details.direct_signatures.clone(),
        users,
        secret_key.details.user_attributes.clone(),
    );

    let new_secret_key = SignedSecretKey::new(
        secret_key.primary_key.clone(),
        new_details,
        secret_key.public_subkeys.clone(),
        secret_key.secret_subkeys.clone(),
    );

    Ok(secret_key_to_bytes(&new_secret_key)?.to_vec())
}

/// Revoke the entire key.
///
/// Creates a key revocation signature on the primary key. Once revoked,
/// the key should not be used for any new operations. The revocation
/// is permanent and cannot be undone.
///
/// # Arguments
/// * `key_data` - The key data (with secret key)
/// * `password` - Password for the secret key
///
/// # Returns
/// The key with the revocation signature added.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{create_key_simple, revoke_key, parse_key_bytes};
///
/// let key = create_key_simple("password", &["Alice <alice@example.com>"]).unwrap();
/// let revoked = revoke_key(&key.secret_key, "password").unwrap();
/// ```
pub fn revoke_key(key_data: &[u8], password: &str) -> Result<Vec<u8>> {
    let mut rng = thread_rng();
    let secret_key = parse_secret_key(key_data)?;
    let password = Password::from(password);

    // Create a key revocation signature
    let mut config = SignatureConfig::from_key(
        &mut rng,
        &secret_key.primary_key,
        SignatureType::KeyRevocation,
    )
    .map_err(|e| Error::Crypto(e.to_string()))?;

    config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))
            .map_err(|e| Error::Crypto(e.to_string()))?,
        Subpacket::regular(SubpacketData::IssuerFingerprint(
            secret_key.primary_key.fingerprint(),
        ))
        .map_err(|e| Error::Crypto(e.to_string()))?,
    ];

    if secret_key.primary_key.version() <= KeyVersion::V4 {
        config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
            secret_key.primary_key.legacy_key_id(),
        ))
        .map_err(|e| Error::Crypto(e.to_string()))?];
    }

    let revocation_sig = config
        .sign_key(
            &secret_key.primary_key,
            &password,
            secret_key.primary_key.public_key(),
        )
        .map_err(|e| Error::Crypto(e.to_string()))?;

    // Add the revocation signature to the key's revocation signatures
    let mut revocation_sigs = secret_key.details.revocation_signatures.clone();
    revocation_sigs.push(revocation_sig);

    let new_details = SignedKeyDetails::new(
        revocation_sigs,
        secret_key.details.direct_signatures.clone(),
        secret_key.details.users.clone(),
        secret_key.details.user_attributes.clone(),
    );

    let new_secret_key = SignedSecretKey::new(
        secret_key.primary_key.clone(),
        new_details,
        secret_key.public_subkeys.clone(),
        secret_key.secret_subkeys.clone(),
    );

    Ok(secret_key_to_bytes(&new_secret_key)?.to_vec())
}

/// Change the password on a secret key.
///
/// Decrypts the secret key material with the old password and re-encrypts
/// it with the new password. This applies to both the primary key and all
/// secret subkeys.
///
/// # Arguments
/// * `key_data` - The key data (with secret key)
/// * `old_password` - Current password
/// * `new_password` - New password
///
/// # Returns
/// The key with the new password protection.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{create_key_simple, update_password, decrypt_bytes, encrypt_bytes, get_pub_key};
///
/// let key = create_key_simple("old_password", &["Alice <alice@example.com>"]).unwrap();
///
/// // Change the password
/// let updated = update_password(&key.secret_key, "old_password", "new_password").unwrap();
///
/// // Now decrypt using the new password
/// let public_key = get_pub_key(&updated).unwrap();
/// let encrypted = encrypt_bytes(public_key.as_bytes(), b"test", true).unwrap();
/// let decrypted = decrypt_bytes(&updated, &encrypted, "new_password").unwrap();
/// assert_eq!(decrypted, b"test");
/// ```
pub fn update_password(key_data: &[u8], old_password: &str, new_password: &str) -> Result<Vec<u8>> {
    let mut rng = thread_rng();
    let secret_key = parse_secret_key(key_data)?;
    let old_pw = Password::from(old_password);
    let new_pw = Password::from(new_password);

    // Clone the primary key and change its password
    let mut new_primary_key = secret_key.primary_key.clone();
    new_primary_key
        .remove_password(&old_pw)
        .map_err(|e| Error::Crypto(format!("Failed to unlock primary key: {}", e)))?;
    new_primary_key
        .set_password(&mut rng, &new_pw)
        .map_err(|e| Error::Crypto(format!("Failed to set new password on primary key: {}", e)))?;

    // Clone and update password on all secret subkeys
    let mut new_secret_subkeys = Vec::new();
    for subkey in &secret_key.secret_subkeys {
        let mut new_subkey = subkey.clone();
        new_subkey
            .key
            .remove_password(&old_pw)
            .map_err(|e| Error::Crypto(format!("Failed to unlock subkey: {}", e)))?;
        new_subkey
            .key
            .set_password(&mut rng, &new_pw)
            .map_err(|e| Error::Crypto(format!("Failed to set new password on subkey: {}", e)))?;
        new_secret_subkeys.push(new_subkey);
    }

    let new_secret_key = SignedSecretKey::new(
        new_primary_key,
        secret_key.details.clone(),
        secret_key.public_subkeys.clone(),
        new_secret_subkeys,
    );

    Ok(secret_key_to_bytes(&new_secret_key)?.to_vec())
}

/// Certify another key with this key (key signing).
///
/// Creates a certification signature on the target key's User IDs,
/// expressing trust in the binding between the key and the identities.
///
/// # Arguments
/// * `certifier_data` - The certifier's secret key (your key)
/// * `target_data` - The target key to certify (their public key)
/// * `certification_type` - Level of verification performed (see [`CertificationType`])
/// * `user_ids` - Specific user IDs to certify (None = all user IDs)
/// * `password` - Password for certifier's key
///
/// # Returns
/// The target key with the new certification signature attached.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{create_key_simple, certify_key, CertificationType, get_pub_key};
///
/// // Create two keys
/// let alice = create_key_simple("alice_pw", &["Alice <alice@example.com>"]).unwrap();
/// let bob = create_key_simple("bob_pw", &["Bob <bob@example.com>"]).unwrap();
///
/// // Alice certifies Bob's key (signs it)
/// let bob_public = get_pub_key(&bob.secret_key).unwrap();
/// let certified_bob = certify_key(
///     &alice.secret_key,
///     bob_public.as_bytes(),
///     CertificationType::Casual,
///     None,  // certify all UIDs
///     "alice_pw",
/// ).unwrap();
/// ```
pub fn certify_key(
    certifier_data: &[u8],
    target_data: &[u8],
    certification_type: CertificationType,
    user_ids: Option<&[&str]>,
    password: &str,
) -> Result<Vec<u8>> {
    let mut rng = thread_rng();

    // Parse the certifier's secret key
    let certifier = parse_secret_key(certifier_data)?;
    ensure_secret_primary_usable_for_external_certification(&certifier)?;
    let password = Password::from(password);

    // Parse the target's public key
    let target = parse_public_key(target_data)?;

    // Convert our CertificationType to rpgp's SignatureType
    let sig_type = match certification_type {
        CertificationType::Generic => SignatureType::CertGeneric,
        CertificationType::Persona => SignatureType::CertPersona,
        CertificationType::Casual => SignatureType::CertCasual,
        CertificationType::Positive => SignatureType::CertPositive,
    };

    // Determine which user IDs to certify
    let uids_to_certify: Vec<&str> = match user_ids {
        Some(uids) => uids.to_vec(),
        None => {
            // Certify all user IDs
            target
                .details
                .users
                .iter()
                .map(|u| std::str::from_utf8(u.id.id()).unwrap_or(""))
                .filter(|s| !s.is_empty())
                .collect()
        }
    };

    // Create certifications for each selected user ID
    let mut new_users: Vec<SignedUser> = Vec::new();

    for signed_user in &target.details.users {
        let uid_str = std::str::from_utf8(signed_user.id.id()).unwrap_or("");

        // Check if this user ID should be certified
        let should_certify = uids_to_certify.contains(&uid_str);

        if should_certify {
            // Create a certification signature using UserId::sign_third_party
            let certified_user = signed_user.id.sign_third_party(
                &mut rng,
                &certifier.primary_key,
                &password,
                &target.primary_key,
                sig_type,
            )?;

            // Combine existing signatures with the new certification
            let mut combined_sigs = signed_user.signatures.clone();
            combined_sigs.extend(certified_user.signatures);

            new_users.push(SignedUser::new(signed_user.id.clone(), combined_sigs));
        } else {
            // Keep the user ID unchanged
            new_users.push(signed_user.clone());
        }
    }

    // Reconstruct the public key with the new certifications
    let certified_key = SignedPublicKey {
        primary_key: target.primary_key.clone(),
        details: pgp::composed::SignedKeyDetails::new(
            target.details.revocation_signatures.clone(),
            target.details.direct_signatures.clone(),
            new_users,
            target.details.user_attributes.clone(),
        ),
        public_subkeys: target.public_subkeys.clone(),
    };

    // Serialize the certified key
    public_key_to_armored(&certified_key).map(|s| s.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subkey_flags() {
        let flags = SubkeyFlags::all();
        assert!(flags.encryption);
        assert!(flags.signing);
        assert!(flags.authentication);

        let flags = SubkeyFlags::from_bitmask(3);
        assert!(flags.encryption);
        assert!(flags.signing);
        assert!(!flags.authentication);
    }

    /// The autocrypt minimisation must round-trip through rpgp's binary
    /// parser. If the output won't reparse, no receiving MUA will accept it.
    #[test]
    fn autocrypt_export_round_trips_through_parser() {
        let key = crate::create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();

        let autocrypt =
            super::export_public_for_autocrypt(key.public_key.as_bytes(), "alice@example.com")
                .expect("autocrypt export");

        // Must be BINARY (no armor header).
        assert!(
            !autocrypt.starts_with(b"-----BEGIN"),
            "autocrypt keydata MUST be binary, not armored"
        );

        // Parse it back as a valid transferable public key.
        let info = crate::parse_key_bytes(&autocrypt, false).expect("parse minimised key");
        assert_eq!(info.user_ids.len(), 1, "exactly one UID");
        assert_eq!(info.user_ids[0].value, "Alice <alice@example.com>");
        assert!(!info.subkeys.is_empty(), "subkey survived minimisation");
    }

    /// Multi-UID keys: only the UID matching `addr` is kept, and the others
    /// are stripped — this is the per-address invariant Autocrypt §2.1.1
    /// requires, and the size win that justifies sending the header at all.
    #[test]
    fn autocrypt_export_strips_non_matching_uids() {
        let key = crate::create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
        // Add a second UID, then minimise on the first.
        let with_two = crate::add_uid(&key.secret_key, "Alice Work <alice@work.example>", "pw")
            .expect("add_uid");

        let autocrypt =
            super::export_public_for_autocrypt(&with_two, "alice@example.com").expect("export");

        let info = crate::parse_key_bytes(&autocrypt, false).expect("parse");
        assert_eq!(info.user_ids.len(), 1, "only addr-matching UID kept");
        assert_eq!(info.user_ids[0].value, "Alice <alice@example.com>");
    }

    /// Address match is case-insensitive on both local and domain parts —
    /// users routinely type Mixed-Case addresses, and RFC 5321 §2.3.11
    /// says the domain part is case-insensitive anyway.
    #[test]
    fn autocrypt_export_matches_address_case_insensitively() {
        let key = crate::create_key_simple("pw", &["Alice <Alice@Example.COM>"]).unwrap();

        let autocrypt =
            super::export_public_for_autocrypt(key.public_key.as_bytes(), "alice@example.com")
                .expect("case-insensitive match");
        let info = crate::parse_key_bytes(&autocrypt, false).unwrap();
        assert_eq!(info.user_ids.len(), 1);
    }

    /// No matching UID → caller-visible error. Silently dropping all UIDs
    /// would produce an OpenPGP packet sequence that's not a valid
    /// transferable public key (RFC 4880 §11.1 mandates one user id) and
    /// every receiving MUA would reject it.
    #[test]
    fn autocrypt_export_errors_when_addr_does_not_match() {
        let key = crate::create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
        let err =
            super::export_public_for_autocrypt(key.public_key.as_bytes(), "nobody@example.com")
                .expect_err("should fail");
        match err {
            Error::InvalidInput(msg) => assert!(msg.contains("nobody@example.com")),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    /// Secret-key input should produce the same minimised PUBLIC bytes as
    /// public-key input. Callers (libtumpa) pass whatever the keystore has —
    /// we mustn't leak secret packets either way.
    #[test]
    fn autocrypt_export_extracts_public_from_secret_input() {
        let key = crate::create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();

        let from_secret =
            super::export_public_for_autocrypt(&key.secret_key, "alice@example.com").unwrap();
        let from_public =
            super::export_public_for_autocrypt(key.public_key.as_bytes(), "alice@example.com")
                .unwrap();

        // Reparse and compare: the minimised keys must have identical
        // primary-key fingerprints AND must contain no secret packets.
        let info_s = crate::parse_key_bytes(&from_secret, false).unwrap();
        let info_p = crate::parse_key_bytes(&from_public, false).unwrap();
        assert_eq!(info_s.fingerprint, info_p.fingerprint);
        assert!(
            !info_s.is_secret,
            "autocrypt export must never include secret material"
        );
    }

    /// Third-party certifications on the UID must NOT appear in the
    /// autocrypt output (Autocrypt §5.2). If they leaked through, the
    /// header would grow unboundedly with each third-party cert and might
    /// expose the social graph of the sender.
    #[test]
    fn autocrypt_export_strips_third_party_certifications() {
        let alice = crate::create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
        let bob = crate::create_key_simple("pw", &["Bob <bob@example.com>"]).unwrap();

        // Bob certifies Alice's UID.
        let alice_certified = crate::certify_key(
            &bob.secret_key,
            alice.public_key.as_bytes(),
            CertificationType::Positive,
            None,
            "pw",
        )
        .expect("certify_key");

        // Sanity: the certified copy has Bob's signature on Alice's UID.
        let info_before = crate::parse_key_bytes(&alice_certified, false).unwrap();
        assert!(
            !info_before.user_ids[0].certifications.is_empty(),
            "test setup: expected Bob's third-party cert on Alice's UID"
        );

        // Run the minimisation, then check the third-party cert is gone.
        let autocrypt =
            super::export_public_for_autocrypt(&alice_certified, "alice@example.com").unwrap();
        let info_after = crate::parse_key_bytes(&autocrypt, false).unwrap();
        assert_eq!(info_after.user_ids.len(), 1);
        assert!(
            info_after.user_ids[0].certifications.is_empty(),
            "third-party certifications must be stripped from autocrypt keydata"
        );
    }

    /// Two UIDs sharing the same email address (different display names)
    /// must collapse to exactly ONE UID in the autocrypt output — Autocrypt
    /// §2.1.1 says "exactly one user id packet", and emitting both would
    /// (a) violate that, (b) leak the alternate display name into every
    /// outbound mail, and (c) make the on-the-wire bytes depend on packet
    /// order, which isn't stable across re-imports.
    #[test]
    fn autocrypt_export_picks_single_uid_when_multiple_share_address() {
        let key = crate::create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
        // Second UID with the SAME email but a different display name.
        let with_dup = crate::add_uid(&key.secret_key, "A. Liddell <alice@example.com>", "pw")
            .expect("add_uid");

        let autocrypt =
            super::export_public_for_autocrypt(&with_dup, "alice@example.com").expect("export");

        let info = crate::parse_key_bytes(&autocrypt, false).expect("parse");
        assert_eq!(
            info.user_ids.len(),
            1,
            "multiple UIDs with the same address must collapse to exactly one"
        );
        // Deterministic pick: first matching UID in packet order wins when
        // no UID is flagged primary. The primary UID is the FIRST added.
        assert_eq!(info.user_ids[0].value, "Alice <alice@example.com>");
    }

    /// Third-party key-revocation signatures (RFC 4880 §5.2.3.15:
    /// designated revoker) MUST NOT leak into the autocrypt header — the
    /// receiving MUA can't verify the revoker's authority from the
    /// keydata alone, and the docstring promises "no third-party
    /// certifications anywhere".
    ///
    /// We can't easily fabricate a designated-revoker signature in a unit
    /// test (rpgp doesn't expose a public helper for it), so this test
    /// proves the filter by injecting a third-party signature into the
    /// `revocation_signatures` slot via the rpgp struct API and verifying
    /// the autocrypt export drops it.
    #[test]
    fn autocrypt_export_strips_third_party_revocation_signatures() {
        use pgp::composed::{Deserializable, SignedPublicKey};
        use pgp::ser::Serialize;
        use std::io::Cursor;

        let alice = crate::create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
        let bob = crate::create_key_simple("pw", &["Bob <bob@example.com>"]).unwrap();

        // Build a tampered alice key whose `revocation_signatures` slot
        // contains a bona-fide signature from BOB — a stand-in for a
        // designated-revoker KeyRevocation that Bob would have issued.
        // We borrow Bob's UID self-cert (which is signed by Bob's primary,
        // so verifying it against Alice's primary fails) and splice it in.
        let (alice_pub, _) = SignedPublicKey::from_armor_single(Cursor::new(&alice.public_key))
            .expect("parse alice pub");
        let (bob_pub, _) = SignedPublicKey::from_armor_single(Cursor::new(&bob.public_key))
            .expect("parse bob pub");
        let bob_sig = bob_pub
            .details
            .users
            .first()
            .and_then(|u| u.signatures.first())
            .cloned()
            .expect("bob has a UID self-sig");

        let tampered = SignedPublicKey {
            primary_key: alice_pub.primary_key.clone(),
            details: pgp::composed::SignedKeyDetails::new(
                vec![bob_sig],
                alice_pub.details.direct_signatures.clone(),
                alice_pub.details.users.clone(),
                alice_pub.details.user_attributes.clone(),
            ),
            public_subkeys: alice_pub.public_subkeys.clone(),
        };
        let tampered_bytes = tampered.to_bytes().expect("serialize tampered");

        // Run the export. The filter must drop Bob's signature; the output
        // must reparse cleanly. (We can't directly inspect packet count
        // through KeyInfo, but a re-export with the same input must be
        // byte-identical to one built from the *un*-tampered key, since
        // the only difference between the two inputs is the third-party
        // signature we're claiming gets filtered.)
        let from_tampered =
            super::export_public_for_autocrypt(&tampered_bytes, "alice@example.com").unwrap();
        let from_clean =
            super::export_public_for_autocrypt(alice.public_key.as_bytes(), "alice@example.com")
                .unwrap();
        assert_eq!(
            from_tampered, from_clean,
            "third-party signatures in the revocation_signatures slot must be \
             stripped — the minimised export should be identical with or \
             without them"
        );
    }

    /// "Self" is established by cryptographic verification, not by trusting
    /// the issuer-fingerprint subpacket. A signature genuinely issued by
    /// the primary key (so the issuer subpacket is "correct") but spliced
    /// into the WRONG context (hash input doesn't match the target UID)
    /// must be dropped from the minimised export. A metadata-only check
    /// would happily keep this signature because the issuer subpacket
    /// names the right primary; only `verify_certification` catches that
    /// the hash doesn't agree with the surrounding UID.
    #[test]
    fn autocrypt_export_drops_signatures_that_dont_cryptographically_verify() {
        use pgp::composed::{Deserializable, SignedPublicKey};
        use pgp::ser::Serialize;
        use std::io::Cursor;

        // One key, two UIDs. Each UID carries its own self-cert from the
        // primary, computed over that UID's own text.
        let key = crate::create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
        let two_uids =
            crate::add_uid(&key.secret_key, "Alice 2 <alice2@example.com>", "pw").unwrap();

        let parsed_secret = pgp::composed::SignedSecretKey::from_bytes(Cursor::new(&two_uids))
            .expect("parse secret");
        let pub_two = parsed_secret.to_public_key();

        // Locate the two UIDs by their text and pluck UID1's self-cert.
        let uid1 = pub_two
            .details
            .users
            .iter()
            .find(|u| String::from_utf8_lossy(u.id.id()).contains("alice@example.com"))
            .expect("uid1 present");
        let uid2 = pub_two
            .details
            .users
            .iter()
            .find(|u| String::from_utf8_lossy(u.id.id()).contains("alice2@example.com"))
            .expect("uid2 present");
        let uid1_self_cert = uid1
            .signatures
            .first()
            .cloned()
            .expect("uid1 self-cert exists");

        // Build a tampered key where UID2's signature list ALSO contains
        // UID1's self-cert. The spliced sig was genuinely issued by the
        // primary (issuer fingerprint subpacket would have pointed at it),
        // but its hash input is UID1's text, not UID2's — so it cannot
        // verify as a self-cert of UID2 and must be dropped.
        let mut uid2_sigs = uid2.signatures.clone();
        uid2_sigs.push(uid1_self_cert);
        let tampered_uid2 = SignedUser::new(uid2.id.clone(), uid2_sigs);

        let mut tampered_users = pub_two.details.users.clone();
        // Replace the UID2 entry in-place to preserve packet order.
        for u in tampered_users.iter_mut() {
            if String::from_utf8_lossy(u.id.id()).contains("alice2@example.com") {
                *u = tampered_uid2.clone();
            }
        }
        let tampered = SignedPublicKey {
            primary_key: pub_two.primary_key.clone(),
            details: pgp::composed::SignedKeyDetails::new(
                pub_two.details.revocation_signatures.clone(),
                pub_two.details.direct_signatures.clone(),
                tampered_users,
                pub_two.details.user_attributes.clone(),
            ),
            public_subkeys: pub_two.public_subkeys.clone(),
        };
        let tampered_bytes = tampered.to_bytes().expect("serialize tampered");

        // Export targeting UID2. The autocrypt output of the tampered key
        // must equal the autocrypt output of the un-tampered key: the
        // spliced UID1 cert is dropped by the cryptographic check.
        let from_tampered =
            super::export_public_for_autocrypt(&tampered_bytes, "alice2@example.com").unwrap();
        let clean_bytes = pub_two.to_bytes().expect("serialize clean");
        let from_clean =
            super::export_public_for_autocrypt(&clean_bytes, "alice2@example.com").unwrap();
        assert_eq!(
            from_tampered, from_clean,
            "a signature issued by the primary but over the WRONG hash \
             input must be rejected — the minimised export must be \
             byte-identical with and without the spliced signature"
        );
    }

    /// If the picked UID has no signature that survives cryptographic
    /// verification, the export MUST error out instead of emitting a UID
    /// packet with zero following signatures. A transferable public key
    /// (RFC 4880 §11.1) requires at least one self-cert after each UID;
    /// emitting an uncertified UID would produce keydata every receiving
    /// MUA rejects, and worse, the failure would surface only on the
    /// recipient side.
    /// We can't construct this scenario by stripping signatures and
    /// re-parsing — rpgp itself enforces §11.1 and refuses to parse a
    /// UID with no following signature. So we substitute Bob's UID
    /// self-cert in place of Alice's: the packet parses fine (claims to
    /// be a CertPositive, has all the right subpackets), but it was
    /// signed by Bob's primary, so `verify_certification` against
    /// Alice's primary fails and the autocrypt filter drops it.
    #[test]
    fn autocrypt_export_errors_when_picked_uid_has_no_verified_self_signature() {
        use pgp::composed::{Deserializable, SignedPublicKey};
        use pgp::ser::Serialize;

        let alice = crate::create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
        let bob = crate::create_key_simple("pw", &["Bob <bob@example.com>"]).unwrap();
        let alice_secret =
            pgp::composed::SignedSecretKey::from_bytes(std::io::Cursor::new(&alice.secret_key))
                .unwrap();
        let alice_pub = alice_secret.to_public_key();
        let bob_secret =
            pgp::composed::SignedSecretKey::from_bytes(std::io::Cursor::new(&bob.secret_key))
                .unwrap();
        let bob_pub = bob_secret.to_public_key();
        let bob_uid_sig = bob_pub
            .details
            .users
            .first()
            .and_then(|u| u.signatures.first())
            .cloned()
            .expect("bob has a UID self-sig");

        // Replace Alice's UID self-cert with Bob's, keeping the UID text.
        // The signature parses fine but cannot verify against Alice's
        // primary, so the autocrypt filter drops it and ends up with an
        // empty self-sig list.
        let tampered_users: Vec<SignedUser> = alice_pub
            .details
            .users
            .iter()
            .map(|u| SignedUser::new(u.id.clone(), vec![bob_uid_sig.clone()]))
            .collect();
        let tampered = SignedPublicKey {
            primary_key: alice_pub.primary_key.clone(),
            details: pgp::composed::SignedKeyDetails::new(
                alice_pub.details.revocation_signatures.clone(),
                alice_pub.details.direct_signatures.clone(),
                tampered_users,
                alice_pub.details.user_attributes.clone(),
            ),
            public_subkeys: alice_pub.public_subkeys.clone(),
        };
        let tampered_bytes = tampered.to_bytes().unwrap();

        let err = super::export_public_for_autocrypt(&tampered_bytes, "alice@example.com")
            .expect_err("export should fail when UID has no verified self-sig");
        match err {
            Error::InvalidInput(msg) => {
                assert!(
                    msg.contains("alice@example.com"),
                    "error should mention the address; got: {msg}"
                );
                assert!(
                    msg.contains("verified self-signature"),
                    "error should explain the cause; got: {msg}"
                );
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    /// Subkeys without a verified `SubkeyBinding` signature MUST be
    /// dropped from the output. A transferable public key requires a
    /// binding signature after each subkey packet (RFC 4880 §11.1); a
    /// subkey without one isn't part of the key, can't be used for
    /// encryption/signing, and would just bloat every outbound mail.
    #[test]
    fn autocrypt_export_drops_subkeys_with_no_verified_binding_signature() {
        use pgp::composed::{Deserializable, SignedPublicKey};
        use pgp::ser::Serialize;

        // Same constraint as the UID-no-self-sig test: rpgp enforces
        // RFC 4880 §11.1 at parse time and won't accept a subkey with
        // zero signatures. So we substitute Bob's subkey-binding sig in
        // place of Alice's. The packet parses (it's a real binding sig),
        // but it was issued by Bob's primary, so verifying it against
        // Alice's primary over Alice's subkey fails.
        let alice = crate::create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
        let bob = crate::create_key_simple("pw", &["Bob <bob@example.com>"]).unwrap();
        let alice_secret =
            pgp::composed::SignedSecretKey::from_bytes(std::io::Cursor::new(&alice.secret_key))
                .unwrap();
        let alice_pub = alice_secret.to_public_key();
        let bob_secret =
            pgp::composed::SignedSecretKey::from_bytes(std::io::Cursor::new(&bob.secret_key))
                .unwrap();
        let bob_pub = bob_secret.to_public_key();
        assert!(
            !alice_pub.public_subkeys.is_empty(),
            "test fixture should have at least one subkey"
        );
        let subkey_count_before = alice_pub.public_subkeys.len();
        let bob_subkey_binding = bob_pub
            .public_subkeys
            .first()
            .and_then(|sk| sk.signatures.first())
            .cloned()
            .expect("bob has a subkey binding sig");

        let stripped_subkeys: Vec<pgp::composed::SignedPublicSubKey> = alice_pub
            .public_subkeys
            .iter()
            .map(|sk| pgp::composed::SignedPublicSubKey {
                key: sk.key.clone(),
                signatures: vec![bob_subkey_binding.clone()],
            })
            .collect();
        let tampered = SignedPublicKey {
            primary_key: alice_pub.primary_key.clone(),
            details: alice_pub.details.clone(),
            public_subkeys: stripped_subkeys,
        };
        let tampered_bytes = tampered.to_bytes().unwrap();

        let autocrypt =
            super::export_public_for_autocrypt(&tampered_bytes, "alice@example.com").unwrap();
        let info = crate::parse_key_bytes(&autocrypt, false).unwrap();
        assert!(
            info.subkeys.is_empty(),
            "subkeys with no verified binding signature must be dropped \
             from the autocrypt output (had {subkey_count_before} before \
             tampering, expected 0 after)"
        );
    }

    /// The PrimaryUserId subpacket only matters when it appears on a
    /// signature the primary actually issued. Otherwise an attacker who
    /// can splice packets could mark a UID with no usable self-cert as
    /// "primary" via a forged signature and force the picker to land on
    /// it — making the export error out for keys that have a perfectly
    /// good sibling UID with valid self-sigs.
    ///
    /// Setup: two UIDs share the same address. UID1 has a genuine
    /// verified self-cert (no PrimaryUserId flag). UID2's only signature
    /// is Bob's UID self-cert — which carries Bob's `is_primary()` flag
    /// (rpgp marks the first UID of a generated key as primary) but
    /// fails to verify against Alice's primary. The new picker MUST
    /// land on UID1; the old metadata-only picker would have grabbed
    /// UID2 (via `SignedUser::is_primary` returning true on the
    /// unverified sig) and then errored out.
    #[test]
    fn autocrypt_export_ignores_primary_flag_on_unverified_self_signature() {
        use pgp::composed::{Deserializable, SignedPublicKey};
        use pgp::ser::Serialize;

        let alice = crate::create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
        let with_dup = crate::add_uid(&alice.secret_key, "Alice 2 <alice@example.com>", "pw")
            .expect("add_uid");
        let bob = crate::create_key_simple("pw", &["Bob <bob@example.com>"]).unwrap();

        let alice_secret =
            pgp::composed::SignedSecretKey::from_bytes(std::io::Cursor::new(&with_dup)).unwrap();
        let alice_pub = alice_secret.to_public_key();
        let bob_secret =
            pgp::composed::SignedSecretKey::from_bytes(std::io::Cursor::new(&bob.secret_key))
                .unwrap();
        let bob_pub = bob_secret.to_public_key();
        let bob_uid_sig = bob_pub
            .details
            .users
            .first()
            .and_then(|u| u.signatures.first())
            .cloned()
            .expect("bob has a UID self-sig");
        // rpgp marks the first generated UID as primary; assert that so
        // the test is doing what it claims.
        assert!(
            bob_uid_sig.is_primary(),
            "test fixture: bob's UID self-sig should carry the \
             PrimaryUserId subpacket"
        );

        // Tampered key: UID1 keeps its real self-cert, UID2's signature
        // list contains only Bob's (primary-flagged) self-cert.
        let tampered_users: Vec<SignedUser> = alice_pub
            .details
            .users
            .iter()
            .map(|u| {
                let uid_text = String::from_utf8_lossy(u.id.id()).to_string();
                if uid_text.contains("Alice 2") {
                    SignedUser::new(u.id.clone(), vec![bob_uid_sig.clone()])
                } else {
                    u.clone()
                }
            })
            .collect();
        let tampered = SignedPublicKey {
            primary_key: alice_pub.primary_key.clone(),
            details: pgp::composed::SignedKeyDetails::new(
                alice_pub.details.revocation_signatures.clone(),
                alice_pub.details.direct_signatures.clone(),
                tampered_users,
                alice_pub.details.user_attributes.clone(),
            ),
            public_subkeys: alice_pub.public_subkeys.clone(),
        };
        let tampered_bytes = tampered.to_bytes().expect("serialize tampered");

        // Should succeed (not error) — UID1 has a verified self-cert
        // and the picker must skip the falsely-flagged "primary" UID2.
        let autocrypt = super::export_public_for_autocrypt(&tampered_bytes, "alice@example.com")
            .expect("picker should land on UID1, not UID2");
        let info = crate::parse_key_bytes(&autocrypt, false).expect("parse output");
        assert_eq!(info.user_ids.len(), 1);
        assert_eq!(
            info.user_ids[0].value, "Alice <alice@example.com>",
            "picker must select the UID with a verified self-cert, not \
             the one whose only signature is a forged primary claim"
        );
    }
}
