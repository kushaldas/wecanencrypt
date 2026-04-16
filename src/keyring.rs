//! Keyring file operations.
//!
//! This module provides functions for reading and writing OpenPGP
//! keyring files that contain multiple keys.

use std::io::Cursor;
use std::path::Path;

use pgp::composed::{
    Deserializable, SignedKeyDetails, SignedPublicKey, SignedPublicSubKey, SignedSecretKey,
};
use pgp::packet::Signature;
use pgp::ser::Serialize;
use pgp::types::KeyDetails;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::internal::{
    fingerprint_to_hex, parse_cert, parse_secret_key, public_key_to_armored, secret_key_to_bytes,
};
use crate::parse::parse_cert_bytes;
use crate::types::CertificateInfo;

/// Parse a keyring file containing multiple keys.
///
/// # Arguments
/// * `path` - Path to the keyring file
///
/// # Returns
/// A list of (CertificateInfo, raw_bytes) for each key in the keyring.
///
/// # Example
/// ```ignore
/// // Ignored: illustrative example with placeholder file path
/// let keys = parse_keyring_file("pubring.gpg")?;
/// for (info, bytes) in keys {
///     println!("Key: {} - {}", info.fingerprint, info.user_ids.first().unwrap_or(&"".to_string()));
/// }
/// ```
pub fn parse_keyring_file(path: impl AsRef<Path>) -> Result<Vec<(CertificateInfo, Vec<u8>)>> {
    let keyring_data = std::fs::read(path.as_ref())?;
    parse_keyring_bytes(&keyring_data)
}

/// Parse keyring data containing multiple keys.
///
/// # Arguments
/// * `data` - Keyring data (armored or binary)
///
/// # Returns
/// A list of (CertificateInfo, raw_bytes) for each key.
pub fn parse_keyring_bytes(data: &[u8]) -> Result<Vec<(CertificateInfo, Vec<u8>)>> {
    let mut results = Vec::new();

    // Try to parse as multiple public keys
    let cursor = Cursor::new(data);
    let (keys_iter, _headers) =
        SignedPublicKey::from_reader_many(cursor).map_err(|e| Error::Parse(e.to_string()))?;

    for key_result in keys_iter {
        match key_result {
            Ok(key) => {
                let bytes = key.to_bytes().map_err(|e| Error::Crypto(e.to_string()))?;
                let info = parse_cert_bytes(&bytes, true)?;
                results.push((info, bytes));
            }
            Err(e) => {
                // Log error but continue parsing other keys
                eprintln!("Warning: failed to parse key: {}", e);
            }
        }
    }

    Ok(results)
}

/// Export multiple keys to a keyring file.
///
/// # Arguments
/// * `keys` - Slice of key data
/// * `output` - Path to write the keyring file
///
/// # Example
/// ```ignore
/// // Ignored: illustrative example with placeholder file paths
/// let key1 = std::fs::read("key1.asc")?;
/// let key2 = std::fs::read("key2.asc")?;
/// export_keyring_file(&[&key1, &key2], "combined.gpg")?;
/// ```
pub fn export_keyring_file(keys: &[&[u8]], output: impl AsRef<Path>) -> Result<()> {
    let mut keyring_data = Vec::new();

    for key_data in keys {
        let (public_key, _is_secret) = parse_cert(key_data)?;
        let bytes = public_key
            .to_bytes()
            .map_err(|e| Error::Crypto(e.to_string()))?;
        keyring_data.extend_from_slice(&bytes);
    }

    std::fs::write(output.as_ref(), keyring_data)?;
    Ok(())
}

/// Export multiple keys to an armored keyring.
///
/// # Arguments
/// * `keys` - Slice of key data
///
/// # Returns
/// ASCII-armored keyring containing all keys.
pub fn export_keyring_armored(keys: &[&[u8]]) -> Result<String> {
    let mut all_armored = String::new();

    for key_data in keys {
        let (public_key, _is_secret) = parse_cert(key_data)?;
        let armored = public_key_to_armored(&public_key)?;
        all_armored.push_str(&armored);
        all_armored.push('\n');
    }

    Ok(all_armored)
}

/// Merge two OpenPGP keys with the same primary key fingerprint,
/// preserving secret key material from either side.
///
/// Merges new information (signatures, user IDs, subkeys, user attributes)
/// from `update_data` into `key_data`. Follows the same overall approach
/// as Sequoia's `Cert::merge_public_and_secret` and rpgpie's `Tsk::merge`:
/// deduplication of components and signatures, new components added, new
/// signatures merged into existing components. Any variant carrying
/// secret material is preferred so that re-importing a public update on
/// top of a stored secret key does not drop the secret packets.
///
/// # Arguments
/// * `key_data` - The original key (armored or binary)
/// * `update_data` - The key with new data to merge (armored or binary)
///
/// # Returns
/// Merged key bytes wrapped in `Zeroizing` so any secret material is
/// scrubbed on drop. When both inputs are public only, the result is
/// still wrapped in `Zeroizing` but contains public-only bytes.
///
/// # Errors
/// * [`Error::InvalidInput`] if the two keys have different primary
///   fingerprints.
pub fn merge_keys(key_data: &[u8], update_data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let (orig_public, orig_is_secret) = parse_cert(key_data)?;
    let (update_public, update_is_secret) = parse_cert(update_data)?;

    let fp1 = fingerprint_to_hex(&orig_public.primary_key);
    let fp2 = fingerprint_to_hex(&update_public.primary_key);
    if fp1 != fp2 {
        return Err(Error::InvalidInput(format!(
            "Key fingerprints do not match: {} vs {}",
            fp1, fp2
        )));
    }

    match (orig_is_secret, update_is_secret) {
        (false, false) => {
            let mut orig = orig_public;
            merge_public_key(&mut orig, update_public);
            orig.to_bytes()
                .map(Zeroizing::new)
                .map_err(|e| Error::Crypto(e.to_string()))
        }
        (true, false) => {
            let mut orig = parse_secret_key(key_data)?;
            merge_secret_key(
                &mut orig,
                SecretMergeSource::Public(Box::new(update_public)),
            );
            secret_key_to_bytes(&orig)
        }
        (false, true) => {
            // Upgrade: start from the incoming secret key as the base,
            // then merge the existing public key's signatures/UIDs in.
            let mut merged = parse_secret_key(update_data)?;
            merge_secret_key(
                &mut merged,
                SecretMergeSource::Public(Box::new(orig_public)),
            );
            secret_key_to_bytes(&merged)
        }
        (true, true) => {
            let mut orig = parse_secret_key(key_data)?;
            let update = parse_secret_key(update_data)?;
            merge_secret_key(&mut orig, SecretMergeSource::Secret(Box::new(update)));
            secret_key_to_bytes(&orig)
        }
    }
}

/// Source of a merge into a `SignedSecretKey`. Either another secret
/// key (we can take its `secret_subkeys` too) or a public key (we
/// merge signatures/components but our own secret material is untouched).
enum SecretMergeSource {
    Secret(Box<SignedSecretKey>),
    Public(Box<SignedPublicKey>),
}

/// Merge a public update into an existing public key, in place.
fn merge_public_key(orig: &mut SignedPublicKey, update: SignedPublicKey) {
    merge_details(&mut orig.details, update.details);
    merge_public_subkeys(&mut orig.public_subkeys, update.public_subkeys);
}

/// Merge an update into an existing secret key, in place, preserving
/// the destination's secret key material.
fn merge_secret_key(orig: &mut SignedSecretKey, source: SecretMergeSource) {
    let (src_details, src_pub_subkeys, src_sec_subkeys) = match source {
        SecretMergeSource::Secret(sec) => {
            let sec = *sec;
            (sec.details, sec.public_subkeys, Some(sec.secret_subkeys))
        }
        SecretMergeSource::Public(pubk) => {
            let pubk = *pubk;
            (pubk.details, pubk.public_subkeys, None)
        }
    };

    merge_details(&mut orig.details, src_details);

    // Signatures from src's public subkey view may describe a subkey for
    // which we already hold the secret packet in `secret_subkeys`. Route
    // those signatures into our secret subkey; otherwise route into
    // `public_subkeys` (merge if present, append if new).
    for sk_update in src_pub_subkeys {
        let upd_fp = sk_update.fingerprint();
        if let Some(existing_sec) = orig
            .secret_subkeys
            .iter_mut()
            .find(|sk| sk.key.fingerprint() == upd_fp)
        {
            merge_signatures(&mut existing_sec.signatures, sk_update.signatures);
        } else if let Some(existing_pub) = orig
            .public_subkeys
            .iter_mut()
            .find(|sk| sk.fingerprint() == upd_fp)
        {
            merge_signatures(&mut existing_pub.signatures, sk_update.signatures);
        } else {
            orig.public_subkeys.push(sk_update);
        }
    }

    // If the source also carried secret subkey material, match by
    // fingerprint: merge signatures on known subkeys, append new secret
    // subkeys. We keep the existing secret packet on match (any variant
    // with secret material is kept; we don't swap it out).
    if let Some(src_sec) = src_sec_subkeys {
        let primary_pub = orig.primary_key.public_key().clone();
        for mut sk_update in src_sec {
            let upd_fp = sk_update.key.fingerprint();
            if let Some(existing) = orig
                .secret_subkeys
                .iter_mut()
                .find(|sk| sk.key.fingerprint() == upd_fp)
            {
                merge_signatures(&mut existing.signatures, sk_update.signatures);
            } else {
                // A new secret subkey we didn't have. Verify the
                // binding signature against our primary before
                // accepting it — otherwise a crafted update could
                // inject a subkey whose "binding" was never actually
                // signed by the primary. On verification failure the
                // subkey is dropped; the rest of the merge proceeds.
                if let Err(e) = sk_update.verify_bindings(&primary_pub) {
                    eprintln!(
                        "Warning: dropping secret subkey {} with invalid binding: {}",
                        hex::encode_upper(upd_fp.as_bytes()),
                        e
                    );
                    continue;
                }
                // If the public_subkeys list has the matching public
                // form, it carries signatures we've already accumulated
                // (revocations, third-party certifications, historical
                // binding sigs). Merge them into the incoming secret
                // subkey before promoting — otherwise they would be
                // silently dropped when we retain() the public entry.
                let prior_sigs: Vec<_> = orig
                    .public_subkeys
                    .iter()
                    .filter(|sk| sk.fingerprint() == upd_fp)
                    .flat_map(|sk| sk.signatures.iter().cloned())
                    .collect();
                if !prior_sigs.is_empty() {
                    merge_signatures(&mut sk_update.signatures, prior_sigs);
                }
                orig.public_subkeys.retain(|sk| sk.fingerprint() != upd_fp);
                orig.secret_subkeys.push(sk_update);
            }
        }
    }
}

/// Merge the signature-bearing fields of `src` into `dst`:
/// direct-key sigs, revocation sigs, UID + sigs, user-attr + sigs.
fn merge_details(dst: &mut SignedKeyDetails, src: SignedKeyDetails) {
    merge_signatures(&mut dst.direct_signatures, src.direct_signatures);
    merge_signatures(&mut dst.revocation_signatures, src.revocation_signatures);

    for uid_update in src.users {
        if let Some(existing) = dst
            .users
            .iter_mut()
            .find(|u| u.id.id() == uid_update.id.id())
        {
            merge_signatures(&mut existing.signatures, uid_update.signatures);
        } else {
            dst.users.push(uid_update);
        }
    }

    for attr_update in src.user_attributes {
        if let Some(existing) = dst
            .user_attributes
            .iter_mut()
            .find(|a| a.attr == attr_update.attr)
        {
            merge_signatures(&mut existing.signatures, attr_update.signatures);
        } else {
            dst.user_attributes.push(attr_update);
        }
    }
}

/// Merge `src` public subkeys into `dst`: match by fingerprint, merge
/// signatures on matches, append new subkeys.
fn merge_public_subkeys(dst: &mut Vec<SignedPublicSubKey>, src: Vec<SignedPublicSubKey>) {
    for sk_update in src {
        if let Some(existing) = dst
            .iter_mut()
            .find(|sk| sk.fingerprint() == sk_update.fingerprint())
        {
            merge_signatures(&mut existing.signatures, sk_update.signatures);
        } else {
            dst.push(sk_update);
        }
    }
}

/// Checks if two signatures contain the same cryptographic signature bytes.
///
/// Two signature packets are considered equal if they produce the same
/// signature bytes, even if they differ in packet framing or unhashed
/// subpackets.
fn signature_bytes_eq(a: &Signature, b: &Signature) -> bool {
    if let (Some(sb1), Some(sb2)) = (a.signature(), b.signature()) {
        sb1 == sb2
    } else {
        a == b
    }
}

/// Merge signatures from `updates` into `target`, deduplicating by signature bytes.
///
/// For signatures already present in `target` (matched by cryptographic signature
/// bytes), any additional unhashed subpackets from the update are merged in.
/// Entirely new signatures are appended.
fn merge_signatures(target: &mut Vec<Signature>, updates: Vec<Signature>) {
    for upd in updates {
        if let Some(existing) = target.iter_mut().find(|s| signature_bytes_eq(s, &upd)) {
            // Signature already present - merge any new unhashed subpackets
            merge_unhashed(existing, &upd);
        } else {
            target.push(upd);
        }
    }
}

/// Merge additional unhashed subpackets from `source` into `target`.
fn merge_unhashed(target: &mut Signature, source: &Signature) {
    let mut inserts = Vec::new();

    if let (Some(c1), Some(c2)) = (target.config(), source.config()) {
        for (pos, sub) in c2.unhashed_subpackets.iter().enumerate() {
            if !c1.unhashed_subpackets.contains(sub) {
                inserts.push((pos, sub.clone()));
            }
        }
    }

    for (pos, sp) in inserts {
        let _ = target.unhashed_subpacket_insert(pos, sp);
    }
}

#[cfg(test)]
mod tests {
    // Tests would require key fixtures
}
