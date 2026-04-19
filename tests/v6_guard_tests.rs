//! Cross-version guard tests for V6 (RFC 9580) support.
//!
//! These tests enforce the library-wide invariant that V4 and V6 keys never
//! intermix: merging, importing, and encrypting-to-recipients must all reject
//! heterogeneous versions.

use wecanencrypt::{
    create_key_simple, create_key_v6_simple, encrypt_bytes_to_multiple, get_pub_key, merge_keys,
    CipherSuite, Error, KeyVersion,
};

const PW: &str = "test-password-123";

fn v4_key() -> Vec<u8> {
    create_key_simple(PW, &["Alice V4 <alice.v4@example.com>"])
        .unwrap()
        .secret_key
        .to_vec()
}

fn v6_key() -> Vec<u8> {
    create_key_v6_simple(
        PW,
        &["Alice V6 <alice.v6@example.com>"],
        CipherSuite::Cv25519Modern,
    )
    .unwrap()
    .secret_key
    .to_vec()
}

// -----------------------------------------------------------------------------
// keyring::merge_keys
// -----------------------------------------------------------------------------

#[test]
fn merge_v4_into_v6_rejected_with_version_mismatch() {
    let v4 = v4_key();
    let v6 = v6_key();

    let v4_pub = get_pub_key(&v4).unwrap();
    let v6_pub = get_pub_key(&v6).unwrap();

    let err = merge_keys(v6_pub.as_bytes(), v4_pub.as_bytes()).unwrap_err();
    match err {
        Error::KeyVersionMismatch { existing, incoming } => {
            assert_eq!(existing, KeyVersion::V6);
            assert_eq!(incoming, KeyVersion::V4);
        }
        other => panic!("expected KeyVersionMismatch, got {:?}", other),
    }
}

#[test]
fn merge_v6_into_v4_rejected_with_version_mismatch() {
    let v4 = v4_key();
    let v6 = v6_key();

    let v4_pub = get_pub_key(&v4).unwrap();
    let v6_pub = get_pub_key(&v6).unwrap();

    let err = merge_keys(v4_pub.as_bytes(), v6_pub.as_bytes()).unwrap_err();
    match err {
        Error::KeyVersionMismatch { existing, incoming } => {
            assert_eq!(existing, KeyVersion::V4);
            assert_eq!(incoming, KeyVersion::V6);
        }
        other => panic!("expected KeyVersionMismatch, got {:?}", other),
    }
}

// -----------------------------------------------------------------------------
// encrypt: mismatched primary/subkey versions
// -----------------------------------------------------------------------------

/// Build a structurally RFC-noncompliant key: a V6 primary bundled with the
/// public encryption subkeys of a V4 key. rpgp's `SecretKeyParamsBuilder`
/// refuses to *generate* such a pair, and rpgp 0.19's parser also rejects
/// it at load time ("Illegal public subkey V4 in v6 key"). Producing a
/// serialized blob still exercises the first defensive layer: the library
/// must refuse to encrypt to it, whether via the parse error or via the
/// belt-and-braces `KeyVersionMismatch` check in `collect_encryption_keys`.
fn malformed_v6_primary_with_v4_subkey_pub_armor() -> String {
    use pgp::composed::Deserializable;
    use pgp::composed::SignedPublicKey;
    use std::io::Cursor;

    let v4_pub = get_pub_key(&v4_key()).unwrap();
    let v6_pub = get_pub_key(&v6_key()).unwrap();

    let (v4_parsed, _) =
        SignedPublicKey::from_armor_single(Cursor::new(v4_pub.as_bytes())).unwrap();
    let (mut v6_parsed, _) =
        SignedPublicKey::from_armor_single(Cursor::new(v6_pub.as_bytes())).unwrap();

    // Splice: replace the V6 key's subkeys with the V4 key's subkeys.
    v6_parsed.public_subkeys = v4_parsed.public_subkeys;

    v6_parsed.to_armored_string(None.into()).unwrap()
}

#[test]
fn encrypt_to_v6_primary_with_v4_subkey_rejected() {
    let malformed = malformed_v6_primary_with_v4_subkey_pub_armor();

    let err = encrypt_bytes_to_multiple(&[malformed.as_bytes()], b"should not encrypt", true)
        .unwrap_err();

    // rpgp 0.19 rejects the splice during parsing (mismatched subkey version
    // is a hard error). `parse_public_key` flattens the specific rpgp message
    // into `Error::Parse("no matching packet found")` because it tries
    // armored → binary → secret-key-fallback and only reports a single
    // terminal error. The belt-and-braces `KeyVersionMismatch` check in
    // `collect_encryption_keys` would fire first if rpgp ever loosened its
    // parser. Either outcome proves the library refuses to encrypt to a
    // mismatched keyring — accept both.
    match err {
        Error::Parse(_) => { /* rpgp rejected the splice at parse time */ }
        Error::KeyVersionMismatch { existing, incoming } => {
            assert_eq!(existing, KeyVersion::V6, "primary is V6");
            assert_eq!(incoming, KeyVersion::V4, "spliced subkey is V4");
        }
        other => panic!(
            "expected Parse or KeyVersionMismatch for malformed V6/V4 recipient, got {:?}",
            other
        ),
    }
}

// -----------------------------------------------------------------------------
// keyring::merge_keys continued
// -----------------------------------------------------------------------------

#[test]
fn merge_same_v6_key_twice_succeeds() {
    // Round-tripping the same V6 key through merge should leave it unchanged
    // in version and preserve the fingerprint — ensures the new guard does not
    // false-positive on a legitimate same-version merge.
    let v6 = v6_key();
    let v6_pub = get_pub_key(&v6).unwrap();

    let merged = merge_keys(v6_pub.as_bytes(), v6_pub.as_bytes()).unwrap();
    let info = wecanencrypt::parse_key_bytes(&merged, false).unwrap();
    assert_eq!(info.key_version, KeyVersion::V6);
    assert_eq!(info.fingerprint.len(), 64);
}

// -----------------------------------------------------------------------------
// KeyStore::import_key
// -----------------------------------------------------------------------------

#[cfg(feature = "keystore")]
mod keystore {
    use super::*;
    use wecanencrypt::KeyStore;

    #[test]
    fn keystore_import_v6_then_same_v6_ok() {
        let store = KeyStore::open_in_memory().unwrap();

        let v6 = v6_key();
        let fp1 = store.import_key(&v6).unwrap();
        assert_eq!(fp1.len(), 64, "V6 fingerprint is SHA-256");

        // Re-importing the same V6 key should succeed (INSERT OR REPLACE path).
        let fp2 = store.import_key(&v6).unwrap();
        assert_eq!(fp1, fp2);

        let info = store.get_key_info(&fp1).unwrap();
        assert_eq!(info.key_version, KeyVersion::V6);
    }

    #[test]
    fn keystore_import_v4_then_v6_independent_fingerprints() {
        // V4 and V6 primary keys never share a fingerprint because the hash
        // structure differs, so these coexist as separate rows — no mismatch
        // error should fire.
        let store = KeyStore::open_in_memory().unwrap();

        let fp_v4 = store.import_key(&v4_key()).unwrap();
        let fp_v6 = store.import_key(&v6_key()).unwrap();
        assert_ne!(fp_v4, fp_v6);
        assert_eq!(fp_v4.len(), 40);
        assert_eq!(fp_v6.len(), 64);

        assert_eq!(
            store.get_key_info(&fp_v4).unwrap().key_version,
            KeyVersion::V4
        );
        assert_eq!(
            store.get_key_info(&fp_v6).unwrap().key_version,
            KeyVersion::V6
        );
    }

    #[test]
    fn keystore_round_trip_preserves_v6_export() {
        let store = KeyStore::open_in_memory().unwrap();
        let fp = store.import_key(&v6_key()).unwrap();

        let exported = store.export_key(&fp).unwrap();
        let info = wecanencrypt::parse_key_bytes(&exported, false).unwrap();
        assert_eq!(info.key_version, KeyVersion::V6);
        assert_eq!(info.fingerprint, fp);
    }
}
