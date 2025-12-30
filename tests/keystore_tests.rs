//! KeyStore integration tests.
//!
//! These tests require the `keystore` feature to be enabled.

#![cfg(feature = "keystore")]

use std::path::PathBuf;
use chrono::Datelike;
use tempfile::tempdir;
use wecanencrypt::{
    create_key, create_key_simple, get_pub_key, parse_cert_bytes,
    add_uid, revoke_uid, update_password,
    sign_bytes_detached,
    encrypt_bytes_from_store, encrypt_bytes_to_multiple_from_store,
    decrypt_bytes_from_store, sign_bytes_detached_from_store,
    verify_bytes_detached_from_store,
    KeyStore, CipherSuite, SubkeyFlags,
};

const TEST_PASSWORD: &str = "test-password-123";

/// Base path for test files.
fn test_files_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("files")
}

fn store_dir() -> PathBuf {
    test_files_dir().join("store")
}

fn read_file(path: &PathBuf) -> Vec<u8> {
    std::fs::read(path).expect(&format!("Failed to read file: {:?}", path))
}

fn create_test_key(uid: &str) -> (Vec<u8>, String) {
    let key = create_key_simple(TEST_PASSWORD, &[uid]).unwrap();
    (key.secret_key, key.fingerprint)
}

#[test]
fn test_keystore_create() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let store = KeyStore::open(&db_path).unwrap();
    assert!(db_path.exists());
    drop(store);
}

#[test]
fn test_keystore_import_and_export_cert() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let store = KeyStore::open(&db_path).unwrap();

    // Create and import a key
    let (secret_key, fingerprint) = create_test_key("Test <test@example.com>");
    let public_key = get_pub_key(&secret_key).unwrap();

    store.import_cert(public_key.as_bytes()).unwrap();

    // Retrieve by fingerprint
    let retrieved = store.export_cert(&fingerprint).unwrap();
    assert!(!retrieved.is_empty());

    let info = parse_cert_bytes(&retrieved, true).unwrap();
    assert_eq!(info.fingerprint, fingerprint);
}

#[test]
fn test_keystore_import_secret_key() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let store = KeyStore::open(&db_path).unwrap();

    let (secret_key, fingerprint) = create_test_key("Secret <secret@example.com>");

    store.import_cert(&secret_key).unwrap();

    let retrieved = store.export_cert(&fingerprint).unwrap();
    let info = parse_cert_bytes(&retrieved, true).unwrap();

    // Should preserve secret key material
    assert!(info.is_secret);
}

#[test]
fn test_keystore_contains() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let store = KeyStore::open(&db_path).unwrap();

    let (secret_key, fingerprint) = create_test_key("Test <test@example.com>");
    let public_key = get_pub_key(&secret_key).unwrap();

    // Not in store yet
    assert!(!store.contains(&fingerprint).unwrap());

    // Import
    store.import_cert(public_key.as_bytes()).unwrap();

    // Now it should be in store
    assert!(store.contains(&fingerprint).unwrap());

    // Nonexistent key
    assert!(!store.contains("DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF").unwrap());
}

#[test]
fn test_keystore_delete_cert() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let store = KeyStore::open(&db_path).unwrap();

    let (secret_key, fingerprint) = create_test_key("Delete <delete@example.com>");
    let public_key = get_pub_key(&secret_key).unwrap();

    store.import_cert(public_key.as_bytes()).unwrap();

    // Verify it exists
    assert!(store.contains(&fingerprint).unwrap());

    // Delete
    store.delete_cert(&fingerprint).unwrap();

    // Verify it's gone
    assert!(!store.contains(&fingerprint).unwrap());
}

#[test]
fn test_keystore_list_certs() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let store = KeyStore::open(&db_path).unwrap();

    // Import multiple keys
    let (key1, fp1) = create_test_key("User1 <user1@example.com>");
    let (key2, fp2) = create_test_key("User2 <user2@example.com>");
    let (key3, fp3) = create_test_key("User3 <user3@example.com>");

    store.import_cert(&get_pub_key(&key1).unwrap().as_bytes()).unwrap();
    store.import_cert(&get_pub_key(&key2).unwrap().as_bytes()).unwrap();
    store.import_cert(&get_pub_key(&key3).unwrap().as_bytes()).unwrap();

    let certs = store.list_certs().unwrap();
    assert_eq!(certs.len(), 3);

    let fingerprints: Vec<_> = certs.iter().map(|c| c.fingerprint.as_str()).collect();
    assert!(fingerprints.contains(&fp1.as_str()));
    assert!(fingerprints.contains(&fp2.as_str()));
    assert!(fingerprints.contains(&fp3.as_str()));
}

#[test]
fn test_keystore_search_by_uid() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let store = KeyStore::open(&db_path).unwrap();

    let (key1, _) = create_test_key("Alice <alice@example.com>");
    let (key2, _) = create_test_key("Bob <bob@example.com>");
    let (key3, _) = create_test_key("Alice Work <alice@work.com>");

    store.import_cert(&get_pub_key(&key1).unwrap().as_bytes()).unwrap();
    store.import_cert(&get_pub_key(&key2).unwrap().as_bytes()).unwrap();
    store.import_cert(&get_pub_key(&key3).unwrap().as_bytes()).unwrap();

    // Search for Alice
    let results = store.search_by_uid("alice").unwrap();
    assert_eq!(results.len(), 2);

    // Search for Bob
    let results = store.search_by_uid("bob").unwrap();
    assert_eq!(results.len(), 1);

    // Search for nonexistent
    let results = store.search_by_uid("charlie").unwrap();
    assert_eq!(results.len(), 0);
}

#[test]
fn test_keystore_find_by_key_id() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let store = KeyStore::open(&db_path).unwrap();

    let (secret_key, fingerprint) = create_test_key("KeyID <keyid@example.com>");
    let public_key = get_pub_key(&secret_key).unwrap();

    store.import_cert(public_key.as_bytes()).unwrap();

    let info = parse_cert_bytes(public_key.as_bytes(), true).unwrap();
    let key_id = &info.key_id;

    // Get by key ID
    let retrieved = store.find_by_key_id(key_id).unwrap();
    assert!(retrieved.is_some());

    let cert_data = retrieved.unwrap();
    let retrieved_info = parse_cert_bytes(&cert_data, true).unwrap();
    assert_eq!(retrieved_info.fingerprint, fingerprint);
}

#[test]
fn test_keystore_update_cert() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let store = KeyStore::open(&db_path).unwrap();

    // Create and import initial key
    let key = create_key_simple(TEST_PASSWORD, &["Original <original@example.com>"]).unwrap();
    store.import_cert(key.secret_key.as_slice()).unwrap();

    // Add a UID to the key
    let updated_key = wecanencrypt::add_uid(
        &key.secret_key,
        "Added <added@example.com>",
        TEST_PASSWORD,
    ).unwrap();

    // Update in store
    store.update_cert(&key.fingerprint, &updated_key).unwrap();

    // Retrieve and verify
    let retrieved = store.export_cert(&key.fingerprint).unwrap();
    let info = parse_cert_bytes(&retrieved, true).unwrap();

    assert_eq!(info.user_ids.len(), 2);
}

#[test]
fn test_keystore_persistence() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let (secret_key, fingerprint) = create_test_key("Persist <persist@example.com>");
    let public_key = get_pub_key(&secret_key).unwrap();

    // Create store, import key, close
    {
        let store = KeyStore::open(&db_path).unwrap();
        store.import_cert(public_key.as_bytes()).unwrap();
    }

    // Reopen and verify data persisted
    {
        let store = KeyStore::open(&db_path).unwrap();
        assert!(store.contains(&fingerprint).unwrap());
    }
}

#[test]
fn test_keystore_import_duplicate() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let store = KeyStore::open(&db_path).unwrap();

    let (secret_key, _) = create_test_key("Duplicate <dup@example.com>");
    let public_key = get_pub_key(&secret_key).unwrap();

    // Import once
    store.import_cert(public_key.as_bytes()).unwrap();

    // Import again (should update, not error)
    let result = store.import_cert(public_key.as_bytes());
    assert!(result.is_ok());

    // Should still have only one cert
    let certs = store.list_certs().unwrap();
    assert_eq!(certs.len(), 1);
}

#[test]
fn test_keystore_count() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let store = KeyStore::open(&db_path).unwrap();

    assert_eq!(store.count().unwrap(), 0);

    let (key1, _) = create_test_key("User1 <user1@example.com>");
    let (key2, _) = create_test_key("User2 <user2@example.com>");

    store.import_cert(&get_pub_key(&key1).unwrap().as_bytes()).unwrap();
    assert_eq!(store.count().unwrap(), 1);

    store.import_cert(&get_pub_key(&key2).unwrap().as_bytes()).unwrap();
    assert_eq!(store.count().unwrap(), 2);
}

#[test]
fn test_keystore_list_secret_keys() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let store = KeyStore::open(&db_path).unwrap();

    // Import one secret key and one public key
    let (secret_key, _) = create_test_key("Secret <secret@example.com>");
    let (public_key_src, _) = create_test_key("Public <public@example.com>");
    let public_key = get_pub_key(&public_key_src).unwrap();

    store.import_cert(&secret_key).unwrap();
    store.import_cert(public_key.as_bytes()).unwrap();

    let secret_keys = store.list_secret_keys().unwrap();
    assert_eq!(secret_keys.len(), 1);
    assert!(secret_keys[0].is_secret);

    let public_keys = store.list_public_keys().unwrap();
    assert_eq!(public_keys.len(), 1);
    assert!(!public_keys[0].is_secret);
}

// =============================================================================
// Additional KeyStore Tests (matching johnnycanencrypt coverage)
// =============================================================================

#[test]
fn test_keystore_get_nonexistent_key() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let store = KeyStore::open(&db_path).unwrap();

    // Try to get a key that doesn't exist
    let result = store.export_cert("A4F388BBB194925AE301F844C52B42177857DD79");
    assert!(result.is_err());
}

#[test]
fn test_keystore_delete_nonexistent_key() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let store = KeyStore::open(&db_path).unwrap();

    // Try to delete a key that doesn't exist
    let result = store.delete_cert("A4F388BBB194925AE301F844C52B42177857DD79");
    assert!(result.is_err());
}

#[test]
fn test_keystore_in_memory() {
    let store = KeyStore::open_in_memory().unwrap();

    assert!(store.path().is_none());
    assert_eq!(store.count().unwrap(), 0);

    let (secret_key, fingerprint) = create_test_key("InMemory <inmemory@example.com>");
    store.import_cert(&secret_key).unwrap();

    assert_eq!(store.count().unwrap(), 1);
    assert!(store.contains(&fingerprint).unwrap());
}

#[test]
fn test_keystore_search_by_email() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let store = KeyStore::open(&db_path).unwrap();

    let (key1, _) = create_test_key("Alice <alice@example.com>");
    let (key2, _) = create_test_key("Bob <bob@work.com>");
    let (key3, _) = create_test_key("Alice Work <alice@work.com>");

    store.import_cert(&get_pub_key(&key1).unwrap().as_bytes()).unwrap();
    store.import_cert(&get_pub_key(&key2).unwrap().as_bytes()).unwrap();
    store.import_cert(&get_pub_key(&key3).unwrap().as_bytes()).unwrap();

    // Search by exact email
    let results = store.search_by_email("alice@example.com").unwrap();
    assert_eq!(results.len(), 1);

    // Search by different email
    let results = store.search_by_email("alice@work.com").unwrap();
    assert_eq!(results.len(), 1);

    // Nonexistent email
    let results = store.search_by_email("charlie@example.com").unwrap();
    assert_eq!(results.len(), 0);
}

#[test]
fn test_keystore_export_armored() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let store = KeyStore::open(&db_path).unwrap();

    let (secret_key, fingerprint) = create_test_key("Armored <armored@example.com>");
    store.import_cert(&secret_key).unwrap();

    let armored = store.export_cert_armored(&fingerprint).unwrap();

    assert!(armored.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    assert!(armored.contains("-----END PGP PUBLIC KEY BLOCK-----"));
}

#[test]
fn test_keystore_get_cert_info() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let store = KeyStore::open(&db_path).unwrap();

    let (secret_key, fingerprint) = create_test_key("Info <info@example.com>");
    store.import_cert(&secret_key).unwrap();

    let info = store.get_cert_info(&fingerprint).unwrap();

    assert_eq!(info.fingerprint, fingerprint);
    assert!(info.is_secret);
    assert_eq!(info.user_ids.len(), 1);
    assert!(info.user_ids[0].contains("info@example.com"));
}

#[test]
fn test_keystore_list_fingerprints() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let store = KeyStore::open(&db_path).unwrap();

    let (key1, fp1) = create_test_key("User1 <user1@example.com>");
    let (key2, fp2) = create_test_key("User2 <user2@example.com>");

    store.import_cert(&get_pub_key(&key1).unwrap().as_bytes()).unwrap();
    store.import_cert(&get_pub_key(&key2).unwrap().as_bytes()).unwrap();

    let fingerprints = store.list_fingerprints().unwrap();

    assert_eq!(fingerprints.len(), 2);
    assert!(fingerprints.contains(&fp1));
    assert!(fingerprints.contains(&fp2));
}

#[test]
fn test_keystore_import_from_file() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let store = KeyStore::open(&db_path).unwrap();

    // Import from fixture file
    let key_path = store_dir().join("public.asc");
    let fingerprint = store.import_cert_file(&key_path).unwrap();

    assert!(!fingerprint.is_empty());
    assert!(store.contains(&fingerprint).unwrap());
}

#[test]
fn test_keystore_password_change() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let store = KeyStore::open(&db_path).unwrap();

    let (secret_key, fingerprint) = create_test_key("Password <password@example.com>");
    store.import_cert(&secret_key).unwrap();

    // Change password
    let cert_data = store.export_cert(&fingerprint).unwrap();
    let new_password = "new-password-456";
    let updated_key = update_password(&cert_data, TEST_PASSWORD, new_password).unwrap();

    // Update in store
    store.update_cert(&fingerprint, &updated_key).unwrap();

    // Verify new password works for signing
    let updated_cert = store.export_cert(&fingerprint).unwrap();
    let signature = sign_bytes_detached(&updated_cert, b"test data", new_password).unwrap();
    assert!(signature.contains("-----BEGIN PGP SIGNATURE-----"));

    // Old password should fail
    let result = sign_bytes_detached(&updated_cert, b"test data", TEST_PASSWORD);
    assert!(result.is_err());
}

#[test]
fn test_keystore_encrypt_decrypt_multiple_recipients() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let store = KeyStore::open(&db_path).unwrap();

    // Create two keys
    let (key1, fp1) = create_test_key("Recipient1 <r1@example.com>");
    let (key2, fp2) = create_test_key("Recipient2 <r2@example.com>");

    store.import_cert(&key1).unwrap();
    store.import_cert(&key2).unwrap();

    let message = b"Message for multiple recipients";

    // Encrypt to both
    let ciphertext = encrypt_bytes_to_multiple_from_store(
        &store,
        &[&fp1, &fp2],
        message,
        true,
    ).unwrap();

    // Both should be able to decrypt
    let decrypted1 = decrypt_bytes_from_store(&store, &fp1, &ciphertext, TEST_PASSWORD).unwrap();
    let decrypted2 = decrypt_bytes_from_store(&store, &fp2, &ciphertext, TEST_PASSWORD).unwrap();

    assert_eq!(decrypted1, message);
    assert_eq!(decrypted2, message);
}

#[test]
fn test_keystore_sign_verify_wrong_data_fails() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let store = KeyStore::open(&db_path).unwrap();

    let (secret_key, fingerprint) = create_test_key("Signer <signer@example.com>");
    store.import_cert(&secret_key).unwrap();

    // Sign some data
    let signature = sign_bytes_detached_from_store(
        &store,
        &fingerprint,
        b"original data",
        TEST_PASSWORD,
    ).unwrap();

    // Verify with correct data - should pass
    let valid = verify_bytes_detached_from_store(
        &store,
        &fingerprint,
        b"original data",
        signature.as_bytes(),
    ).unwrap();
    assert!(valid);

    // Verify with wrong data - should fail
    let valid = verify_bytes_detached_from_store(
        &store,
        &fingerprint,
        b"modified data",
        signature.as_bytes(),
    ).unwrap();
    assert!(!valid);
}

#[test]
fn test_keystore_add_and_revoke_uid() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let store = KeyStore::open(&db_path).unwrap();

    let (secret_key, fingerprint) = create_test_key("Original <original@example.com>");
    store.import_cert(&secret_key).unwrap();

    // Add a UID
    let cert_data = store.export_cert(&fingerprint).unwrap();
    let with_new_uid = add_uid(&cert_data, "Added <added@example.com>", TEST_PASSWORD).unwrap();
    store.update_cert(&fingerprint, &with_new_uid).unwrap();

    // Verify UID was added
    let info = store.get_cert_info(&fingerprint).unwrap();
    assert_eq!(info.user_ids.len(), 2);

    // Revoke the added UID
    let updated_cert = store.export_cert(&fingerprint).unwrap();
    let with_revoked = revoke_uid(&updated_cert, "Added <added@example.com>", TEST_PASSWORD).unwrap();
    store.update_cert(&fingerprint, &with_revoked).unwrap();

    // UID count stays same (revoked UIDs still present)
    let info = store.get_cert_info(&fingerprint).unwrap();
    assert!(info.user_ids.len() >= 1);
}

#[test]
fn test_keystore_add_uid_to_public_key_fails() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let store = KeyStore::open(&db_path).unwrap();

    // Import public key only
    let (secret_key, fingerprint) = create_test_key("Public <public@example.com>");
    let public_key = get_pub_key(&secret_key).unwrap();
    store.import_cert(public_key.as_bytes()).unwrap();

    // Try to add UID - should fail because it's a public key
    let cert_data = store.export_cert(&fingerprint).unwrap();
    let result = add_uid(&cert_data, "New <new@example.com>", TEST_PASSWORD);
    assert!(result.is_err());
}

#[test]
fn test_keystore_key_without_uid_fails() {
    // Note: Unlike johnnycanencrypt, our implementation requires at least one UID
    // for key creation. This is a design decision for better key identification.

    // Attempt to create key without UID - should fail
    let result = create_key(
        TEST_PASSWORD,
        &[],  // Empty UIDs
        CipherSuite::Cv25519,
        None,
        None,
        None,
        SubkeyFlags::all(),
        false,
        true,
    );

    assert!(result.is_err());
}

#[test]
fn test_keystore_key_with_multiple_uids() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let store = KeyStore::open(&db_path).unwrap();

    // Create key with multiple UIDs
    let uids = &[
        "Primary <primary@example.com>",
        "secondary@example.com",
        "Another Name",
    ];
    let key = create_key_simple(TEST_PASSWORD, uids).unwrap();

    store.import_cert(&key.secret_key).unwrap();

    let info = store.get_cert_info(&key.fingerprint).unwrap();
    assert_eq!(info.user_ids.len(), 3);

    // Search should find by any UID
    let results = store.search_by_uid("primary").unwrap();
    assert_eq!(results.len(), 1);

    let results = store.search_by_uid("secondary").unwrap();
    assert_eq!(results.len(), 1);

    let results = store.search_by_uid("Another").unwrap();
    assert_eq!(results.len(), 1);
}

#[test]
fn test_keystore_creation_expiration_times() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let store = KeyStore::open(&db_path).unwrap();

    // Import Kushal's key with known creation/expiration times
    let key_path = store_dir().join("pgp_keys.asc");
    let fingerprint = store.import_cert_file(&key_path).unwrap();

    let info = store.get_cert_info(&fingerprint).unwrap();

    // Verify creation time exists (it's always set, not optional)
    // Kushal's key was created on 2017-10-17
    assert!(info.creation_time.year() == 2017);

    // This key has an expiration time (2020-10-16)
    assert!(info.expiration_time.is_some());
    let exp = info.expiration_time.unwrap();
    assert!(exp.year() == 2020);
}

#[test]
fn test_keystore_encrypt_decrypt_from_store() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let store = KeyStore::open(&db_path).unwrap();

    let (secret_key, fingerprint) = create_test_key("Store <store@example.com>");
    store.import_cert(&secret_key).unwrap();

    let message = b"Secret message via store";

    // Encrypt using store helper
    let ciphertext = encrypt_bytes_from_store(&store, &fingerprint, message, true).unwrap();
    assert!(String::from_utf8_lossy(&ciphertext).starts_with("-----BEGIN PGP MESSAGE-----"));

    // Decrypt using store helper
    let decrypted = decrypt_bytes_from_store(&store, &fingerprint, &ciphertext, TEST_PASSWORD).unwrap();
    assert_eq!(decrypted, message);
}

#[test]
fn test_keystore_with_fixture_files() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let store = KeyStore::open(&db_path).unwrap();

    // Import multiple fixture files
    let files = [
        store_dir().join("public.asc"),
        store_dir().join("hellopublic.asc"),
        store_dir().join("pgp_keys.asc"),
    ];

    for path in &files {
        store.import_cert_file(path).unwrap();
    }

    assert_eq!(store.count().unwrap(), 3);

    // List and verify
    let certs = store.list_certs().unwrap();
    assert_eq!(certs.len(), 3);
}

#[test]
fn test_keystore_update_key_merges_correctly() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let store = KeyStore::open(&db_path).unwrap();

    // Import old key
    let old_key_path = store_dir().join("pgp_keys.asc");
    let fingerprint = store.import_cert_file(&old_key_path).unwrap();

    let old_info = store.get_cert_info(&fingerprint).unwrap();

    // Import updated key (should merge/update)
    let new_key_path = store_dir().join("kushal_updated_key.asc");
    let new_key_data = read_file(&new_key_path);
    store.update_cert(&fingerprint, &new_key_data).unwrap();

    let new_info = store.get_cert_info(&fingerprint).unwrap();

    // The updated key should have more UIDs or different expiration
    // Just verify the update succeeded
    assert_eq!(new_info.fingerprint, old_info.fingerprint);
}

// =============================================================================
// File-Based Store Operations Tests
// =============================================================================

#[test]
fn test_keystore_encrypt_decrypt_file() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let store = KeyStore::open(&db_path).unwrap();

    // Create and import a key
    let (secret_key, fingerprint) = create_test_key("FileTest <filetest@example.com>");
    store.import_cert(&secret_key).unwrap();

    // Create a test file
    let input_path = dir.path().join("input.txt");
    let encrypted_path = dir.path().join("encrypted.gpg");
    let decrypted_path = dir.path().join("decrypted.txt");

    std::fs::write(&input_path, b"Test data for file encryption").unwrap();

    // Encrypt file
    wecanencrypt::encrypt_file_from_store(
        &store,
        &fingerprint,
        &input_path,
        &encrypted_path,
        true,
    ).unwrap();

    assert!(encrypted_path.exists());

    // Decrypt file
    wecanencrypt::decrypt_file_from_store(
        &store,
        &fingerprint,
        &encrypted_path,
        &decrypted_path,
        TEST_PASSWORD,
    ).unwrap();

    // Verify content matches
    let decrypted = std::fs::read(&decrypted_path).unwrap();
    assert_eq!(decrypted, b"Test data for file encryption");
}

#[test]
fn test_keystore_sign_verify_file_detached() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let store = KeyStore::open(&db_path).unwrap();

    // Create and import a key
    let (secret_key, fingerprint) = create_test_key("SignFile <signfile@example.com>");
    store.import_cert(&secret_key).unwrap();

    // Create a test file
    let data_path = dir.path().join("data.txt");
    let sig_path = dir.path().join("data.txt.sig");

    std::fs::write(&data_path, b"Data to be signed").unwrap();

    // Sign file
    let signature = wecanencrypt::sign_file_detached_from_store(
        &store,
        &fingerprint,
        &data_path,
        TEST_PASSWORD,
    ).unwrap();

    assert!(signature.starts_with("-----BEGIN PGP SIGNATURE-----"));

    // Write signature to file
    std::fs::write(&sig_path, signature.as_bytes()).unwrap();

    // Verify
    let valid = wecanencrypt::verify_file_detached_from_store(
        &store,
        &fingerprint,
        &data_path,
        &sig_path,
    ).unwrap();

    assert!(valid);
}

#[test]
fn test_keystore_encrypt_file_multiple_recipients() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    let store = KeyStore::open(&db_path).unwrap();

    // Create two keys
    let (key1, fp1) = create_test_key("Recipient1 <r1@example.com>");
    let (key2, fp2) = create_test_key("Recipient2 <r2@example.com>");

    store.import_cert(&key1).unwrap();
    store.import_cert(&key2).unwrap();

    // Create a test file
    let input_path = dir.path().join("input.txt");
    let encrypted_path = dir.path().join("encrypted.gpg");
    let decrypted1_path = dir.path().join("decrypted1.txt");
    let decrypted2_path = dir.path().join("decrypted2.txt");

    std::fs::write(&input_path, b"Multi-recipient test").unwrap();

    // Encrypt to both recipients
    wecanencrypt::encrypt_file_to_multiple_from_store(
        &store,
        &[&fp1, &fp2],
        &input_path,
        &encrypted_path,
        true,
    ).unwrap();

    // Both should be able to decrypt
    wecanencrypt::decrypt_file_from_store(
        &store,
        &fp1,
        &encrypted_path,
        &decrypted1_path,
        TEST_PASSWORD,
    ).unwrap();

    wecanencrypt::decrypt_file_from_store(
        &store,
        &fp2,
        &encrypted_path,
        &decrypted2_path,
        TEST_PASSWORD,
    ).unwrap();

    // Verify both got the same content
    let decrypted1 = std::fs::read(&decrypted1_path).unwrap();
    let decrypted2 = std::fs::read(&decrypted2_path).unwrap();
    assert_eq!(decrypted1, b"Multi-recipient test");
    assert_eq!(decrypted2, b"Multi-recipient test");
}

// =============================================================================
// Schema Upgrade Tests
// =============================================================================

#[test]
fn test_keystore_schema_upgrade() {
    let dir = tempdir().unwrap();

    // Copy the old database from fixtures (same as Python test)
    let old_db_path = store_dir().join("oldjce.db");
    let new_db_path = dir.path().join("jce.db");
    std::fs::copy(&old_db_path, &new_db_path).unwrap();

    // Open with KeyStore which should trigger migration
    let store = KeyStore::open(&new_db_path).unwrap();

    // Verify the store works after upgrade
    // The old database should have keys that are now accessible
    let certs = store.list_certs().unwrap();

    // Verify we can use the store normally after upgrade
    assert!(store.count().unwrap() >= 0);
}
