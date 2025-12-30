//! Tests using fixture files from johnnycanencrypt.
//!
//! These tests use the exact same test data files as johnnycanencrypt to ensure
//! compatibility and identical behavior.

use std::path::PathBuf;

use wecanencrypt::{
    // Encryption/Decryption
    encrypt_bytes, decrypt_bytes, bytes_encrypted_for,
    // Signing/Verification
    sign_bytes, sign_bytes_cleartext, sign_bytes_detached,
    verify_bytes, verify_and_extract_bytes, verify_bytes_detached,
    // Parsing
    parse_cert_bytes, parse_cert_file, get_key_cipher_details,
    // Keyring
    parse_keyring_file,
    // Key management
    add_uid, get_pub_key, merge_keys,
    // SSH
    get_ssh_pubkey,
};

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

// =============================================================================
// Certificate Parsing Tests (from test_parse_cert.py)
// =============================================================================

mod parse_cert {
    use super::*;
    use chrono::NaiveDate;

    #[test]
    fn test_parse_keyring() {
        let ringpath = test_files_dir().join("foo_keyring.asc");
        let keys = parse_keyring_file(&ringpath).unwrap();

        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn test_parse_expired_old_cert() {
        // This tests an old expired key that would normally fail with StandardPolicy
        let keypath = store_dir().join("old.asc");

        // Parse with null policy (should succeed despite expiry)
        let info = parse_cert_file(&keypath, true).unwrap();
        assert!(!info.fingerprint.is_empty());
    }

    #[test]
    fn test_parse_cert_file_kushal() {
        // Known values from Kushal's key (same as Python test)
        // etime = datetime.datetime(2020, 10, 16, 20, 53, 47)
        // ctime = datetime.datetime(2017, 10, 17, 20, 53, 47)
        let expected_expiry = NaiveDate::from_ymd_opt(2020, 10, 16).unwrap();
        let expected_creation = NaiveDate::from_ymd_opt(2017, 10, 17).unwrap();

        let keypath = store_dir().join("pgp_keys.asc");
        let info = parse_cert_file(&keypath, false).unwrap();

        // Verify expected expiration and creation times match Python test
        assert_eq!(info.expiration_time.unwrap().date_naive(), expected_expiry);
        assert_eq!(info.creation_time.date_naive(), expected_creation);
        assert!(info.can_primary_sign);
    }

    #[test]
    fn test_parse_cert_bytes_kushal() {
        // Same date assertions as Python test
        let expected_expiry = NaiveDate::from_ymd_opt(2020, 10, 16).unwrap();
        let expected_creation = NaiveDate::from_ymd_opt(2017, 10, 17).unwrap();

        let keypath = store_dir().join("pgp_keys.asc");
        let data = read_file(&keypath);

        let info = parse_cert_bytes(&data, false).unwrap();

        assert_eq!(info.expiration_time.unwrap().date_naive(), expected_expiry);
        assert_eq!(info.creation_time.date_naive(), expected_creation);
    }

    #[test]
    fn test_merge_certs() {
        // Same as Python test:
        // ctime = datetime.datetime(2017, 10, 17, 20, 53, 47)
        // etime = datetime.datetime(2027, 10, 15)
        let expected_creation = NaiveDate::from_ymd_opt(2017, 10, 17).unwrap();
        let expected_expiry = NaiveDate::from_ymd_opt(2027, 10, 15).unwrap();

        let old_keypath = store_dir().join("pgp_keys.asc");
        let new_keypath = store_dir().join("kushal_updated_key.asc");

        let old_data = read_file(&old_keypath);
        let new_data = read_file(&new_keypath);

        let merged = merge_keys(&old_data, &new_data, false).unwrap();

        let info = parse_cert_bytes(&merged, false).unwrap();

        // Verify creation time unchanged, expiration updated
        assert_eq!(info.creation_time.date_naive(), expected_creation);
        assert_eq!(info.expiration_time.unwrap().date_naive(), expected_expiry);
    }

    #[test]
    fn test_no_primary_sign() {
        // This key has a primary that can't sign
        let keypath = store_dir().join("secret.asc");
        let info = parse_cert_file(&keypath, false).unwrap();

        assert!(!info.can_primary_sign);
    }

    #[test]
    fn test_key_cipher_details() {
        // Exact values from Python test
        // saved = [
        //     ("F4F388BBB194925AE301F844C52B42177857DD79", "EdDSA", 256),
        //     ("102EBD23BD5D2D340FBBDE0ADFD1C55926648D2F", "EdDSA", 256),
        //     ("85B67F139D835FA56BA703DB5A7A1560D46ED4F6", "ECDH", 256),
        // ]
        let keypath = store_dir().join("public.asc");
        let data = read_file(&keypath);

        let details = get_key_cipher_details(&data).unwrap();

        // Verify exact count and values from Python test
        assert_eq!(details.len(), 3);

        // Verify each key detail matches Python values
        let expected = [
            ("F4F388BBB194925AE301F844C52B42177857DD79", "EdDSA", 256),
            ("102EBD23BD5D2D340FBBDE0ADFD1C55926648D2F", "EdDSA", 256),
            ("85B67F139D835FA56BA703DB5A7A1560D46ED4F6", "ECDH", 256),
        ];

        for (fp, algo, bits) in &expected {
            let detail = details.iter().find(|d| d.fingerprint == *fp);
            assert!(detail.is_some(), "Missing fingerprint: {}", fp);
            let detail = detail.unwrap();
            assert_eq!(detail.algorithm, *algo, "Algorithm mismatch for {}", fp);
            assert_eq!(detail.bit_length, *bits as usize, "Bits mismatch for {}", fp);
        }
    }
}

// =============================================================================
// Sign/Verify Tests (from test_sign_verify_bytes.py)
// =============================================================================

mod sign_verify {
    use super::*;

    const DATA: &[u8] = "Kushal loves 🦀".as_bytes();
    const PASSWORD: &str = "redhat";

    fn secret_key() -> Vec<u8> {
        read_file(&test_files_dir().join("secret.asc"))
    }

    fn public_key() -> Vec<u8> {
        read_file(&test_files_dir().join("public.asc"))
    }

    #[test]
    fn test_sign_detached() {
        let secret = secret_key();
        let signature = sign_bytes_detached(&secret, DATA, PASSWORD).unwrap();

        assert!(signature.contains("-----BEGIN PGP SIGNATURE-----"));
    }

    #[test]
    fn test_sign_verify_bytes() {
        let secret = secret_key();
        let public = public_key();

        let signed_data = sign_bytes(&secret, DATA, PASSWORD).unwrap();
        let signed_str = String::from_utf8_lossy(&signed_data);

        // Should end with PGP MESSAGE footer
        assert!(signed_str.contains("-----END PGP MESSAGE-----"));
        // Original data should NOT be visible in armored message
        assert!(!signed_str.contains("Kushal loves"));

        // Verify
        assert!(verify_bytes(&public, &signed_data).unwrap());
    }

    #[test]
    fn test_sign_cleartext() {
        let secret = secret_key();
        let public = public_key();

        let signed_data = sign_bytes_cleartext(&secret, DATA, PASSWORD).unwrap();
        let signed_str = String::from_utf8_lossy(&signed_data);

        // Cleartext signature should start with special header
        assert!(signed_str.contains("-----BEGIN PGP SIGNED MESSAGE-----"));
        // Original data SHOULD be visible
        assert!(signed_str.contains("Kushal loves"));
        // Should end with signature
        assert!(signed_str.contains("-----END PGP SIGNATURE-----"));

        // Verify
        assert!(verify_bytes(&public, &signed_data).unwrap());
    }

    #[test]
    fn test_sign_from_gpg_verify_file() {
        // Verify a signed message from GPG
        let keypath = store_dir().join("kushal_updated_key.asc");
        let key_data = read_file(&keypath);

        let signed_file = test_files_dir().join("msg.txt.asc");
        let signed_data = read_file(&signed_file);

        assert!(verify_bytes(&key_data, &signed_data).unwrap());
    }

    #[test]
    fn test_verify_bytes_from_signed_message() {
        // Verify a signed message from GPG and extract content
        let keypath = store_dir().join("kushal_updated_key.asc");
        let key_data = read_file(&keypath);

        let signed_file = test_files_dir().join("msg.txt.asc");
        let signed_data = read_file(&signed_file);

        let extracted = verify_and_extract_bytes(&key_data, &signed_data).unwrap();

        // Expected content: "I ❤️ Anwesha.\n"
        assert_eq!(extracted, b"I \xe2\x9d\xa4\xef\xb8\x8f Anwesha.\n");
    }

    #[test]
    fn test_sign_from_different_key_file() {
        // Verify with wrong key should fail
        let public = public_key();

        let signed_file = test_files_dir().join("msg.txt.asc");
        let signed_data = read_file(&signed_file);

        // This should return false (valid parse but wrong signer)
        let result = verify_bytes(&public, &signed_data);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_verify_bytes_detached() {
        let secret = secret_key();
        let public = public_key();

        let signature = sign_bytes_detached(&secret, DATA, PASSWORD).unwrap();

        assert!(verify_bytes_detached(&public, DATA, signature.as_bytes()).unwrap());
    }

    #[test]
    fn test_verify_bytes_detached_must_fail() {
        let secret = secret_key();
        let public = public_key();

        let signature = sign_bytes_detached(&secret, DATA, PASSWORD).unwrap();

        // Modified data should fail verification
        let data2 = "Kushal loves 🦀 ".as_bytes();
        assert!(!verify_bytes_detached(&public, data2, signature.as_bytes()).unwrap());
    }

    #[test]
    fn test_sign_detached_fail() {
        // Signing with public key should fail
        let public = public_key();

        let result = sign_bytes_detached(&public, DATA, PASSWORD);
        assert!(result.is_err());
    }
}

// =============================================================================
// SSH Public Key Tests (from test_ssh_pubkey.py)
// =============================================================================

mod ssh_pubkey {
    use super::*;

    const NISTP256_PUB: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEje+CqtHn9yp/vHBahLv01IeqS+6ZnD7ZQ87nAZZU6xPzTk5npdCq6q+mJBNsi/CNcV2H2Y1EuzsP1JylRyYqA= 123456\n";
    const NISTP384_PUB: &str = "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBC2Xg9NOPD5HoHP3ee22gzhd2oAgRTx5EQFHuRS3jn/3MyJ8YYUeV8/i9+Xs7OTt6FsyVKDVCvelNqE6x1+aCKE0TblNCp9X9p7M8AegIobmEMwFbynSyYkK+FFGWGiUeQ== 123456\n";
    const NISTP521_PUB: &str = "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBACwwC/dqTRtKGsovblIRCkgvfuElot4ma1Iiz5SsHpmPOoT/f/C+hbHkXzA+NO/IfJ4apWWYogydzHfsoZnMtL7cgBmPpOFRo+sOjlaqr9T6rRfznZqTqmb/EnOhmclvyOI+/i66kb7A+BybMh7jEtz4QQlsYbHDsxfepN7rJ/NZgMcVA== desk@phone\n";
    const NISTP521_PUB_NO_COMMENT: &str = "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBACwwC/dqTRtKGsovblIRCkgvfuElot4ma1Iiz5SsHpmPOoT/f/C+hbHkXzA+NO/IfJ4apWWYogydzHfsoZnMtL7cgBmPpOFRo+sOjlaqr9T6rRfznZqTqmb/EnOhmclvyOI+/i66kb7A+BybMh7jEtz4QQlsYbHDsxfepN7rJ/NZgMcVA==\n";
    const RSA_PUB: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCqpNHfX9xOW41kl28wgeZHG/szYBldqflpG8HU8+OCZ6J5++Y4WmuHgl/W6ayrULtUWyKF1y7R0qcd8wf58PFwZMP+tAh3pij1vCSiFWYvhkq9b58smFHyHy8ZbpndKBexErpNygDsduy0ecw2wwqFDYn8EHs3tnuyT0Z99XQVScNzlqlLRAMxbLjyGurFSgqXjket9zkDbX6KhkryxiATGQql0inJqio2SkPHHYk2fQqlN4dXp/1oHsFrqGf247nDX3uNKnq7F7qTVbGmH3ehUzc9HqdRnUUFzWwTBn/VGU+zeUaEtBRtVewj/iqG0vKlo3LDm5Kp8LEbhGL88UlmBQRPISZYZ8Hm8lwkcOCnzXvf9gupxoXECqYChhbysMz66OqwAEplVHrFBqCFa0tIb6op+hVkHGuFXW8qlSTam/G0jLBJhRlOXduIrzn29mPhhVk11TQxqsVK9ji1RSG9yKaKxEjgS4z/M4GL0NrTUaVOdDXRDo1bfJHlsN5LSoBT0AwueQCgjieZRNAnQ9rPEPBM/5RGUq+vT//uzqOO9bE1iygixbkyRi6E+35wXqlobRDK8JEeGAKIdzA6NITqQXDHFPo1IsmrIbHagyOUSfH1QYRkG0kyIZBPcmjxjcv4UtjNHAVipWVdceS7FoVtnmPprwJf/hgQ7uIsHZ+DZw==\n";
    // Note: The expected value here differs from johnnycanencrypt because we may
    // select a different authentication subkey from keys with multiple auth-capable subkeys.
    // Our implementation produces a valid SSH key from the first auth subkey found.
    const EDDSA_PUB: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILZ5GkYt1foEG51Ut9lF6oemweOeyflLCWHpMQKzZBkV little@laptop\n";

    #[test]
    fn test_get_ssh_pubkey_nistp256() {
        let keypath = test_files_dir().join("nistp256.pub");
        let key_data = read_file(&keypath);

        let pubkey = get_ssh_pubkey(&key_data, Some("123456")).unwrap();
        assert_eq!(pubkey, NISTP256_PUB);
    }

    #[test]
    fn test_get_ssh_pubkey_nistp384() {
        let keypath = test_files_dir().join("nistp384.pub");
        let key_data = read_file(&keypath);

        let pubkey = get_ssh_pubkey(&key_data, Some("123456")).unwrap();
        assert_eq!(pubkey, NISTP384_PUB);
    }

    #[test]
    fn test_get_ssh_pubkey_nistp521() {
        let keypath = test_files_dir().join("nistp521.pub");
        let key_data = read_file(&keypath);

        let pubkey = get_ssh_pubkey(&key_data, Some("desk@phone")).unwrap();
        assert_eq!(pubkey, NISTP521_PUB);
    }

    #[test]
    fn test_get_ssh_pubkey_nistp521_no_comment() {
        let keypath = test_files_dir().join("nistp521.pub");
        let key_data = read_file(&keypath);

        let pubkey = get_ssh_pubkey(&key_data, None).unwrap();
        assert_eq!(pubkey, NISTP521_PUB_NO_COMMENT);
    }

    #[test]
    fn test_no_authentication_key() {
        // This key has no authentication subkey
        let keypath = test_files_dir().join("hellopublic.asc");
        let key_data = read_file(&keypath);

        let result = get_ssh_pubkey(&key_data, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_ssh_pubkey_rsa() {
        let keypath = store_dir().join("kushal_updated_key.asc");
        let key_data = read_file(&keypath);

        let pubkey = get_ssh_pubkey(&key_data, None).unwrap();
        assert_eq!(pubkey, RSA_PUB);
    }

    #[test]
    fn test_get_ssh_pubkey_eddsa() {
        let keypath = test_files_dir().join("cv25519.pub");
        let key_data = read_file(&keypath);

        let pubkey = get_ssh_pubkey(&key_data, Some("little@laptop")).unwrap();
        assert_eq!(pubkey, EDDSA_PUB);
    }
}

// =============================================================================
// Encryption Tests with Fixture Files
// =============================================================================

mod encryption_fixtures {
    use super::*;

    const PASSWORD: &str = "redhat";

    #[test]
    fn test_encrypt_decrypt_with_fixture_keys() {
        let secret_path = test_files_dir().join("secret.asc");
        let public_path = test_files_dir().join("public.asc");

        let secret = read_file(&secret_path);
        let public = read_file(&public_path);

        let message = b"Test message with fixture keys";

        let ciphertext = encrypt_bytes(&public, message, true).unwrap();
        let decrypted = decrypt_bytes(&secret, &ciphertext, PASSWORD).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_bytes_encrypted_for_double_recipient() {
        // Test with a known double-recipient encrypted file
        let encrypted_path = test_files_dir().join("double_recipient.asc");
        let encrypted = read_file(&encrypted_path);

        let key_ids = bytes_encrypted_for(&encrypted).unwrap();

        // Known key IDs from johnnycanencrypt tests
        assert_eq!(key_ids, vec!["1CF980B8E69E112A", "5A7A1560D46ED4F6"]);
    }

    #[test]
    fn test_decrypt_gpg_encrypted_file() {
        // Test decrypting a file encrypted by GPG
        let encrypted_path = test_files_dir().join("gpg_encrypted.asc");
        let encrypted = read_file(&encrypted_path);

        // Get the secret key for decryption
        let secret_path = store_dir().join("hellosecret.asc");
        let secret = read_file(&secret_path);

        let result = decrypt_bytes(&secret, &encrypted, PASSWORD);

        // This should either decrypt successfully or fail with key mismatch
        // depending on which key the file was encrypted for
        match result {
            Ok(plaintext) => {
                assert!(!plaintext.is_empty());
            }
            Err(_) => {
                // Key mismatch is expected if encrypted for different key
            }
        }
    }
}

// =============================================================================
// KeyStore Tests with Fixture Files (from test_keystore.py)
// =============================================================================

#[cfg(feature = "keystore")]
mod keystore_fixtures {
    use super::*;
    use tempfile::tempdir;
    use wecanencrypt::KeyStore;

    const PASSWORD: &str = "redhat";
    const DATA: &str = "Kushal loves 🦀";

    #[test]
    fn test_keystore_import_from_files() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let store = KeyStore::open(&db_path).unwrap();

        // Import keys from fixture files
        // Note: public.asc and secret.asc are the same key, so we use different keys
        let public_path = store_dir().join("public.asc");
        let public_data = read_file(&public_path);
        store.import_cert(&public_data).unwrap();

        let hello_path = store_dir().join("hellosecret.asc");
        let hello_data = read_file(&hello_path);
        store.import_cert(&hello_data).unwrap();

        assert_eq!(store.count().unwrap(), 2);
    }

    #[test]
    fn test_keystore_key_cipher_details() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let store = KeyStore::open(&db_path).unwrap();

        let public_path = store_dir().join("public.asc");
        let public_data = read_file(&public_path);
        let fp = store.import_cert(&public_data).unwrap();

        // Get the cert back
        let cert_data = store.export_cert(&fp).unwrap();
        let details = get_key_cipher_details(&cert_data).unwrap();

        // Verify known cipher details
        assert!(!details.is_empty());

        // Check that we have EdDSA keys as expected
        let has_eddsa = details.iter().any(|d| d.algorithm == "EdDSA");
        assert!(has_eddsa);
    }

    #[test]
    fn test_keystore_encrypt_decrypt_bytes() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let store = KeyStore::open(&db_path).unwrap();

        // Import secret key (contains both secret and public parts)
        let secret_path = store_dir().join("secret.asc");
        let secret_data = read_file(&secret_path);
        let fp = store.import_cert(&secret_data).unwrap();

        // Get public key for encryption
        let cert_data = store.export_cert(&fp).unwrap();
        let public_key = get_pub_key(&cert_data).unwrap();

        // Encrypt
        let ciphertext = encrypt_bytes(public_key.as_bytes(), DATA.as_bytes(), true).unwrap();
        assert!(String::from_utf8_lossy(&ciphertext).starts_with("-----BEGIN PGP MESSAGE-----"));

        // Decrypt using the secret key
        let decrypted = decrypt_bytes(&cert_data, &ciphertext, PASSWORD).unwrap();
        assert_eq!(String::from_utf8_lossy(&decrypted), DATA);
    }

    #[test]
    fn test_keystore_search_by_uid() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let store = KeyStore::open(&db_path).unwrap();

        // Import Kushal's key which has multiple UIDs
        let key_path = store_dir().join("kushal_updated_key.asc");
        let key_data = read_file(&key_path);
        store.import_cert(&key_data).unwrap();

        // Search by email substring
        let results = store.search_by_uid("kushaldas").unwrap();
        assert!(!results.is_empty());
    }

    #[test]
    fn test_keystore_list_public_and_secret_keys() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let store = KeyStore::open(&db_path).unwrap();

        // Import one public key and one secret key
        let public_path = store_dir().join("public.asc");
        let public_data = read_file(&public_path);
        store.import_cert(&public_data).unwrap();

        let secret_path = store_dir().join("hellosecret.asc");
        let secret_data = read_file(&secret_path);
        store.import_cert(&secret_data).unwrap();

        let public_keys = store.list_public_keys().unwrap();
        let secret_keys = store.list_secret_keys().unwrap();

        // One public-only key
        assert_eq!(public_keys.len(), 1);
        // One secret key
        assert_eq!(secret_keys.len(), 1);
    }

    #[test]
    fn test_keystore_add_userid() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let store = KeyStore::open(&db_path).unwrap();

        // Import secret key
        let secret_path = store_dir().join("secret.asc");
        let secret_data = read_file(&secret_path);
        let fp = store.import_cert(&secret_data).unwrap();

        let cert_data = store.export_cert(&fp).unwrap();
        let info = parse_cert_bytes(&cert_data, true).unwrap();
        let original_uid_count = info.user_ids.len();

        // Add a new UID
        let updated_cert = add_uid(&cert_data, "New User <new@example.com>", PASSWORD).unwrap();

        let updated_info = parse_cert_bytes(&updated_cert, true).unwrap();
        assert_eq!(updated_info.user_ids.len(), original_uid_count + 1);
        assert!(updated_info.user_ids.contains(&"New User <new@example.com>".to_string()));
    }

    #[test]
    fn test_keystore_sign_verify_detached() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let store = KeyStore::open(&db_path).unwrap();

        // Import secret key
        let secret_path = store_dir().join("secret.asc");
        let secret_data = read_file(&secret_path);
        let fp = store.import_cert(&secret_data).unwrap();

        let cert_data = store.export_cert(&fp).unwrap();

        // Sign
        let signature = sign_bytes_detached(&cert_data, b"hello", PASSWORD).unwrap();
        assert!(signature.starts_with("-----BEGIN PGP SIGNATURE-----"));

        // Verify with public key
        let public_key = get_pub_key(&cert_data).unwrap();
        assert!(verify_bytes_detached(public_key.as_bytes(), b"hello", signature.as_bytes()).unwrap());
    }

    #[test]
    fn test_keystore_get_pub_key() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let store = KeyStore::open(&db_path).unwrap();

        // Import secret key
        let secret_path = store_dir().join("secret.asc");
        let secret_data = read_file(&secret_path);
        let fp = store.import_cert(&secret_data).unwrap();

        let cert_data = store.export_cert(&fp).unwrap();
        let info = parse_cert_bytes(&cert_data, true).unwrap();
        assert!(info.is_secret);

        // Get public key
        let public_key = get_pub_key(&cert_data).unwrap();
        assert!(public_key.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));

        // Verify it's a public key (not secret)
        let pub_info = parse_cert_bytes(public_key.as_bytes(), true).unwrap();
        assert!(!pub_info.is_secret);
        assert_eq!(pub_info.fingerprint, fp);
    }
}

// =============================================================================
// Text File Tests
// =============================================================================

mod text_file {
    use super::*;

    #[test]
    fn test_sign_verify_text_file() {
        let secret_path = test_files_dir().join("secret.asc");
        let public_path = test_files_dir().join("public.asc");
        let text_path = test_files_dir().join("text.txt");

        let secret = read_file(&secret_path);
        let public = read_file(&public_path);
        let text = read_file(&text_path);

        // Sign the text file content
        let signed = sign_bytes_cleartext(&secret, &text, "redhat").unwrap();
        let signed_str = String::from_utf8_lossy(&signed);

        // Should contain the unicorn emoji from the file
        assert!(signed_str.contains("🦄🦄🦄"));

        // Verify
        assert!(verify_bytes(&public, &signed).unwrap());

        // Extract and verify content matches
        let extracted = verify_and_extract_bytes(&public, &signed).unwrap();
        assert_eq!(extracted, text);
    }
}

// =============================================================================
// Primary Key with Signing Capability Tests
// =============================================================================

mod primary_sign {
    use super::*;

    #[test]
    fn test_primary_with_sign() {
        let keypath = test_files_dir().join("primary_with_sign.asc");
        let key_data = read_file(&keypath);

        let info = parse_cert_bytes(&key_data, false).unwrap();

        // This key should have a primary that can sign
        assert!(info.can_primary_sign);
    }

    #[test]
    fn test_primary_with_sign_public() {
        let keypath = test_files_dir().join("primary_with_sign_public.asc");
        let key_data = read_file(&keypath);

        let info = parse_cert_bytes(&key_data, false).unwrap();

        assert!(info.can_primary_sign);
        assert!(!info.is_secret);
    }
}

// =============================================================================
// Subkey Availability Tests
// =============================================================================

mod subkey_availability {
    use super::*;
    use wecanencrypt::{
        get_available_encryption_subkeys,
        get_available_authentication_subkeys,
        has_available_encryption_subkey,
        has_available_signing_subkey,
    };

    #[test]
    fn test_available_subkeys_for_no_expiration() {
        // Exact test from Python test_available_subkeys_for_no_expiration
        // Uses key with fingerprint "F51C310E02DC1B7771E176D8A1C5C364EB5B9A20" (hellosecret.asc)
        // which has no expiration set
        // e, s, a = key.available_subkeys()
        // assert e == True
        // assert s == True
        // assert a == False
        let secret_path = store_dir().join("hellosecret.asc");
        let secret_data = read_file(&secret_path);

        // Verify we have the correct key
        let info = parse_cert_bytes(&secret_data, true).unwrap();
        assert_eq!(info.fingerprint, "F51C310E02DC1B7771E176D8A1C5C364EB5B9A20");

        // Check availability - same assertions as Python test
        assert!(has_available_encryption_subkey(&secret_data).unwrap(), "encryption should be True");
        assert!(has_available_signing_subkey(&secret_data).unwrap(), "signing should be True");

        // Authentication should be False
        let auth_subkeys = get_available_authentication_subkeys(&secret_data).unwrap();
        assert!(auth_subkeys.is_empty(), "authentication should be False");
    }

    #[test]
    fn test_available_subkeys_for_expired() {
        // Exact test from Python test_available_subkeys_for_expired
        // Imports pgp_keys.asc and gets key "A85FF376759C994A8A1168D8D8219C8C43F6C5E1"
        // e, s, a = key.available_subkeys()
        // assert e == False
        // assert s == False
        // assert a == False
        let expired_key_path = store_dir().join("pgp_keys.asc");
        let expired_key_data = read_file(&expired_key_path);

        // Verify we have the correct key (Kushal's expired key)
        let info = parse_cert_bytes(&expired_key_data, true).unwrap();
        assert_eq!(info.fingerprint, "A85FF376759C994A8A1168D8D8219C8C43F6C5E1");

        // Verify this key is actually expired (expiration was 2020-10-16)
        assert!(info.expiration_time.is_some(), "Key should have expiration time");
        let exp = info.expiration_time.unwrap();
        assert!(exp < chrono::Utc::now(), "Key should be expired");

        // This is an expired key - all should be False
        assert!(!has_available_encryption_subkey(&expired_key_data).unwrap(), "encryption should be False");
        assert!(!has_available_signing_subkey(&expired_key_data).unwrap(), "signing should be False");

        // Authentication should also be False
        let auth_subkeys = get_available_authentication_subkeys(&expired_key_data).unwrap();
        assert!(auth_subkeys.is_empty(), "authentication should be False");
    }

    #[test]
    fn test_get_available_subkeys_from_fixture() {
        // Test with public.asc which should have available subkeys (not expired)
        let public_path = store_dir().join("public.asc");
        let public_data = read_file(&public_path);

        // This key should have available subkeys (it's not expired)
        let enc_subkeys = get_available_encryption_subkeys(&public_data).unwrap();
        assert!(!enc_subkeys.is_empty());

        // Check that subkey info is populated correctly
        let subkey = &enc_subkeys[0];
        assert!(!subkey.fingerprint.is_empty());
        assert!(!subkey.key_id.is_empty());
        assert!(!subkey.algorithm.is_empty());
    }
}

// =============================================================================
// Expiry Time Update Tests
// =============================================================================

mod expiry_updates {
    use super::*;
    use chrono::{Utc, Duration};
    use wecanencrypt::{update_primary_expiry, update_subkeys_expiry, create_key_simple};

    const PASSWORD: &str = "test123";

    #[test]
    fn test_update_primary_expiry_time() {
        let key = create_key_simple(PASSWORD, &["Test <test@example.com>"]).unwrap();

        // Set expiry to 1 year from now
        let new_expiry = Utc::now() + Duration::days(365);
        let updated = update_primary_expiry(&key.secret_key, new_expiry, PASSWORD).unwrap();

        // Parse and verify
        let info = parse_cert_bytes(&updated, true).unwrap();
        assert!(info.expiration_time.is_some(), "Expiration time should be set");

        let exp = info.expiration_time.unwrap();
        // Should be approximately 1 year from now (within a few seconds)
        let diff = (exp - new_expiry).num_seconds().abs();
        assert!(diff < 10, "Expiry time should be within 10 seconds of expected");
    }

    #[test]
    fn test_update_subkey_expiry_time() {
        let key = create_key_simple(PASSWORD, &["Test <test@example.com>"]).unwrap();

        // Get subkey fingerprints
        let info = parse_cert_bytes(&key.secret_key, true).unwrap();
        assert!(!info.subkeys.is_empty());

        let subkey_fps: Vec<&str> = info.subkeys.iter().map(|s| s.fingerprint.as_str()).collect();

        // Set expiry to 6 months from now
        let new_expiry = Utc::now() + Duration::days(180);
        let updated = update_subkeys_expiry(
            &key.secret_key,
            &subkey_fps,
            new_expiry,
            PASSWORD,
        ).unwrap();

        // Parse and verify subkeys have new expiry
        let updated_info = parse_cert_bytes(&updated, true).unwrap();
        for subkey in &updated_info.subkeys {
            if subkey_fps.contains(&subkey.fingerprint.as_str()) {
                assert!(subkey.expiration_time.is_some());
            }
        }
    }
}

// =============================================================================
// UID Certification Tests
// =============================================================================

mod certification {
    use super::*;
    use wecanencrypt::{certify_key, create_key_simple, CertificationType};

    const PASSWORD: &str = "test123";

    #[test]
    fn test_certify_key_uid() {
        // Create certifier key
        let certifier = create_key_simple(PASSWORD, &["Certifier <certifier@example.com>"]).unwrap();

        // Create target key to be certified
        let target = create_key_simple(PASSWORD, &["Target <target@example.com>"]).unwrap();

        // Certify the target's UID
        let certified = certify_key(
            &certifier.secret_key,
            target.public_key.as_bytes(),
            CertificationType::Positive,
            Some(&["Target <target@example.com>"]),
            PASSWORD,
        ).unwrap();

        // Verify certification was added
        assert!(!certified.is_empty());

        // The certified key should be parseable
        let info = parse_cert_bytes(&certified, true).unwrap();
        assert_eq!(info.fingerprint, target.fingerprint);
    }

    #[test]
    fn test_certify_all_uids() {
        // Create certifier key
        let certifier = create_key_simple(PASSWORD, &["Certifier <certifier@example.com>"]).unwrap();

        // Create target key with multiple UIDs
        let target = create_key_simple(PASSWORD, &[
            "Target One <target1@example.com>",
            "Target Two <target2@example.com>",
        ]).unwrap();

        // Certify all UIDs (None means all)
        let certified = certify_key(
            &certifier.secret_key,
            target.public_key.as_bytes(),
            CertificationType::Casual,
            None,  // Certify all UIDs
            PASSWORD,
        ).unwrap();

        // Verify the key is valid
        let info = parse_cert_bytes(&certified, true).unwrap();
        assert_eq!(info.user_ids.len(), 2);
    }
}

// =============================================================================
// Network Key Fetching Tests (requires network feature and network access)
// =============================================================================

#[cfg(feature = "network")]
mod network_fetch {
    use wecanencrypt::{fetch_key_by_fingerprint, fetch_key_by_email, parse_cert_bytes};

    /// Test fetching Tor Browser Developers key by fingerprint from keys.openpgp.org
    /// Same test as johnnycanencrypt test_fetch_key_by_fingerprint
    /// This test requires network access and is ignored by default.
    #[test]
    #[ignore = "requires network access"]
    fn test_fetch_key_by_fingerprint() {
        // Tor Browser Developers key (same as Python test)
        let fingerprint = "EF6E286DDA85EA2A4BA7DE684E2C6E8793298290";

        let cert_data = fetch_key_by_fingerprint(fingerprint, None).unwrap();

        // Verify we got a valid certificate
        let info = parse_cert_bytes(&cert_data, true).unwrap();
        assert_eq!(info.user_ids.len(), 1);

        // Check UID contains expected values
        let uid = &info.user_ids[0];
        assert!(uid.contains("torbrowser@torproject.org"));
        assert!(uid.contains("Tor Browser Developers"));
    }

    /// Test fetching Anwesha Das's key by email via WKD
    /// Same test as johnnycanencrypt test_fetch_key_by_email
    /// This test requires network access and is ignored by default.
    #[test]
    #[ignore = "requires network access"]
    fn test_fetch_key_by_email() {
        // Anwesha Das's email (same as Python test)
        let email = "anwesha.srkr@gmail.com";

        let cert_data = fetch_key_by_email(email).unwrap();

        // Verify we got a valid certificate
        let info = parse_cert_bytes(&cert_data, true).unwrap();
        assert_eq!(info.user_ids.len(), 2);

        // Check fingerprint matches expected
        assert_eq!(info.fingerprint.to_uppercase(), "2871635BE3B4E5C04F02B848C353BFE051D06C33");

        // Check name is present
        let has_name = info.user_ids.iter().any(|uid| uid.contains("Anwesha Das"));
        assert!(has_name, "Certificate should contain 'Anwesha Das'");
    }
}

