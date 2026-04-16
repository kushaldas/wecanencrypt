//! Integration tests for wecanencrypt library.
//!
//! These tests verify the full functionality of the library including
//! key generation, encryption, decryption, signing, and verification.

use wecanencrypt::{
    // Key management
    add_uid,
    bytes_encrypted_for,
    // Key generation
    create_key,
    create_key_simple,
    // Decryption
    decrypt_bytes,
    // Encryption
    encrypt_bytes,
    encrypt_bytes_to_multiple,
    get_key_cipher_details,
    get_pub_key,
    merge_keys,
    // Parsing
    parse_cert_bytes,
    revoke_uid,
    // Signing
    sign_bytes,
    sign_bytes_cleartext,
    sign_bytes_detached,
    update_password,
    verify_and_extract_bytes,
    // Verification
    verify_bytes,
    verify_bytes_detached,
    // Types
    CipherSuite,
    SubkeyFlags,
};

const TEST_PASSWORD: &str = "test-password-123";
const TEST_UID: &str = "Test User <test@example.com>";

/// Helper to generate a test key with default settings.
fn generate_test_key() -> (Vec<u8>, String) {
    let key = create_key_simple(TEST_PASSWORD, &[TEST_UID]).unwrap();
    // Convert Zeroizing<Vec<u8>> to Vec<u8> for test convenience
    (key.secret_key.to_vec(), key.fingerprint)
}

/// Helper to generate a test key with specific cipher suite.
fn generate_test_key_with_cipher(cipher: CipherSuite) -> (Vec<u8>, String) {
    let key = create_key(
        TEST_PASSWORD,
        &[TEST_UID],
        cipher,
        None,
        None,
        None,
        SubkeyFlags::all(),
        false,
        true,
    )
    .unwrap();
    (key.secret_key.to_vec(), key.fingerprint)
}

// =============================================================================
// Key Generation Tests
// =============================================================================

mod key_generation {
    use super::*;

    #[test]
    fn test_create_key_simple() {
        let key = create_key_simple(TEST_PASSWORD, &[TEST_UID]).unwrap();

        assert!(!key.public_key.is_empty());
        assert!(!key.secret_key.is_empty());
        assert!(!key.fingerprint.is_empty());
        assert_eq!(key.fingerprint.len(), 40); // SHA-1 fingerprint in hex
    }

    #[test]
    fn test_create_key_cv25519() {
        let key = create_key(
            TEST_PASSWORD,
            &[TEST_UID],
            CipherSuite::Cv25519,
            None,
            None,
            None,
            SubkeyFlags::all(),
            false,
            true,
        )
        .unwrap();

        assert!(!key.fingerprint.is_empty());
    }

    #[test]
    #[ignore = "RSA4k key generation is slow (~10s release, ~200s debug)"]
    fn test_create_key_rsa4k() {
        let key = create_key(
            TEST_PASSWORD,
            &[TEST_UID],
            CipherSuite::Rsa4k,
            None,
            None,
            None,
            SubkeyFlags::all(),
            false,
            true,
        )
        .unwrap();

        assert!(!key.fingerprint.is_empty());
    }

    #[test]
    fn test_create_key_multiple_uids() {
        let uids = &["Alice <alice@example.com>", "Alice Work <alice@work.com>"];
        let key = create_key_simple(TEST_PASSWORD, uids).unwrap();

        let info = parse_cert_bytes(&key.secret_key, true).unwrap();
        assert_eq!(info.user_ids.len(), 2);
        assert!(info
            .user_ids
            .iter()
            .any(|u| u.value == "Alice <alice@example.com>"));
        assert!(info
            .user_ids
            .iter()
            .any(|u| u.value == "Alice Work <alice@work.com>"));
    }

    #[test]
    fn test_create_key_encryption_only() {
        let key = create_key(
            TEST_PASSWORD,
            &[TEST_UID],
            CipherSuite::Cv25519,
            None,
            None,
            None,
            SubkeyFlags {
                encryption: true,
                signing: false,
                authentication: false,
            },
            false,
            true,
        )
        .unwrap();

        assert!(!key.fingerprint.is_empty());
    }

    #[test]
    fn test_create_key_empty_uid_fails() {
        let result = create_key_simple(TEST_PASSWORD, &[]);
        assert!(result.is_err());
    }
}

// =============================================================================
// Certificate Parsing Tests
// =============================================================================

mod parsing {
    use super::*;

    #[test]
    fn test_parse_cert_bytes() {
        let (secret_key, fingerprint) = generate_test_key();

        let info = parse_cert_bytes(&secret_key, false).unwrap();

        assert_eq!(info.fingerprint, fingerprint);
        assert!(info.is_secret);
        assert_eq!(info.user_ids.len(), 1);
        assert_eq!(info.user_ids[0].value, TEST_UID);
    }

    #[test]
    fn test_parse_public_key() {
        let (secret_key, _) = generate_test_key();
        let public_key = get_pub_key(&secret_key).unwrap();

        let info = parse_cert_bytes(public_key.as_bytes(), false).unwrap();

        assert!(!info.is_secret);
        assert_eq!(info.user_ids.len(), 1);
    }

    #[test]
    fn test_get_key_cipher_details() {
        let (secret_key, _) = generate_test_key();

        let details = get_key_cipher_details(&secret_key).unwrap();

        // Should have primary key + subkeys
        assert!(!details.is_empty());
        for detail in &details {
            assert!(!detail.fingerprint.is_empty());
            assert!(!detail.algorithm.is_empty());
        }
    }
}

// =============================================================================
// Encryption/Decryption Tests
// =============================================================================

mod encryption {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (secret_key, _) = generate_test_key();
        let public_key = get_pub_key(&secret_key).unwrap();

        let plaintext = b"Hello, World! This is a secret message.";

        // Encrypt
        let ciphertext = encrypt_bytes(public_key.as_bytes(), plaintext, true).unwrap();
        assert!(!ciphertext.is_empty());
        assert_ne!(&ciphertext[..], plaintext);

        // Decrypt
        let decrypted = decrypt_bytes(&secret_key, &ciphertext, TEST_PASSWORD).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_binary() {
        let (secret_key, _) = generate_test_key();
        let public_key = get_pub_key(&secret_key).unwrap();

        let plaintext = b"Binary message";

        // Encrypt without armor
        let ciphertext = encrypt_bytes(public_key.as_bytes(), plaintext, false).unwrap();

        // Should not start with armor header
        assert!(!ciphertext.starts_with(b"-----BEGIN"));

        // Decrypt
        let decrypted = decrypt_bytes(&secret_key, &ciphertext, TEST_PASSWORD).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_to_multiple_recipients() {
        let (secret_key1, _) = generate_test_key();
        let (secret_key2, _) = generate_test_key();

        let public_key1 = get_pub_key(&secret_key1).unwrap();
        let public_key2 = get_pub_key(&secret_key2).unwrap();

        let plaintext = b"Message for multiple recipients";

        // Encrypt to both
        let ciphertext = encrypt_bytes_to_multiple(
            &[public_key1.as_bytes(), public_key2.as_bytes()],
            plaintext,
            true,
        )
        .unwrap();

        // Both should be able to decrypt
        let decrypted1 = decrypt_bytes(&secret_key1, &ciphertext, TEST_PASSWORD).unwrap();
        let decrypted2 = decrypt_bytes(&secret_key2, &ciphertext, TEST_PASSWORD).unwrap();

        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
    }

    #[test]
    fn test_bytes_encrypted_for() {
        let (secret_key, _) = generate_test_key();
        let public_key = get_pub_key(&secret_key).unwrap();

        let plaintext = b"Test message";
        let ciphertext = encrypt_bytes(public_key.as_bytes(), plaintext, false).unwrap();

        let key_ids = bytes_encrypted_for(&ciphertext).unwrap();
        assert!(!key_ids.is_empty());
    }

    #[test]
    fn test_decrypt_wrong_password_fails() {
        let (secret_key, _) = generate_test_key();
        let public_key = get_pub_key(&secret_key).unwrap();

        let plaintext = b"Secret message";
        let ciphertext = encrypt_bytes(public_key.as_bytes(), plaintext, true).unwrap();

        let result = decrypt_bytes(&secret_key, &ciphertext, "wrong-password");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let (secret_key1, _) = generate_test_key();
        let (secret_key2, _) = generate_test_key();

        let public_key1 = get_pub_key(&secret_key1).unwrap();

        let plaintext = b"Secret message";
        let ciphertext = encrypt_bytes(public_key1.as_bytes(), plaintext, true).unwrap();

        // Try to decrypt with wrong key
        let result = decrypt_bytes(&secret_key2, &ciphertext, TEST_PASSWORD);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_rejects_insecure_algorithms() {
        use wecanencrypt::{encrypt_bytes_to_multiple_with_algo, SymmetricKeyAlgorithm};

        let (secret_key, _) = generate_test_key();
        let public_key = get_pub_key(&secret_key).unwrap();

        let plaintext = b"test message";

        // Plaintext (no encryption) must be rejected
        let result = encrypt_bytes_to_multiple_with_algo(
            &[public_key.as_bytes()],
            plaintext,
            true,
            SymmetricKeyAlgorithm::Plaintext,
        );
        assert!(result.is_err());

        // TripleDES must be rejected
        let result = encrypt_bytes_to_multiple_with_algo(
            &[public_key.as_bytes()],
            plaintext,
            true,
            SymmetricKeyAlgorithm::TripleDES,
        );
        assert!(result.is_err());

        // CAST5 must be rejected
        let result = encrypt_bytes_to_multiple_with_algo(
            &[public_key.as_bytes()],
            plaintext,
            true,
            SymmetricKeyAlgorithm::CAST5,
        );
        assert!(result.is_err());

        // IDEA must be rejected
        let result = encrypt_bytes_to_multiple_with_algo(
            &[public_key.as_bytes()],
            plaintext,
            true,
            SymmetricKeyAlgorithm::IDEA,
        );
        assert!(result.is_err());

        // Blowfish must be rejected
        let result = encrypt_bytes_to_multiple_with_algo(
            &[public_key.as_bytes()],
            plaintext,
            true,
            SymmetricKeyAlgorithm::Blowfish,
        );
        assert!(result.is_err());

        // AES-128 must be accepted
        let ciphertext = encrypt_bytes_to_multiple_with_algo(
            &[public_key.as_bytes()],
            plaintext,
            true,
            SymmetricKeyAlgorithm::AES128,
        )
        .unwrap();
        let decrypted = decrypt_bytes(&secret_key, &ciphertext, TEST_PASSWORD).unwrap();
        assert_eq!(decrypted, plaintext);

        // AES-256 must be accepted
        let ciphertext = encrypt_bytes_to_multiple_with_algo(
            &[public_key.as_bytes()],
            plaintext,
            true,
            SymmetricKeyAlgorithm::AES256,
        )
        .unwrap();
        let decrypted = decrypt_bytes(&secret_key, &ciphertext, TEST_PASSWORD).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_large_message() {
        let (secret_key, _) = generate_test_key();
        let public_key = get_pub_key(&secret_key).unwrap();

        // 1MB message
        let plaintext: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();

        let ciphertext = encrypt_bytes(public_key.as_bytes(), &plaintext, false).unwrap();
        let decrypted = decrypt_bytes(&secret_key, &ciphertext, TEST_PASSWORD).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_file_encrypted_for() {
        use tempfile::tempdir;
        use wecanencrypt::{encrypt_file, file_encrypted_for};

        let (secret_key, _) = generate_test_key();
        let public_key = get_pub_key(&secret_key).unwrap();
        let info = parse_cert_bytes(&secret_key, true).unwrap();

        let dir = tempdir().unwrap();
        let encrypted_path = dir.path().join("encrypted.pgp");

        // Encrypt a file
        encrypt_file(public_key.as_bytes(), "Cargo.toml", &encrypted_path, false).unwrap();

        // Check which key IDs the file was encrypted for
        let key_ids = file_encrypted_for(&encrypted_path).unwrap();
        assert!(!key_ids.is_empty());

        // Should contain one of our subkey IDs
        let our_subkey_ids: Vec<String> = info.subkeys.iter().map(|s| s.key_id.clone()).collect();
        assert!(
            key_ids.iter().any(|kid| our_subkey_ids.contains(kid)),
            "Encrypted file should be for one of our subkeys, got {:?}, expected one of {:?}",
            key_ids,
            our_subkey_ids
        );
    }

    #[test]
    fn test_encrypt_reader_to_file_multiple_recipients() {
        use std::io::Cursor;
        use tempfile::tempdir;
        use wecanencrypt::encrypt_reader_to_file;

        let key1 = create_key_simple(TEST_PASSWORD, &["Reader1 <r1@example.com>"]).unwrap();
        let key2 = create_key_simple(TEST_PASSWORD, &["Reader2 <r2@example.com>"]).unwrap();
        let pub1 = get_pub_key(&key1.secret_key).unwrap();
        let pub2 = get_pub_key(&key2.secret_key).unwrap();

        let dir = tempdir().unwrap();
        let encrypted_path = dir.path().join("encrypted.pgp");

        let plaintext = b"Multi-recipient reader encryption";
        let reader = Cursor::new(plaintext);

        encrypt_reader_to_file(
            &[pub1.as_bytes(), pub2.as_bytes()],
            reader,
            &encrypted_path,
            false,
        )
        .unwrap();

        // Both recipients should be able to decrypt
        let ciphertext = std::fs::read(&encrypted_path).unwrap();
        let decrypted1 = decrypt_bytes(&key1.secret_key, &ciphertext, TEST_PASSWORD).unwrap();
        let decrypted2 = decrypt_bytes(&key2.secret_key, &ciphertext, TEST_PASSWORD).unwrap();
        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
    }
}

// =============================================================================
// Signing/Verification Tests
// =============================================================================

mod signing {
    use super::*;

    #[test]
    fn test_sign_verify_roundtrip() {
        let (secret_key, _) = generate_test_key();
        let public_key = get_pub_key(&secret_key).unwrap();

        let message = b"This message will be signed.";

        // Sign
        let signed = sign_bytes(&secret_key, message, TEST_PASSWORD).unwrap();
        assert!(!signed.is_empty());

        // Verify
        let valid = verify_bytes(public_key.as_bytes(), &signed).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_sign_verify_and_extract() {
        let (secret_key, _) = generate_test_key();
        let public_key = get_pub_key(&secret_key).unwrap();

        let message = b"Extract this message after verification.";

        let signed = sign_bytes(&secret_key, message, TEST_PASSWORD).unwrap();

        let extracted = verify_and_extract_bytes(public_key.as_bytes(), &signed).unwrap();
        assert_eq!(extracted, message);
    }

    #[test]
    fn test_sign_cleartext() {
        let (secret_key, _) = generate_test_key();
        let public_key = get_pub_key(&secret_key).unwrap();

        let message = b"Cleartext signed message";

        let signed = sign_bytes_cleartext(&secret_key, message, TEST_PASSWORD).unwrap();

        // Cleartext signature should contain the original message
        let signed_str = String::from_utf8_lossy(&signed);
        assert!(signed_str.contains("-----BEGIN PGP SIGNED MESSAGE-----"));

        // Verify
        let valid = verify_bytes(public_key.as_bytes(), &signed).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_sign_detached() {
        let (secret_key, _) = generate_test_key();
        let public_key = get_pub_key(&secret_key).unwrap();

        let message = b"Message with detached signature";

        let signature = sign_bytes_detached(&secret_key, message, TEST_PASSWORD).unwrap();

        // Should be armored signature
        assert!(signature.contains("-----BEGIN PGP SIGNATURE-----"));

        // Verify detached
        let valid =
            verify_bytes_detached(public_key.as_bytes(), message, signature.as_bytes()).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_verify_wrong_key_fails() {
        let (secret_key1, _) = generate_test_key();
        let (secret_key2, _) = generate_test_key();

        let public_key2 = get_pub_key(&secret_key2).unwrap();

        let message = b"Signed message";
        let signed = sign_bytes(&secret_key1, message, TEST_PASSWORD).unwrap();

        // Verify with wrong key should return false
        let valid = verify_bytes(public_key2.as_bytes(), &signed).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_verify_detached_tampered_message_fails() {
        let (secret_key, _) = generate_test_key();
        let public_key = get_pub_key(&secret_key).unwrap();

        let message = b"Original message";
        let signature = sign_bytes_detached(&secret_key, message, TEST_PASSWORD).unwrap();

        // Verify with tampered message
        let tampered = b"Tampered message";
        let valid =
            verify_bytes_detached(public_key.as_bytes(), tampered, signature.as_bytes()).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_sign_wrong_password_fails() {
        let (secret_key, _) = generate_test_key();
        let message = b"Message";

        let result = sign_bytes(&secret_key, message, "wrong-password");
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_with_primary_key_variants() {
        use wecanencrypt::{
            sign_bytes_cleartext_with_primary_key, sign_bytes_detached_with_primary_key,
            sign_bytes_with_primary_key,
        };

        let (secret_key, _) = generate_test_key();
        let public_key = get_pub_key(&secret_key).unwrap();
        let message = b"Test primary key signing";

        // Binary signature with primary key
        let signed = sign_bytes_with_primary_key(&secret_key, message, TEST_PASSWORD).unwrap();
        let valid = verify_bytes(public_key.as_bytes(), &signed).unwrap();
        assert!(valid);

        // Cleartext signature with primary key
        let signed =
            sign_bytes_cleartext_with_primary_key(&secret_key, message, TEST_PASSWORD).unwrap();
        let valid = verify_bytes(public_key.as_bytes(), &signed).unwrap();
        assert!(valid);

        // Detached signature with primary key
        let signature =
            sign_bytes_detached_with_primary_key(&secret_key, message, TEST_PASSWORD).unwrap();
        let valid =
            verify_bytes_detached(public_key.as_bytes(), message, signature.as_bytes()).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_sign_prefers_signing_subkey() {
        // Generate a key with all subkeys (including a signing subkey)
        let key = create_key(
            TEST_PASSWORD,
            &[TEST_UID],
            CipherSuite::Cv25519,
            None,
            None,
            None,
            SubkeyFlags::all(),
            false, // primary cannot sign
            true,
        )
        .unwrap();
        let public_key = get_pub_key(&key.secret_key).unwrap();

        // The default sign_bytes should use the signing subkey and still verify
        let message = b"Signed by subkey";
        let signed = sign_bytes(&key.secret_key, message, TEST_PASSWORD).unwrap();
        let valid = verify_bytes(public_key.as_bytes(), &signed).unwrap();
        assert!(valid);

        // Detached too
        let sig = sign_bytes_detached(&key.secret_key, message, TEST_PASSWORD).unwrap();
        let valid = verify_bytes_detached(public_key.as_bytes(), message, sig.as_bytes()).unwrap();
        assert!(valid);

        // Cleartext too
        let signed = sign_bytes_cleartext(&key.secret_key, message, TEST_PASSWORD).unwrap();
        let valid = verify_bytes(public_key.as_bytes(), &signed).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_sign_fails_for_certify_only_key_without_signing_subkey() {
        // Key where primary CANNOT sign and has no signing subkey (encryption only)
        let key = create_key(
            TEST_PASSWORD,
            &[TEST_UID],
            CipherSuite::Cv25519,
            None,
            None,
            None,
            SubkeyFlags::encryption_only(),
            false, // primary cannot sign
            true,
        )
        .unwrap();

        let message = b"Should fail to sign";

        // All signing functions should return NoSigningSubkey
        let result = sign_bytes(&key.secret_key, message, TEST_PASSWORD);
        assert!(
            matches!(result, Err(wecanencrypt::Error::NoSigningSubkey)),
            "sign_bytes should fail with NoSigningSubkey, got {:?}",
            result
        );

        let result = sign_bytes_detached(&key.secret_key, message, TEST_PASSWORD);
        assert!(
            matches!(result, Err(wecanencrypt::Error::NoSigningSubkey)),
            "sign_bytes_detached should fail with NoSigningSubkey, got {:?}",
            result
        );

        let result = sign_bytes_cleartext(&key.secret_key, message, TEST_PASSWORD);
        assert!(
            matches!(result, Err(wecanencrypt::Error::NoSigningSubkey)),
            "sign_bytes_cleartext should fail with NoSigningSubkey, got {:?}",
            result
        );
    }

    #[test]
    fn test_sign_primary_vs_subkey_produces_different_signatures() {
        use wecanencrypt::sign_bytes_detached_with_primary_key;

        // Key where primary CAN sign and also has a signing subkey
        let key = create_key(
            TEST_PASSWORD,
            &[TEST_UID],
            CipherSuite::Cv25519,
            None,
            None,
            None,
            SubkeyFlags::all(),
            true, // primary can sign
            true,
        )
        .unwrap();
        let public_key = get_pub_key(&key.secret_key).unwrap();

        let message = b"Compare signatures";

        // Default: uses signing subkey
        let sig_subkey = sign_bytes_detached(&key.secret_key, message, TEST_PASSWORD).unwrap();
        // Forced: uses primary key
        let sig_primary =
            sign_bytes_detached_with_primary_key(&key.secret_key, message, TEST_PASSWORD).unwrap();

        // Both must verify
        let valid =
            verify_bytes_detached(public_key.as_bytes(), message, sig_subkey.as_bytes()).unwrap();
        assert!(valid, "subkey signature should verify");
        let valid =
            verify_bytes_detached(public_key.as_bytes(), message, sig_primary.as_bytes()).unwrap();
        assert!(valid, "primary key signature should verify");

        // The signatures should differ (different issuer keys)
        assert_ne!(sig_subkey, sig_primary);
    }
}

// =============================================================================
// Key Management Tests
// =============================================================================

mod key_management {
    use super::*;

    #[test]
    fn test_add_uid() {
        let (secret_key, _) = generate_test_key();

        let new_uid = "New Identity <new@example.com>";
        let updated_key = add_uid(&secret_key, new_uid, TEST_PASSWORD).unwrap();

        let info = parse_cert_bytes(&updated_key, true).unwrap();
        assert_eq!(info.user_ids.len(), 2);
        assert!(info.user_ids.iter().any(|u| u.value == new_uid));
    }

    #[test]
    fn test_revoke_uid() {
        // Create key with multiple UIDs
        let key = create_key_simple(
            TEST_PASSWORD,
            &[
                "Primary <primary@example.com>",
                "Secondary <secondary@example.com>",
            ],
        )
        .unwrap();

        let updated_key = revoke_uid(
            &key.secret_key,
            "Secondary <secondary@example.com>",
            TEST_PASSWORD,
        )
        .unwrap();

        // Key should still parse (revoked UID is still present but marked as revoked)
        let info = parse_cert_bytes(&updated_key, true).unwrap();
        assert!(!info.user_ids.is_empty());
    }

    #[test]
    fn test_update_password() {
        let (secret_key, _) = generate_test_key();
        let public_key = get_pub_key(&secret_key).unwrap();

        let new_password = "new-password-456";

        // Update password
        let updated_key = update_password(&secret_key, TEST_PASSWORD, new_password).unwrap();

        // Encrypt a message
        let message = b"Test message";
        let ciphertext = encrypt_bytes(public_key.as_bytes(), message, true).unwrap();

        // Old password should fail
        let result = decrypt_bytes(&updated_key, &ciphertext, TEST_PASSWORD);
        assert!(result.is_err());

        // New password should work
        let decrypted = decrypt_bytes(&updated_key, &ciphertext, new_password).unwrap();
        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_add_uid_fails_for_public_key() {
        let (secret_key, _) = generate_test_key();
        let public_key = get_pub_key(&secret_key).unwrap();

        // Adding UID to a public-only key should fail
        let result = add_uid(
            public_key.as_bytes(),
            "New <new@example.com>",
            TEST_PASSWORD,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_get_pub_key() {
        let (secret_key, fingerprint) = generate_test_key();

        let public_key = get_pub_key(&secret_key).unwrap();

        // Should be armored
        assert!(public_key.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----"));

        // Should parse and have same fingerprint
        let info = parse_cert_bytes(public_key.as_bytes(), false).unwrap();
        assert_eq!(info.fingerprint, fingerprint);
        assert!(!info.is_secret);
    }
}

// =============================================================================
// Cross-cipher Tests
// =============================================================================

mod cross_cipher {
    use super::*;

    #[test]
    fn test_cv25519_encrypt_decrypt() {
        let (secret_key, _) = generate_test_key_with_cipher(CipherSuite::Cv25519);
        let public_key = get_pub_key(&secret_key).unwrap();

        let message = b"Cv25519 encrypted message";
        let ciphertext = encrypt_bytes(public_key.as_bytes(), message, true).unwrap();
        let decrypted = decrypt_bytes(&secret_key, &ciphertext, TEST_PASSWORD).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_rsa4k_encrypt_decrypt() {
        // Use fixture keys instead of generating (RSA4k generation is slow)
        let store = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/files/store");
        let public_key = std::fs::read(store.join("rsa4k_public.asc")).unwrap();
        let secret_key = std::fs::read(store.join("rsa4k_secret.asc")).unwrap();

        let message = b"RSA4k encrypted message";
        let ciphertext = encrypt_bytes(&public_key, message, true).unwrap();
        let decrypted = decrypt_bytes(&secret_key, &ciphertext, "testpassword").unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_cv25519_sign_verify() {
        let (secret_key, _) = generate_test_key_with_cipher(CipherSuite::Cv25519);
        let public_key = get_pub_key(&secret_key).unwrap();

        let message = b"Cv25519 signed message";
        let signed = sign_bytes(&secret_key, message, TEST_PASSWORD).unwrap();
        let valid = verify_bytes(public_key.as_bytes(), &signed).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_rsa4k_sign_verify() {
        // Use fixture keys instead of generating (RSA4k generation is slow)
        let store = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/files/store");
        let public_key = std::fs::read(store.join("rsa4k_public.asc")).unwrap();
        let secret_key = std::fs::read(store.join("rsa4k_secret.asc")).unwrap();

        let message = b"RSA4k signed message";
        let signed = sign_bytes(&secret_key, message, "testpassword").unwrap();
        let valid = verify_bytes(&public_key, &signed).unwrap();

        assert!(valid);
    }
}

// =============================================================================
// Reader-Based Encryption/Decryption
// =============================================================================

mod reader_encryption {
    use std::io::Cursor;
    use tempfile::tempdir;
    use wecanencrypt::{
        create_key_simple, decrypt_reader_to_file, encrypt_reader_to_file, get_pub_key,
    };

    const TEST_PASSWORD: &str = "test-password-123";

    /// Port of JCE test_encrypt_decrypt.py::test_encryption_of_multiple_keys_of_a_filehandler
    #[test]
    fn test_encrypt_decrypt_reader_to_file() {
        let dir = tempdir().unwrap();
        let encrypted_path = dir.path().join("encrypted.pgp");
        let decrypted_path = dir.path().join("decrypted.txt");

        // Create a key
        let key = create_key_simple(TEST_PASSWORD, &["Reader Test <reader@example.com>"]).unwrap();
        let public_key = get_pub_key(&key.secret_key).unwrap();

        let plaintext = b"Hello from reader-based encryption!";

        // Encrypt from a reader (Cursor simulates a file handle)
        let reader = Cursor::new(plaintext);
        encrypt_reader_to_file(&[public_key.as_bytes()], reader, &encrypted_path, false).unwrap();

        // Verify encrypted file exists
        assert!(encrypted_path.exists());

        // Decrypt from reader to file
        let encrypted_data = std::fs::read(&encrypted_path).unwrap();
        let encrypted_reader = Cursor::new(encrypted_data);
        decrypt_reader_to_file(
            &key.secret_key,
            encrypted_reader,
            &decrypted_path,
            TEST_PASSWORD,
        )
        .unwrap();

        // Verify content matches
        let decrypted = std::fs::read(&decrypted_path).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}

// =============================================================================
// Key Flag Policy Tests (RFC 4880 §5.2.3.3 "latest self-signature wins")
// =============================================================================

mod key_flag_policy {
    use super::*;
    use wecanencrypt::pgp::composed::{SignedKeyDetails, SignedSecretKey};
    use wecanencrypt::pgp::packet::{
        KeyFlags, PacketTrait, SignatureConfig, SignatureType, Subpacket, SubpacketData,
    };
    use wecanencrypt::pgp::ser::Serialize;
    use wecanencrypt::pgp::types::{KeyDetails, KeyVersion, Password, SignedUser, Timestamp};

    /// Helper: parse a secret key from bytes.
    fn parse_secret(data: &[u8]) -> SignedSecretKey {
        use std::io::Cursor;
        use wecanencrypt::pgp::composed::Deserializable;
        match SignedSecretKey::from_armor_single(Cursor::new(data)) {
            Ok((key, _)) => key,
            Err(_) => SignedSecretKey::from_bytes(data).unwrap(),
        }
    }

    /// Helper: create a new self-signature on a UID with specific key flags,
    /// re-sign, and rebuild the cert. Returns the updated secret key bytes.
    pub(super) fn resign_uid_with_flags(
        secret_data: &[u8],
        password: &str,
        sign_flag: bool,
        certify_flag: bool,
    ) -> Vec<u8> {
        let secret_key = parse_secret(secret_data);
        let password_obj: Password = password.into();
        let mut rng = rand::thread_rng();

        let mut new_users = Vec::new();
        for signed_user in &secret_key.details.users {
            // Build key flags
            let mut flags = KeyFlags::default();
            flags.set_certify(certify_flag);
            flags.set_sign(sign_flag);

            // Build subpackets — use a creation time slightly in the future to
            // ensure this self-sig is "newer" than the original one.
            let hashed_subpackets = vec![
                Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now())).unwrap(),
                Subpacket::regular(SubpacketData::IssuerFingerprint(
                    secret_key.primary_key.fingerprint(),
                ))
                .unwrap(),
                Subpacket::regular(SubpacketData::KeyFlags(flags)).unwrap(),
            ];

            let mut config = SignatureConfig::from_key(
                &mut rng,
                &secret_key.primary_key,
                SignatureType::CertPositive,
            )
            .unwrap();
            config.hashed_subpackets = hashed_subpackets;

            if secret_key.primary_key.version() <= KeyVersion::V4 {
                config.unhashed_subpackets =
                    vec![Subpacket::regular(SubpacketData::IssuerKeyId(
                        secret_key.primary_key.legacy_key_id(),
                    ))
                    .unwrap()];
            }

            let sig = config
                .sign_certification(
                    &secret_key.primary_key,
                    &secret_key.primary_key.public_key(),
                    &password_obj,
                    signed_user.id.tag(),
                    &signed_user.id,
                )
                .unwrap();

            // Keep ALL existing signatures (including old self-sigs) + add new one.
            // This simulates accumulation after a merge — multiple self-sigs coexist.
            let mut combined_sigs = signed_user.signatures.clone();
            combined_sigs.push(sig);
            new_users.push(SignedUser::new(signed_user.id.clone(), combined_sigs));
        }

        let updated = SignedSecretKey::new(
            secret_key.primary_key.clone(),
            SignedKeyDetails::new(
                secret_key.details.revocation_signatures.clone(),
                secret_key.details.direct_signatures.clone(),
                new_users,
                secret_key.details.user_attributes.clone(),
            ),
            secret_key.public_subkeys.clone(),
            secret_key.secret_subkeys.clone(),
        );

        updated.to_bytes().unwrap()
    }

    #[test]
    fn test_latest_self_sig_wins_for_sign_flag() {
        // Generate a key WITH primary signing capability.
        let key = create_key(
            TEST_PASSWORD,
            &[TEST_UID],
            CipherSuite::Cv25519,
            None,
            None,
            None,
            SubkeyFlags::all(),
            true, // can_primary_sign = true
            true,
        )
        .unwrap();

        let info = parse_cert_bytes(&key.secret_key, true).unwrap();
        assert!(
            info.can_primary_sign,
            "Original key should have primary sign capability"
        );

        // Create a newer self-sig that REMOVES the sign flag (certify-only).
        let updated = resign_uid_with_flags(&key.secret_key, TEST_PASSWORD, false, true);

        let info2 = parse_cert_bytes(&updated, true).unwrap();
        assert!(
            !info2.can_primary_sign,
            "After adding newer self-sig without sign flag, can_primary_sign should be false"
        );
    }

    #[test]
    fn test_latest_self_sig_wins_adding_sign_flag() {
        // Generate a key WITHOUT primary signing capability.
        let key = create_key(
            TEST_PASSWORD,
            &[TEST_UID],
            CipherSuite::Cv25519,
            None,
            None,
            None,
            SubkeyFlags::all(),
            false, // can_primary_sign = false
            true,
        )
        .unwrap();

        let info = parse_cert_bytes(&key.secret_key, true).unwrap();
        assert!(
            !info.can_primary_sign,
            "Original key should NOT have primary sign capability"
        );

        // Create a newer self-sig that ADDS the sign flag.
        let updated = resign_uid_with_flags(&key.secret_key, TEST_PASSWORD, true, true);

        let info2 = parse_cert_bytes(&updated, true).unwrap();
        assert!(
            info2.can_primary_sign,
            "After adding newer self-sig with sign flag, can_primary_sign should be true"
        );
    }

    #[test]
    fn test_merge_preserves_latest_self_sig_flags() {
        // Generate a key with sign capability.
        let key = create_key(
            TEST_PASSWORD,
            &[TEST_UID],
            CipherSuite::Cv25519,
            None,
            None,
            None,
            SubkeyFlags::all(),
            true, // can_primary_sign = true
            true,
        )
        .unwrap();

        // Create an "updated" version that removes sign flag.
        let updated = resign_uid_with_flags(&key.secret_key, TEST_PASSWORD, false, true);

        // Extract public keys for merge.
        let pub_orig = get_pub_key(&key.secret_key).unwrap();
        let pub_updated = get_pub_key(&updated).unwrap();

        // Merge: original + updated. The updated cert has a newer self-sig
        // without the sign flag.
        let merged = merge_keys(pub_orig.as_bytes(), pub_updated.as_bytes()).unwrap();

        let info = parse_cert_bytes(&merged, false).unwrap();
        assert!(
            !info.can_primary_sign,
            "After merging cert with newer self-sig removing sign flag, can_primary_sign should be false"
        );
    }

    #[test]
    fn test_merge_older_self_sig_does_not_override_newer() {
        // Generate a key WITHOUT sign capability.
        let key_no_sign = create_key(
            TEST_PASSWORD,
            &[TEST_UID],
            CipherSuite::Cv25519,
            None,
            None,
            None,
            SubkeyFlags::all(),
            false, // can_primary_sign = false
            true,
        )
        .unwrap();

        // Create a newer version that ADDS sign capability.
        let key_with_sign =
            resign_uid_with_flags(&key_no_sign.secret_key, TEST_PASSWORD, true, true);

        let pub_with_sign = get_pub_key(&key_with_sign).unwrap();
        let pub_no_sign = get_pub_key(&key_no_sign.secret_key).unwrap();

        // Merge: start from cert WITH sign flag, merge in the OLDER cert without it.
        // The older self-sig should NOT override the newer one.
        let merged = merge_keys(pub_with_sign.as_bytes(), pub_no_sign.as_bytes()).unwrap();

        let info = parse_cert_bytes(&merged, false).unwrap();
        assert!(
            info.can_primary_sign,
            "Merging in older self-sig without sign flag should not override newer self-sig that has it"
        );
    }

    #[test]
    fn test_certify_only_key_remains_certify_only_after_accumulation() {
        // Generate a certify-only key (no primary sign).
        let key = create_key(
            TEST_PASSWORD,
            &[TEST_UID],
            CipherSuite::Cv25519,
            None,
            None,
            None,
            SubkeyFlags::all(),
            false, // certify only
            true,
        )
        .unwrap();

        let info = parse_cert_bytes(&key.secret_key, true).unwrap();
        assert!(
            !info.can_primary_sign,
            "Certify-only key should not have sign capability"
        );

        // Update the expiry — this creates a new self-sig that copies flags
        // from the existing sig (should preserve certify-only).
        let exp = chrono::Utc::now() + chrono::Duration::days(365);
        let updated =
            wecanencrypt::update_primary_expiry(&key.secret_key, exp, TEST_PASSWORD).unwrap();

        let info2 = parse_cert_bytes(&updated, true).unwrap();
        assert!(
            !info2.can_primary_sign,
            "After expiry update, certify-only key should still not have sign capability"
        );
    }
}

// =============================================================================
// merge_keys dispatch matrix: covers all combinations of public/secret inputs,
// plus the FP-mismatch error path.
// =============================================================================

mod merge_secret_dispatch {
    use super::*;
    use pgp::composed::{Deserializable, SignedPublicKey, SignedSecretKey};
    use pgp::ser::Serialize;
    use pgp::types::KeyDetails;
    use std::io::Cursor;

    fn fresh_key() -> wecanencrypt::GeneratedKey {
        create_key_simple(TEST_PASSWORD, &[TEST_UID]).unwrap()
    }

    fn parse_pub(data: &[u8]) -> SignedPublicKey {
        SignedPublicKey::from_armor_single(Cursor::new(data))
            .map(|(k, _)| k)
            .or_else(|_| SignedPublicKey::from_bytes(Cursor::new(data)))
            .expect("parse as public")
    }

    fn parse_sec(data: &[u8]) -> SignedSecretKey {
        SignedSecretKey::from_armor_single(Cursor::new(data))
            .map(|(k, _)| k)
            .or_else(|_| SignedSecretKey::from_bytes(Cursor::new(data)))
            .expect("parse as secret")
    }

    #[test]
    fn test_merge_public_public_unchanged() {
        // pub + pub should still produce a public cert (regression).
        let key = fresh_key();
        let pub_bytes = key.public_key.as_bytes();
        let merged = merge_keys(pub_bytes, pub_bytes).unwrap();

        // Must NOT parse as a secret key.
        assert!(SignedSecretKey::from_bytes(Cursor::new(&*merged)).is_err());
        // Must parse as a public key.
        let _pub = parse_pub(&merged);

        let info = parse_cert_bytes(&merged, false).unwrap();
        assert!(!info.is_secret);
        assert_eq!(info.fingerprint, key.fingerprint);
    }

    #[test]
    fn test_merge_public_plus_secret_upgrades() {
        // pub + sec → result carries secret material (upgrade path).
        let key = fresh_key();
        let pub_bytes = key.public_key.as_bytes();
        let merged = merge_keys(pub_bytes, &key.secret_key).unwrap();

        let info = parse_cert_bytes(&merged, true).unwrap();
        assert!(info.is_secret, "pub + sec merge should produce a secret cert");
        assert_eq!(info.fingerprint, key.fingerprint);

        // The serialized bytes must parse back as a secret key.
        let _sec = parse_sec(&merged);
    }

    #[test]
    fn test_merge_secret_plus_secret_preserves() {
        // sec + sec merges signatures; result remains secret.
        let key = fresh_key();
        let orig_secret = key.secret_key.to_vec();

        // Produce a modified secret (newer self-sig on the UID).
        let updated_secret =
            key_flag_policy::resign_uid_with_flags(&orig_secret, TEST_PASSWORD, true, true);

        let merged = merge_keys(&orig_secret, &updated_secret).unwrap();

        let info = parse_cert_bytes(&merged, true).unwrap();
        assert!(info.is_secret, "sec + sec merge should produce a secret cert");
        assert_eq!(info.fingerprint, key.fingerprint);

        // The new self-sig from the update should have been merged in —
        // the merged cert should have at least 2 self-signatures on the
        // UID (original + updated).
        let merged_sec = parse_sec(&merged);
        let sig_count: usize = merged_sec
            .details
            .users
            .iter()
            .map(|u| u.signatures.len())
            .sum();
        assert!(
            sig_count >= 2,
            "expected merged UID signatures from both inputs, got {}",
            sig_count
        );
    }

    #[test]
    fn test_merge_secret_plus_public_preserves_secret() {
        // Key-signing workflow: secret base + public update (e.g.
        // third-party certification on our UID). Secret material must
        // survive.
        let key = fresh_key();
        let secret_bytes = key.secret_key.to_vec();

        // Produce a public update derived from the same key but with a
        // fresh newer self-sig on the UID (stand-in for "someone
        // returned an updated public cert").
        let updated_secret =
            key_flag_policy::resign_uid_with_flags(&secret_bytes, TEST_PASSWORD, true, true);
        let updated_pub = get_pub_key(&updated_secret).unwrap();

        let merged = merge_keys(&secret_bytes, updated_pub.as_bytes()).unwrap();

        let info = parse_cert_bytes(&merged, true).unwrap();
        assert!(
            info.is_secret,
            "sec + pub merge must preserve secret material"
        );
        assert_eq!(info.fingerprint, key.fingerprint);

        // Round-trip must still parse as a secret key with secret
        // subkey material intact.
        let merged_sec = parse_sec(&merged);
        assert!(
            !merged_sec.secret_subkeys.is_empty(),
            "secret subkeys must be preserved across sec + pub merge"
        );

        // And the new self-sig from the update should have been merged
        // into the UID's signatures.
        let sig_count: usize = merged_sec
            .details
            .users
            .iter()
            .map(|u| u.signatures.len())
            .sum();
        assert!(
            sig_count >= 2,
            "expected merged UID signatures, got {}",
            sig_count
        );
    }

    #[test]
    fn test_merge_secret_subkey_packets_preserved() {
        // Parse the fresh secret and count secret subkeys up front.
        let key = fresh_key();
        let secret_bytes = key.secret_key.to_vec();
        let orig_sec = parse_sec(&secret_bytes);
        let expected_sec_subkeys: Vec<_> = orig_sec
            .secret_subkeys
            .iter()
            .map(|sk| fingerprint_hex(&sk.key.fingerprint()))
            .collect();
        assert!(
            !expected_sec_subkeys.is_empty(),
            "test precondition: fresh key should have secret subkeys"
        );

        // Public update: the public view of the same cert. Under the
        // hood merge_keys should route each public subkey signature
        // into the matching secret subkey, never overwriting the
        // secret packet with a public one.
        let pub_update = key.public_key.clone();
        let merged = merge_keys(&secret_bytes, pub_update.as_bytes()).unwrap();

        let merged_sec = parse_sec(&merged);
        let got_sec_subkeys: Vec<_> = merged_sec
            .secret_subkeys
            .iter()
            .map(|sk| fingerprint_hex(&sk.key.fingerprint()))
            .collect();

        for fp in &expected_sec_subkeys {
            assert!(
                got_sec_subkeys.contains(fp),
                "secret subkey {} was dropped during merge",
                fp
            );
        }
    }

    #[test]
    fn test_merge_fingerprint_mismatch_errors() {
        // Two distinct keys → merge must refuse.
        let a = fresh_key();
        let b = fresh_key();
        assert_ne!(a.fingerprint, b.fingerprint);

        let err = merge_keys(a.public_key.as_bytes(), b.public_key.as_bytes())
            .expect_err("merge with different FPs must error");
        let msg = err.to_string();
        assert!(
            msg.contains("fingerprint") || msg.contains("Fingerprint"),
            "unexpected error: {}",
            msg
        );
    }

    #[test]
    fn test_merge_absorbs_new_valid_secret_subkey() {
        // Build a "smaller" base cert from a fresh key by dropping one
        // of its secret subkeys, then merge the full key back in.
        // The dropped (but primary-bound) subkey should be re-absorbed
        // through the new-secret-subkey branch in merge_secret_cert.
        let key = fresh_key();
        let full_sec = parse_sec(&key.secret_key);
        assert!(
            full_sec.secret_subkeys.len() >= 2,
            "test precondition: fresh key should have multiple secret subkeys"
        );

        let dropped_fp = fingerprint_hex(&full_sec.secret_subkeys[1].key.fingerprint());
        let smaller = SignedSecretKey::new(
            full_sec.primary_key.clone(),
            full_sec.details.clone(),
            full_sec.public_subkeys.clone(),
            full_sec.secret_subkeys[..1].to_vec(),
        );
        let smaller_bytes = smaller.to_bytes().unwrap();

        let merged = merge_keys(&smaller_bytes, &key.secret_key).unwrap();
        let merged_sec = parse_sec(&merged);

        let got: Vec<_> = merged_sec
            .secret_subkeys
            .iter()
            .map(|sk| fingerprint_hex(&sk.key.fingerprint()))
            .collect();
        assert!(
            got.contains(&dropped_fp),
            "expected re-absorbed secret subkey {} in {:?}",
            dropped_fp,
            got
        );
    }

    #[test]
    fn test_merge_rejects_tampered_secret_subkey_binding() {
        // Attack: craft an update that advertises A's primary but
        // smuggles a secret subkey whose binding signature was made by
        // a *different* primary (key B). merge_keys must refuse that
        // subkey — otherwise anyone who can get a victim to import
        // their "updated" secret cert can inject an arbitrary subkey.
        let key_a = fresh_key();
        let key_b = fresh_key();

        let sec_a = parse_sec(&key_a.secret_key);
        let sec_b = parse_sec(&key_b.secret_key);

        let stolen_subkey = sec_b.secret_subkeys[0].clone();
        let stolen_fp = fingerprint_hex(&stolen_subkey.key.fingerprint());

        let mut tampered_sec_subkeys = sec_a.secret_subkeys.clone();
        tampered_sec_subkeys.push(stolen_subkey);
        let tampered = SignedSecretKey::new(
            sec_a.primary_key.clone(),
            sec_a.details.clone(),
            sec_a.public_subkeys.clone(),
            tampered_sec_subkeys,
        );
        let tampered_bytes = tampered.to_bytes().unwrap();

        // Primary FP matches (both claim to be A), so FP check passes
        // and merge enters the sec + sec dispatch.
        let merged = merge_keys(&key_a.secret_key, &tampered_bytes).unwrap();
        let merged_sec = parse_sec(&merged);

        let got_sec_fps: Vec<_> = merged_sec
            .secret_subkeys
            .iter()
            .map(|sk| fingerprint_hex(&sk.key.fingerprint()))
            .collect();
        assert!(
            !got_sec_fps.contains(&stolen_fp),
            "stolen subkey {} leaked into merged cert (got {:?})",
            stolen_fp,
            got_sec_fps
        );

        // Key A's legitimate subkeys must still be present.
        for leg_sk in &sec_a.secret_subkeys {
            let fp = fingerprint_hex(&leg_sk.key.fingerprint());
            assert!(
                got_sec_fps.contains(&fp),
                "legitimate subkey {} dropped by merge",
                fp
            );
        }
    }

    fn fingerprint_hex(fp: &pgp::types::Fingerprint) -> String {
        hex::encode_upper(fp.as_bytes())
    }
}
