//! Integration tests for wecanencrypt library.
//!
//! These tests verify the full functionality of the library including
//! key generation, encryption, decryption, signing, and verification.

use wecanencrypt::{
    // Key generation
    create_key, create_key_simple,
    // Encryption
    encrypt_bytes, encrypt_bytes_to_multiple, bytes_encrypted_for,
    // Decryption
    decrypt_bytes,
    // Signing
    sign_bytes, sign_bytes_cleartext, sign_bytes_detached,
    // Verification
    verify_bytes, verify_and_extract_bytes, verify_bytes_detached,
    // Parsing
    parse_cert_bytes, get_key_cipher_details,
    // Key management
    add_uid, revoke_uid, update_password, get_pub_key,
    // Types
    CipherSuite, SubkeyFlags,
};

const TEST_PASSWORD: &str = "test-password-123";
const TEST_UID: &str = "Test User <test@example.com>";

/// Helper to generate a test key with default settings.
fn generate_test_key() -> (Vec<u8>, String) {
    let key = create_key_simple(TEST_PASSWORD, &[TEST_UID]).unwrap();
    (key.secret_key, key.fingerprint)
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
    (key.secret_key, key.fingerprint)
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
        assert!(info.user_ids.contains(&"Alice <alice@example.com>".to_string()));
        assert!(info.user_ids.contains(&"Alice Work <alice@work.com>".to_string()));
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
        assert_eq!(info.user_ids[0], TEST_UID);
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
    fn test_encrypt_large_message() {
        let (secret_key, _) = generate_test_key();
        let public_key = get_pub_key(&secret_key).unwrap();

        // 1MB message
        let plaintext: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();

        let ciphertext = encrypt_bytes(public_key.as_bytes(), &plaintext, false).unwrap();
        let decrypted = decrypt_bytes(&secret_key, &ciphertext, TEST_PASSWORD).unwrap();

        assert_eq!(decrypted, plaintext);
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
        assert!(info.user_ids.contains(&new_uid.to_string()));
    }

    #[test]
    fn test_revoke_uid() {
        // Create key with multiple UIDs
        let key = create_key_simple(
            TEST_PASSWORD,
            &["Primary <primary@example.com>", "Secondary <secondary@example.com>"],
        )
        .unwrap();

        let updated_key =
            revoke_uid(&key.secret_key, "Secondary <secondary@example.com>", TEST_PASSWORD)
                .unwrap();

        // Key should still parse (revoked UID is still present but marked as revoked)
        let info = parse_cert_bytes(&updated_key, true).unwrap();
        assert!(info.user_ids.len() >= 1);
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
        let store = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/files/store");
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
        let store = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/files/store");
        let public_key = std::fs::read(store.join("rsa4k_public.asc")).unwrap();
        let secret_key = std::fs::read(store.join("rsa4k_secret.asc")).unwrap();

        let message = b"RSA4k signed message";
        let signed = sign_bytes(&secret_key, message, "testpassword").unwrap();
        let valid = verify_bytes(&public_key, &signed).unwrap();

        assert!(valid);
    }
}
