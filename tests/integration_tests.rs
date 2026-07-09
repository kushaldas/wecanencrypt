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
    parse_key_bytes,
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

        let info = parse_key_bytes(&key.secret_key, true).unwrap();
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
    fn test_parse_key_bytes() {
        let (secret_key, fingerprint) = generate_test_key();

        let info = parse_key_bytes(&secret_key, false).unwrap();

        assert_eq!(info.fingerprint, fingerprint);
        assert!(info.is_secret);
        assert_eq!(info.user_ids.len(), 1);
        assert_eq!(info.user_ids[0].value, TEST_UID);
    }

    #[test]
    fn test_parse_public_key() {
        let (secret_key, _) = generate_test_key();
        let public_key = get_pub_key(&secret_key).unwrap();

        let info = parse_key_bytes(public_key.as_bytes(), false).unwrap();

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
        let info = parse_key_bytes(&secret_key, true).unwrap();

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
    use std::io::Cursor;
    use wecanencrypt::pgp::composed::{
        CleartextSignedMessage, Deserializable, DetachedSignature, MessageBuilder, SignedSecretKey,
    };
    use wecanencrypt::pgp::crypto::hash::HashAlgorithm;
    use wecanencrypt::pgp::types::Password;

    fn parse_secret(data: &[u8]) -> SignedSecretKey {
        SignedSecretKey::from_armor_single(Cursor::new(data))
            .map(|(k, _)| k)
            .or_else(|_| SignedSecretKey::from_bytes(Cursor::new(data)))
            .expect("parse as secret")
    }

    fn raw_primary_detached_signature(secret_key: &SignedSecretKey, data: &[u8]) -> String {
        let mut rng = rand::thread_rng();
        let signature = DetachedSignature::sign_binary_data(
            &mut rng,
            &secret_key.primary_key,
            &Password::from(TEST_PASSWORD),
            HashAlgorithm::Sha256,
            Cursor::new(data),
        )
        .expect("create primary detached signature");
        signature
            .to_armored_string(None.into())
            .expect("armor detached signature")
    }

    fn raw_primary_inline_signature(secret_key: &SignedSecretKey, data: &[u8]) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut builder = MessageBuilder::from_bytes("", data.to_vec());
        builder.sign(
            &secret_key.primary_key,
            Password::from(TEST_PASSWORD),
            HashAlgorithm::Sha256,
        );
        builder
            .to_armored_string(&mut rng, None.into())
            .expect("armor inline signature")
            .into_bytes()
    }

    fn raw_primary_cleartext_signature(secret_key: &SignedSecretKey, data: &[u8]) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let text = String::from_utf8_lossy(data);
        CleartextSignedMessage::sign(
            &mut rng,
            &text,
            &secret_key.primary_key,
            &Password::from(TEST_PASSWORD),
        )
        .expect("create cleartext signature")
        .to_armored_string(None.into())
        .expect("armor cleartext signature")
        .into_bytes()
    }

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

        let key = create_key(
            TEST_PASSWORD,
            &[TEST_UID],
            CipherSuite::Cv25519,
            None,
            None,
            None,
            SubkeyFlags::all(),
            true,
            true,
        )
        .unwrap();
        let secret_key = key.secret_key;
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
    fn test_forced_primary_signing_rejects_certify_only_primary() {
        use wecanencrypt::{
            sign_bytes_cleartext_with_primary_key, sign_bytes_detached_with_primary_key,
            sign_bytes_with_primary_key,
        };

        let key = create_key(
            TEST_PASSWORD,
            &[TEST_UID],
            CipherSuite::Cv25519,
            None,
            None,
            None,
            SubkeyFlags::encryption_only(),
            false,
            true,
        )
        .unwrap();
        let info = parse_key_bytes(&key.secret_key, true).unwrap();
        assert!(!info.can_primary_sign);

        let message = b"certify-only primary must not sign data";

        let result = sign_bytes_with_primary_key(&key.secret_key, message, TEST_PASSWORD);
        assert!(
            matches!(result, Err(wecanencrypt::Error::NoSigningSubkey)),
            "forced inline primary signing should reject certify-only primary, got {result:?}"
        );

        let result = sign_bytes_cleartext_with_primary_key(&key.secret_key, message, TEST_PASSWORD);
        assert!(
            matches!(result, Err(wecanencrypt::Error::NoSigningSubkey)),
            "forced cleartext primary signing should reject certify-only primary, got {result:?}"
        );

        let result = sign_bytes_detached_with_primary_key(&key.secret_key, message, TEST_PASSWORD);
        assert!(
            matches!(result, Err(wecanencrypt::Error::NoSigningSubkey)),
            "forced detached primary signing should reject certify-only primary, got {result:?}"
        );
    }

    #[test]
    fn test_certify_only_primary_signatures_fail_policy_verification() {
        let key = create_key(
            TEST_PASSWORD,
            &[TEST_UID],
            CipherSuite::Cv25519,
            None,
            None,
            None,
            SubkeyFlags::encryption_only(),
            false,
            true,
        )
        .unwrap();
        let public_key = get_pub_key(&key.secret_key).unwrap();
        let secret_key = parse_secret(&key.secret_key);
        let message = b"certify-only primary signature must not verify as data signing";

        let detached = raw_primary_detached_signature(&secret_key, message);
        let valid =
            verify_bytes_detached(public_key.as_bytes(), message, detached.as_bytes()).unwrap();
        assert!(
            !valid,
            "policy-aware detached verification must reject certify-only primary signatures"
        );

        let inline = raw_primary_inline_signature(&secret_key, message);
        let valid = verify_bytes(public_key.as_bytes(), &inline).unwrap();
        assert!(
            !valid,
            "policy-aware inline verification must reject certify-only primary signatures"
        );
        assert!(matches!(
            verify_and_extract_bytes(public_key.as_bytes(), &inline),
            Err(wecanencrypt::Error::VerificationFailed)
        ));

        let cleartext = raw_primary_cleartext_signature(&secret_key, message);
        let valid = verify_bytes(public_key.as_bytes(), &cleartext).unwrap();
        assert!(
            !valid,
            "policy-aware cleartext verification must reject certify-only primary signatures"
        );
        assert!(matches!(
            verify_and_extract_bytes(public_key.as_bytes(), &cleartext),
            Err(wecanencrypt::Error::VerificationFailed)
        ));
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

        let info = parse_key_bytes(&updated_key, true).unwrap();
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
        let info = parse_key_bytes(&updated_key, true).unwrap();
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
        let info = parse_key_bytes(public_key.as_bytes(), false).unwrap();
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
    use wecanencrypt::pgp::composed::{
        SignedKeyDetails, SignedPublicSubKey, SignedSecretKey, SignedSecretSubKey,
    };
    use wecanencrypt::pgp::packet::{
        KeyFlags, Signature, SignatureConfig, SignatureType, Subpacket, SubpacketData,
    };
    use wecanencrypt::pgp::ser::Serialize;
    use wecanencrypt::pgp::types::{KeyDetails, KeyVersion, Password, SignedUser, Tag, Timestamp};

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
                config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
                    secret_key.primary_key.legacy_key_id(),
                ))
                .unwrap()];
            }

            let sig = config
                .sign_certification(
                    &secret_key.primary_key,
                    &secret_key.primary_key.public_key(),
                    &password_obj,
                    Tag::UserId,
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

    /// Helper: create a newer verified subkey binding with specific key flags.
    fn subkey_binding_with_flags(
        secret_key: &SignedSecretKey,
        subkey: &SignedSecretSubKey,
        password: &str,
        sign_flag: bool,
        auth_flag: bool,
    ) -> Signature {
        let mut rng = rand::thread_rng();
        let mut flags = KeyFlags::default();
        flags.set_sign(sign_flag);
        flags.set_authentication(auth_flag);

        let newest_binding_created = subkey
            .signatures
            .iter()
            .filter(|sig| sig.typ() == Some(SignatureType::SubkeyBinding))
            .filter_map(|sig| sig.created().map(|ts| ts.as_secs()))
            .max()
            .unwrap_or_else(|| subkey.key.created_at().as_secs());

        let mut config = SignatureConfig::from_key(
            &mut rng,
            &secret_key.primary_key,
            SignatureType::SubkeyBinding,
        )
        .unwrap();
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
                newest_binding_created + 2,
            )))
            .unwrap(),
            Subpacket::regular(SubpacketData::IssuerFingerprint(
                secret_key.primary_key.fingerprint(),
            ))
            .unwrap(),
            Subpacket::regular(SubpacketData::KeyFlags(flags)).unwrap(),
        ];
        if secret_key.primary_key.version() <= KeyVersion::V4 {
            config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
                secret_key.primary_key.legacy_key_id(),
            ))
            .unwrap()];
        }

        config
            .sign_subkey_binding(
                &secret_key.primary_key,
                secret_key.primary_key.public_key(),
                &Password::from(password),
                subkey.key.public_key(),
            )
            .unwrap()
    }

    /// Helper: append a newer verified binding to a secret subkey and its
    /// matching public copy, preserving the old binding history.
    fn resign_subkey_with_flags(
        secret_data: &[u8],
        password: &str,
        target_fp: &wecanencrypt::pgp::types::Fingerprint,
        sign_flag: bool,
        auth_flag: bool,
    ) -> Vec<u8> {
        let secret_key = parse_secret(secret_data);
        let target = secret_key
            .secret_subkeys
            .iter()
            .find(|subkey| &subkey.key.fingerprint() == target_fp)
            .expect("target subkey exists");
        let binding =
            subkey_binding_with_flags(&secret_key, target, password, sign_flag, auth_flag);

        let mut secret_subkeys = secret_key.secret_subkeys.clone();
        let idx = secret_subkeys
            .iter()
            .position(|subkey| &subkey.key.fingerprint() == target_fp)
            .expect("target secret subkey exists");
        let secret_subkey = &mut secret_subkeys[idx];
        let mut secret_sigs = secret_subkey.signatures.clone();
        secret_sigs.push(binding.clone());
        *secret_subkey = SignedSecretSubKey::new(secret_subkey.key.clone(), secret_sigs);

        let mut public_subkeys = secret_key.public_subkeys.clone();
        if let Some(public_subkey) = public_subkeys
            .iter_mut()
            .find(|subkey| &subkey.key.fingerprint() == target_fp)
        {
            let mut public_sigs = public_subkey.signatures.clone();
            public_sigs.push(binding);
            *public_subkey = SignedPublicSubKey::new(public_subkey.key.clone(), public_sigs);
        }

        let updated = SignedSecretKey::new(
            secret_key.primary_key.clone(),
            secret_key.details.clone(),
            public_subkeys,
            secret_subkeys,
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

        let info = parse_key_bytes(&key.secret_key, true).unwrap();
        assert!(
            info.can_primary_sign,
            "Original key should have primary sign capability"
        );

        // Create a newer self-sig that REMOVES the sign flag (certify-only).
        let updated = resign_uid_with_flags(&key.secret_key, TEST_PASSWORD, false, true);

        let info2 = parse_key_bytes(&updated, true).unwrap();
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

        let info = parse_key_bytes(&key.secret_key, true).unwrap();
        assert!(
            !info.can_primary_sign,
            "Original key should NOT have primary sign capability"
        );

        // Create a newer self-sig that ADDS the sign flag.
        let updated = resign_uid_with_flags(&key.secret_key, TEST_PASSWORD, true, true);

        let info2 = parse_key_bytes(&updated, true).unwrap();
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

        let info = parse_key_bytes(&merged, false).unwrap();
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

        let info = parse_key_bytes(&merged, false).unwrap();
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

        let info = parse_key_bytes(&key.secret_key, true).unwrap();
        assert!(
            !info.can_primary_sign,
            "Certify-only key should not have sign capability"
        );

        // Update the expiry — this creates a new self-sig that copies flags
        // from the existing sig (should preserve certify-only).
        let exp = chrono::Utc::now() + chrono::Duration::days(365);
        let updated =
            wecanencrypt::update_primary_expiry(&key.secret_key, exp, TEST_PASSWORD).unwrap();

        let info2 = parse_key_bytes(&updated, true).unwrap();
        assert!(
            !info2.can_primary_sign,
            "After expiry update, certify-only key should still not have sign capability"
        );
    }

    #[test]
    fn test_latest_subkey_binding_removing_sign_flag_blocks_signing_helpers() {
        let key = create_key(
            TEST_PASSWORD,
            &[TEST_UID],
            CipherSuite::Cv25519,
            None,
            None,
            None,
            SubkeyFlags::signing_only(),
            false,
            true,
        )
        .unwrap();
        let secret_key = parse_secret(&key.secret_key);
        let signing_fp = secret_key
            .secret_subkeys
            .iter()
            .find(|subkey| subkey.signatures.iter().any(|sig| sig.key_flags().sign()))
            .expect("generated key has a signing subkey")
            .key
            .fingerprint();

        assert!(
            sign_bytes_detached(&key.secret_key, b"before role removal", TEST_PASSWORD).is_ok(),
            "original signing subkey should be usable before the newer binding removes signing"
        );

        let updated =
            resign_subkey_with_flags(&key.secret_key, TEST_PASSWORD, &signing_fp, false, false);
        let updated_public = get_pub_key(&updated).unwrap();

        assert!(
            !wecanencrypt::has_available_signing_subkey(&updated).unwrap(),
            "latest binding without sign flag must remove the available signing subkey"
        );
        assert!(
            matches!(
                sign_bytes(&updated, b"inline", TEST_PASSWORD),
                Err(wecanencrypt::Error::NoSigningSubkey)
            ),
            "inline signing must not use a stale historical sign flag"
        );
        assert!(
            matches!(
                sign_bytes_cleartext(&updated, b"cleartext", TEST_PASSWORD),
                Err(wecanencrypt::Error::NoSigningSubkey)
            ),
            "cleartext signing must not use a stale historical sign flag"
        );
        assert!(
            matches!(
                sign_bytes_detached(&updated, b"detached", TEST_PASSWORD),
                Err(wecanencrypt::Error::NoSigningSubkey)
            ),
            "detached signing must not use a stale historical sign flag"
        );
        assert!(
            matches!(
                wecanencrypt::get_signing_pubkey(updated_public.as_bytes()),
                Err(wecanencrypt::Error::NoSigningSubkey)
            ),
            "signing public-key export must not use a stale historical sign flag"
        );
    }

    #[test]
    fn test_latest_subkey_binding_removing_auth_flag_blocks_ssh_helpers() {
        let key = create_key(
            TEST_PASSWORD,
            &[TEST_UID],
            CipherSuite::Cv25519,
            None,
            None,
            None,
            SubkeyFlags {
                encryption: false,
                signing: false,
                authentication: true,
            },
            false,
            true,
        )
        .unwrap();
        let secret_key = parse_secret(&key.secret_key);
        let auth_fp = secret_key
            .secret_subkeys
            .iter()
            .find(|subkey| {
                subkey
                    .signatures
                    .iter()
                    .any(|sig| sig.key_flags().authentication())
            })
            .expect("generated key has an authentication subkey")
            .key
            .fingerprint();

        let public_before = get_pub_key(&key.secret_key).unwrap();
        assert!(
            wecanencrypt::get_ssh_pubkey(public_before.as_bytes(), None).is_ok(),
            "original authentication subkey should export for SSH"
        );
        assert!(
            wecanencrypt::ssh_sign_raw(
                &key.secret_key,
                b"before role removal",
                TEST_PASSWORD,
                wecanencrypt::SshHashAlgorithm::Sha256,
            )
            .is_ok(),
            "original authentication subkey should sign SSH challenges"
        );

        let updated =
            resign_subkey_with_flags(&key.secret_key, TEST_PASSWORD, &auth_fp, false, false);
        let updated_public = get_pub_key(&updated).unwrap();

        assert!(
            wecanencrypt::get_available_authentication_subkeys(&updated)
                .unwrap()
                .is_empty(),
            "latest binding without auth flag must remove the available authentication subkey"
        );
        assert!(
            matches!(
                wecanencrypt::get_ssh_pubkey(updated_public.as_bytes(), None),
                Err(wecanencrypt::Error::NoAuthenticationSubkey)
            ),
            "SSH public-key export must not use a stale historical auth flag"
        );
        assert!(
            matches!(
                wecanencrypt::ssh_sign_raw(
                    &updated,
                    b"after role removal",
                    TEST_PASSWORD,
                    wecanencrypt::SshHashAlgorithm::Sha256,
                ),
                Err(wecanencrypt::Error::NoAuthenticationSubkey)
            ),
            "SSH raw signing must not use a stale historical auth flag"
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
    use pgp::packet::{SignatureConfig, SignatureType, Subpacket, SubpacketData, UserId};
    use pgp::ser::Serialize;
    use pgp::types::{
        KeyDetails, KeyVersion, PacketHeaderVersion, Password, SignedUser, Tag, Timestamp,
    };
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

    fn attacker_signed_uid(attacker: &SignedSecretKey, uid: &str) -> SignedUser {
        let mut rng = rand::thread_rng();
        let user_id = UserId::from_str(PacketHeaderVersion::New, uid).expect("create UID");
        let mut config =
            SignatureConfig::from_key(&mut rng, &attacker.primary_key, SignatureType::CertPositive)
                .expect("signature config");
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now())).unwrap(),
            Subpacket::regular(SubpacketData::IssuerFingerprint(
                attacker.primary_key.fingerprint(),
            ))
            .unwrap(),
        ];
        if attacker.primary_key.version() <= KeyVersion::V4 {
            config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
                attacker.primary_key.legacy_key_id(),
            ))
            .unwrap()];
        }

        let sig = config
            .sign_certification(
                &attacker.primary_key,
                attacker.primary_key.public_key(),
                &Password::from(TEST_PASSWORD),
                Tag::UserId,
                &user_id,
            )
            .expect("attacker signs UID");
        SignedUser::new(user_id, vec![sig])
    }

    fn public_with_extra_user(victim: &SignedSecretKey, user: SignedUser) -> Vec<u8> {
        let mut details = victim.details.clone();
        details.users.push(user);
        let poisoned = SignedPublicKey {
            primary_key: victim.primary_key.public_key().clone(),
            details,
            public_subkeys: victim.to_public_key().public_subkeys,
        };
        poisoned.to_bytes().expect("serialize poisoned public key")
    }

    fn public_with_attacker_subkeys(
        victim: &SignedSecretKey,
        attacker: &SignedSecretKey,
    ) -> Vec<u8> {
        let poisoned = SignedPublicKey {
            primary_key: victim.primary_key.public_key().clone(),
            details: victim.details.clone(),
            public_subkeys: attacker.to_public_key().public_subkeys,
        };
        poisoned.to_bytes().expect("serialize poisoned public key")
    }

    fn uid_has_verified_self_cert(secret: &SignedSecretKey, uid: &str) -> bool {
        let primary = secret.primary_key.public_key();
        secret
            .details
            .users
            .iter()
            .find(|user| std::str::from_utf8(user.id.id()).unwrap_or("") == uid)
            .map(|user| {
                user.signatures.iter().any(|sig| {
                    matches!(
                        sig.typ(),
                        Some(SignatureType::CertGeneric)
                            | Some(SignatureType::CertPersona)
                            | Some(SignatureType::CertCasual)
                            | Some(SignatureType::CertPositive)
                    ) && sig
                        .verify_certification(primary, Tag::UserId, &user.id)
                        .is_ok()
                })
            })
            .unwrap_or(false)
    }

    fn public_subkey_has_verified_binding(
        secret: &SignedSecretKey,
        fp: &pgp::types::Fingerprint,
    ) -> bool {
        let primary = secret.primary_key.public_key();
        secret
            .public_subkeys
            .iter()
            .find(|subkey| &subkey.key.fingerprint() == fp)
            .map(|subkey| {
                subkey.signatures.iter().any(|sig| {
                    sig.typ() == Some(SignatureType::SubkeyBinding)
                        && sig.verify_subkey_binding(primary, &subkey.key).is_ok()
                })
            })
            .unwrap_or(false)
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

        let info = parse_key_bytes(&merged, false).unwrap();
        assert!(!info.is_secret);
        assert_eq!(info.fingerprint, key.fingerprint);
    }

    #[test]
    fn test_merge_public_plus_secret_upgrades() {
        // pub + sec → result carries secret material (upgrade path).
        let key = fresh_key();
        let pub_bytes = key.public_key.as_bytes();
        let merged = merge_keys(pub_bytes, &key.secret_key).unwrap();

        let info = parse_key_bytes(&merged, true).unwrap();
        assert!(
            info.is_secret,
            "pub + sec merge should produce a secret cert"
        );
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

        let info = parse_key_bytes(&merged, true).unwrap();
        assert!(
            info.is_secret,
            "sec + sec merge should produce a secret cert"
        );
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

        let info = parse_key_bytes(&merged, true).unwrap();
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

    /// Build a variant of `full` where `victim_fp` has been demoted to
    /// public_subkeys (its secret packet stripped). Returns the
    /// binary-serialized variant.
    fn demote_to_public(full: &SignedSecretKey, victim_fp: &pgp::types::Fingerprint) -> Vec<u8> {
        let mut new_sec_subkeys = Vec::new();
        let mut new_pub_subkeys = full.public_subkeys.clone();
        for sk in &full.secret_subkeys {
            if sk.key.fingerprint() == *victim_fp {
                // Drop the secret packet; keep the signatures on the public form.
                new_pub_subkeys.push(sk.signed_public_key());
            } else {
                new_sec_subkeys.push(sk.clone());
            }
        }
        SignedSecretKey::new(
            full.primary_key.clone(),
            full.details.clone(),
            new_pub_subkeys,
            new_sec_subkeys,
        )
        .to_bytes()
        .unwrap()
    }

    #[test]
    fn test_merge_promotion_preserves_public_side_signatures() {
        // orig has K2 in public_subkeys (say, because a previous import
        // dropped its secret material while keeping the binding sig).
        // update has K2 back as a full secret subkey — with a *renewed*
        // binding sig (fresh timestamp, different bytes). Merge must
        // promote K2 into secret_subkeys AND keep both sigs.
        let key = fresh_key();
        let full_sec = parse_sec(&key.secret_key);
        assert!(
            full_sec.secret_subkeys.len() >= 2,
            "test precondition: multiple secret subkeys required"
        );
        let victim_fp = full_sec.secret_subkeys[1].key.fingerprint();
        let victim_fp_hex = fingerprint_hex(&victim_fp);

        // Build a renewed cert whose binding sig on K2 is distinct
        // bytes from the original (update_subkeys_expiry regenerates
        // the subkey binding signature with a fresh creation time).
        let future = chrono::Utc::now() + chrono::Duration::days(365);
        let renewed = wecanencrypt::update_subkeys_expiry(
            &key.secret_key,
            &[&victim_fp_hex],
            future,
            TEST_PASSWORD,
        )
        .unwrap();

        // orig = key with K2 demoted to public_subkeys (carrying the
        // ORIGINAL binding sig).
        let orig_bytes = demote_to_public(&full_sec, &victim_fp);

        // update = renewed full secret cert (K2 on the secret side
        // carrying the NEW binding sig, different bytes).
        let merged = merge_keys(&orig_bytes, &renewed).unwrap();
        let merged_sec = parse_sec(&merged);

        // K2 must now be on the secret side.
        let k2 = merged_sec
            .secret_subkeys
            .iter()
            .find(|sk| sk.key.fingerprint() == victim_fp)
            .unwrap_or_else(|| panic!("K2 {} was not promoted to secret_subkeys", victim_fp_hex));

        // K2 must carry BOTH binding sigs (old preserved from the
        // public-form entry + new from the secret side). Without the
        // preservation splice, only the renewed sig would survive.
        assert!(
            k2.signatures.len() >= 2,
            "promoted subkey {} lost prior public-side signatures: got {}",
            victim_fp_hex,
            k2.signatures.len()
        );

        // Sanity: K2 must not be on the public side anymore.
        assert!(
            !merged_sec
                .public_subkeys
                .iter()
                .any(|sk| sk.fingerprint() == victim_fp),
            "K2 remained in public_subkeys after promotion"
        );
    }

    #[test]
    fn test_merge_promotion_dedups_identical_binding_sig() {
        // Same subkey on both sides, with the SAME binding sig on both.
        // The preservation splice must dedup via merge_signatures — no
        // double-entry of the identical sig.
        let key = fresh_key();
        let full_sec = parse_sec(&key.secret_key);
        let victim_fp = full_sec.secret_subkeys[1].key.fingerprint();

        // orig = key with K2 demoted to public_subkeys; signatures
        // there are verbatim copies of the original binding sig.
        let orig_bytes = demote_to_public(&full_sec, &victim_fp);

        // update = the unmodified full secret cert. K2's secret side
        // has the exact same binding sig bytes.
        let merged = merge_keys(&orig_bytes, &key.secret_key).unwrap();
        let merged_sec = parse_sec(&merged);

        let k2 = merged_sec
            .secret_subkeys
            .iter()
            .find(|sk| sk.key.fingerprint() == victim_fp)
            .expect("K2 promoted");

        // Only one copy of each distinct signature — duplicates must be
        // collapsed by merge_signatures' signature_bytes_eq dedup.
        let original_sig_count = full_sec
            .secret_subkeys
            .iter()
            .find(|sk| sk.key.fingerprint() == victim_fp)
            .unwrap()
            .signatures
            .len();
        assert_eq!(
            k2.signatures.len(),
            original_sig_count,
            "dedup failed: expected {} sigs, got {}",
            original_sig_count,
            k2.signatures.len()
        );
    }

    #[test]
    fn test_merge_promotion_no_op_when_no_public_form() {
        // When orig does NOT have K_new in public_subkeys at all, the
        // preservation splice must be a no-op and the incoming secret
        // subkey's signatures must be taken as-is.
        let key = fresh_key();
        let full_sec = parse_sec(&key.secret_key);
        assert!(full_sec.secret_subkeys.len() >= 2);

        // orig = key with K2 entirely removed (not on any side).
        let k2_fp = full_sec.secret_subkeys[1].key.fingerprint();
        let trimmed = SignedSecretKey::new(
            full_sec.primary_key.clone(),
            full_sec.details.clone(),
            full_sec.public_subkeys.clone(),
            full_sec.secret_subkeys[..1].to_vec(),
        );
        let orig_bytes = trimmed.to_bytes().unwrap();

        // update = full secret cert (brings K2 back).
        let merged = merge_keys(&orig_bytes, &key.secret_key).unwrap();
        let merged_sec = parse_sec(&merged);

        let k2 = merged_sec
            .secret_subkeys
            .iter()
            .find(|sk| sk.key.fingerprint() == k2_fp)
            .expect("K2 should be absorbed");

        // Signature count must match what the update originally carried
        // — nothing spliced in (because there was no public-form entry).
        let update_sig_count = full_sec
            .secret_subkeys
            .iter()
            .find(|sk| sk.key.fingerprint() == k2_fp)
            .unwrap()
            .signatures
            .len();
        assert_eq!(k2.signatures.len(), update_sig_count);
    }

    #[test]
    fn test_primary_expiry_does_not_self_certify_poisoned_merged_uid() {
        let victim = fresh_key();
        let attacker = create_key_simple(TEST_PASSWORD, &["Attacker <a@example.com>"]).unwrap();
        let victim_sec = parse_sec(&victim.secret_key);
        let attacker_sec = parse_sec(&attacker.secret_key);
        let poisoned_uid = "Mallory <mallory@example.com>";
        let poisoned_public = public_with_extra_user(
            &victim_sec,
            attacker_signed_uid(&attacker_sec, poisoned_uid),
        );

        let merged = merge_keys(&victim.secret_key, &poisoned_public).unwrap();
        let merged_sec = parse_sec(&merged);
        assert!(
            merged_sec
                .details
                .users
                .iter()
                .any(|user| std::str::from_utf8(user.id.id()).unwrap_or("") == poisoned_uid),
            "poisoned UID must be present before maintenance for the regression to be meaningful"
        );
        assert!(
            !uid_has_verified_self_cert(&merged_sec, poisoned_uid),
            "poisoned UID must not start with a victim self-certification"
        );

        let future = chrono::Utc::now() + chrono::Duration::days(365);
        let renewed = wecanencrypt::update_primary_expiry(&merged, future, TEST_PASSWORD).unwrap();
        let renewed_sec = parse_sec(&renewed);

        assert!(
            !uid_has_verified_self_cert(&renewed_sec, poisoned_uid),
            "primary expiry maintenance must not create the first valid self-certification \
             for an unverified merged UID"
        );
    }

    #[test]
    fn test_subkey_expiry_does_not_bind_poisoned_merged_public_subkey() {
        let victim = fresh_key();
        let attacker = create_key_simple(TEST_PASSWORD, &["Attacker <a@example.com>"]).unwrap();
        let victim_sec = parse_sec(&victim.secret_key);
        let attacker_sec = parse_sec(&attacker.secret_key);
        let attacker_public = attacker_sec.to_public_key();
        let poisoned_fp = attacker_public
            .public_subkeys
            .first()
            .expect("attacker key has a public subkey")
            .key
            .fingerprint();
        let poisoned_fp_hex = fingerprint_hex(&poisoned_fp);
        let poisoned_public = public_with_attacker_subkeys(&victim_sec, &attacker_sec);

        let merged = merge_keys(&victim.secret_key, &poisoned_public).unwrap();
        let merged_sec = parse_sec(&merged);
        assert!(
            merged_sec
                .public_subkeys
                .iter()
                .any(|subkey| subkey.key.fingerprint() == poisoned_fp),
            "poisoned public subkey must be present before maintenance"
        );
        assert!(
            !public_subkey_has_verified_binding(&merged_sec, &poisoned_fp),
            "poisoned public subkey must not start with a victim binding"
        );

        let future = chrono::Utc::now() + chrono::Duration::days(365);
        let renewed = wecanencrypt::update_subkeys_expiry(
            &merged,
            &[&poisoned_fp_hex],
            future,
            TEST_PASSWORD,
        )
        .unwrap();
        let renewed_sec = parse_sec(&renewed);

        assert!(
            !public_subkey_has_verified_binding(&renewed_sec, &poisoned_fp),
            "subkey expiry maintenance must not create the first valid binding \
             for an unverified merged public subkey"
        );
    }

    fn fingerprint_hex(fp: &pgp::types::Fingerprint) -> String {
        hex::encode_upper(fp.as_bytes())
    }
}

// =============================================================================
// V6 (RFC 9580) key tests
// =============================================================================

mod v6_keys {
    use super::*;
    use wecanencrypt::{create_key_v6, create_key_v6_simple, Error, KeyVersion};

    #[test]
    fn v6_cv25519_modern_round_trip() {
        let key =
            create_key_v6_simple(TEST_PASSWORD, &[TEST_UID], CipherSuite::Cv25519Modern).unwrap();

        // V6 fingerprints are SHA-256 → 32 bytes → 64 hex chars.
        assert_eq!(
            key.fingerprint.len(),
            64,
            "V6 primary fingerprint must be SHA-256 (64 hex chars), got {}",
            key.fingerprint
        );

        let info = parse_key_bytes(&key.secret_key, false).unwrap();
        assert_eq!(info.key_version, KeyVersion::V6);
        for sk in &info.subkeys {
            assert_eq!(
                sk.key_version,
                KeyVersion::V6,
                "every subkey of a V6 primary must also be V6"
            );
            assert_eq!(sk.fingerprint.len(), 64);
        }

        // Round-trip encryption — auto-dispatch should pick SEIPDv2 for V6.
        let pub_key = get_pub_key(&key.secret_key).unwrap();
        let ciphertext = encrypt_bytes(pub_key.as_bytes(), b"v6 secret", true).unwrap();
        let plaintext = decrypt_bytes(&key.secret_key, &ciphertext, TEST_PASSWORD).unwrap();
        assert_eq!(plaintext, b"v6 secret");

        // Sign / verify round-trip.
        let signed = sign_bytes(&key.secret_key, b"v6 payload", TEST_PASSWORD).unwrap();
        let extracted = verify_and_extract_bytes(pub_key.as_bytes(), &signed).unwrap();
        assert_eq!(extracted, b"v6 payload");
    }

    #[test]
    fn v6_cv448_modern_round_trip() {
        let key =
            create_key_v6_simple(TEST_PASSWORD, &[TEST_UID], CipherSuite::Cv448Modern).unwrap();
        assert_eq!(key.fingerprint.len(), 64);

        let info = parse_key_bytes(&key.secret_key, false).unwrap();
        assert_eq!(info.key_version, KeyVersion::V6);

        let pub_key = get_pub_key(&key.secret_key).unwrap();
        let ciphertext = encrypt_bytes(pub_key.as_bytes(), b"ed448 works", true).unwrap();
        let plaintext = decrypt_bytes(&key.secret_key, &ciphertext, TEST_PASSWORD).unwrap();
        assert_eq!(plaintext, b"ed448 works");
    }

    #[test]
    fn v6_rejects_legacy_cv25519() {
        let result = create_key_v6(
            TEST_PASSWORD,
            &[TEST_UID],
            CipherSuite::Cv25519,
            None,
            None,
            None,
            SubkeyFlags::all(),
            false,
            true,
        );

        match result {
            Err(Error::InvalidInput(msg)) => {
                assert!(msg.contains("V6"), "error should mention V6; got: {}", msg);
            }
            other => panic!("expected InvalidInput for V6 + Cv25519, got {:?}", other),
        }
    }

    #[test]
    fn v6_sign_detached_and_verify() {
        let key =
            create_key_v6_simple(TEST_PASSWORD, &[TEST_UID], CipherSuite::Cv25519Modern).unwrap();
        let pub_key = get_pub_key(&key.secret_key).unwrap();

        let sig = sign_bytes_detached(&key.secret_key, b"detach me", TEST_PASSWORD).unwrap();
        assert!(verify_bytes_detached(pub_key.as_bytes(), b"detach me", sig.as_bytes()).unwrap());
    }

    #[test]
    fn v6_cleartext_sign_and_verify() {
        let key =
            create_key_v6_simple(TEST_PASSWORD, &[TEST_UID], CipherSuite::Cv25519Modern).unwrap();
        let pub_key = get_pub_key(&key.secret_key).unwrap();

        let clear = sign_bytes_cleartext(&key.secret_key, b"hello v6", TEST_PASSWORD).unwrap();
        assert!(verify_bytes(pub_key.as_bytes(), &clear).unwrap());
    }

    #[test]
    fn v6_mixed_recipient_list_rejected() {
        let v4 = create_key_simple(TEST_PASSWORD, &[TEST_UID]).unwrap();
        let v6 = create_key_v6_simple(
            TEST_PASSWORD,
            &["V6 User <v6@example.com>"],
            CipherSuite::Cv25519Modern,
        )
        .unwrap();

        let v4_pub = get_pub_key(&v4.secret_key).unwrap();
        let v6_pub = get_pub_key(&v6.secret_key).unwrap();

        let err =
            encrypt_bytes_to_multiple(&[v4_pub.as_bytes(), v6_pub.as_bytes()], b"mixed", true)
                .unwrap_err();
        match err {
            Error::KeyVersionMismatch { .. } => {}
            other => panic!("expected KeyVersionMismatch, got {:?}", other),
        }
    }

    #[test]
    fn v6_parse_reports_v6_on_all_subkeys() {
        let key =
            create_key_v6_simple(TEST_PASSWORD, &[TEST_UID], CipherSuite::Cv25519Modern).unwrap();

        let info = parse_key_bytes(&key.secret_key, false).unwrap();
        assert_eq!(info.key_version, KeyVersion::V6);
        assert!(!info.subkeys.is_empty());
        for sk in &info.subkeys {
            assert_eq!(sk.key_version, KeyVersion::V6);
        }

        let details = get_key_cipher_details(&key.secret_key).unwrap();
        assert!(!details.is_empty());
    }

    #[test]
    fn v6_update_password_preserves_version() {
        let key =
            create_key_v6_simple(TEST_PASSWORD, &[TEST_UID], CipherSuite::Cv25519Modern).unwrap();

        let new_secret =
            update_password(&key.secret_key, TEST_PASSWORD, "a-brand-new-password").unwrap();
        let info = parse_key_bytes(&new_secret, false).unwrap();
        assert_eq!(
            info.key_version,
            KeyVersion::V6,
            "password rotation must not downgrade the key version"
        );

        let pub_key = get_pub_key(&new_secret).unwrap();
        let ct = encrypt_bytes(pub_key.as_bytes(), b"post-rotate", true).unwrap();
        let pt = decrypt_bytes(&new_secret, &ct, "a-brand-new-password").unwrap();
        assert_eq!(pt, b"post-rotate");
    }

    #[test]
    fn v6_add_uid_keeps_v6() {
        let key =
            create_key_v6_simple(TEST_PASSWORD, &[TEST_UID], CipherSuite::Cv25519Modern).unwrap();

        let with_extra = add_uid(
            &key.secret_key,
            "Another V6 <more@example.com>",
            TEST_PASSWORD,
        )
        .unwrap();

        let info = parse_key_bytes(&with_extra, false).unwrap();
        assert_eq!(info.key_version, KeyVersion::V6);
        assert!(info
            .user_ids
            .iter()
            .any(|u| u.value.contains("more@example.com")));
    }

    #[test]
    fn v6_revoke_uid_keeps_v6() {
        let key = create_key_v6_simple(
            TEST_PASSWORD,
            &[TEST_UID, "Secondary <second@example.com>"],
            CipherSuite::Cv25519Modern,
        )
        .unwrap();

        let revoked = revoke_uid(
            &key.secret_key,
            "Secondary <second@example.com>",
            TEST_PASSWORD,
        )
        .unwrap();
        let info = parse_key_bytes(&revoked, false).unwrap();
        assert_eq!(info.key_version, KeyVersion::V6);
        let secondary = info
            .user_ids
            .iter()
            .find(|u| u.value.contains("second@example.com"))
            .expect("secondary UID still listed");
        assert!(secondary.revoked);
    }
}
