//! Smart card integration tests.
//!
//! These tests require a physical YubiKey or compatible OpenPGP smart card.
//! Run with: cargo test --features card --test card_tests -- --ignored --test-threads=1
//!
//! **Self-contained tests**: Each signing/decryption test automatically:
//! 1. Resets the card to factory defaults
//! 2. Uploads the required key to the appropriate slot
//! 3. Verifies the fingerprint on the card matches expected
//! 4. Performs the test operation
//!
//! This means tests can be run independently without manual setup.
//!
//! Test keys available in tests/files/card_keys/:
//! - 5286C32E7C71E14C4C82F9AE0B207108925CB162 - Ed25519/CV25519 key
//!   - Primary: 5286C32E7C71E14C4C82F9AE0B207108925CB162 [C]
//!   - Signing: 30A697C27F90EAED0B78C8235E0BDC772A2CF037 [S]
//!   - Auth:    50BAC98D4ADFD5D4485A1B04DEECB8B1546ED530 [A]
//!   - Encrypt: 5D22EC7757DF42ED9C21AC9E7020C6D7B564D455 [E]
//!
//! - 2184DF8AF2CAFEB16357FE43E6F848F1DDC66C12 - RSA4096 key
//!   - Primary: 2184DF8AF2CAFEB16357FE43E6F848F1DDC66C12 [C]
//!   - Signing: E89EF5363C6F3E47A2067199067DC0B8054D00B1 [S]
//!   - Encrypt: 2366949147F5DA0306657B76C6F6EC57D4DFB9EC [E]
//!   - Auth:    B5871E65B9F6E5CF02C43E49B85DB676BEF37B03 [A]
//!
//! Test keys available in tests/files/store/:
//! - EA05A76601DAEF5CD035A2CF015F97430A6FD047 - NIST P-256 key
//!   - Primary: EA05A76601DAEF5CD035A2CF015F97430A6FD047 [C]
//!   - Signing: 0C2987BBC6F594F93BB69F3DE800CA48A39EFA1A [S]
//!   - Encrypt: 30F08A9908F8DCC812598D8DDC808202A07F17AC [E]
//!   - Auth:    685DC145A492E63B984A948381EFCE6F3D51FDBC [A]
//!
//! - 41F3EEDE2E88CD725EDA15D98B0EA682F000ED61 - NIST P-384 key
//!   - Primary: 41F3EEDE2E88CD725EDA15D98B0EA682F000ED61 [C]
//!   - Signing: 9850241FAA91B89C4528299CB1B1E916EAEEBDD1 [S]
//!   - Encrypt: 3F092693762A1864B7CDEDC546D95DBE5BCB67DA [E]
//!   - Auth:    6F98EF07F705A9C12AFAF8D9FD412A1563E6FDF2 [A]
//!
//! - C18F906D8776698D73B08A9496211BE971A86030 - NIST P-521 key
//!   - Primary: C18F906D8776698D73B08A9496211BE971A86030 [C]
//!   - Signing: D4AF1821F5F0CDA5594D126A4665CFB34310E908 [S]
//!   - Encrypt: 932ED7A86A9E587D5026DBF2DEA8A57E7F4BC1D9 [E]
//!   - Auth:    F18AB9F7E1A1FF88F76A4025BF2EA49F18178C08 [A]
//!
//! Default PINs (after reset):
//! - User PIN: 123456
//! - Admin PIN: 12345678
//!
//! WARNING: These tests will RESET your card and ERASE all existing keys!

#[cfg(feature = "card")]
mod card_tests {
    use std::fs;
    use wecanencrypt::card::*;
    use wecanencrypt::card::upload::{
        upload_key_to_card,
        upload_primary_key_to_card,
        upload_subkey_by_fingerprint,
        CardKeySlot,
    };
    use wecanencrypt::{encrypt_bytes, verify_bytes_detached};

    // ==================== Test Key Paths ====================

    const CV25519_PUBLIC_KEY: &str = "tests/files/card_keys/5286C32E7C71E14C4C82F9AE0B207108925CB162.pub";
    const CV25519_SECRET_KEY: &str = "tests/files/card_keys/5286C32E7C71E14C4C82F9AE0B207108925CB162.sec";
    const RSA_PUBLIC_KEY: &str = "tests/files/card_keys/2184DF8AF2CAFEB16357FE43E6F848F1DDC66C12.pub";
    const RSA_SECRET_KEY: &str = "tests/files/card_keys/2184DF8AF2CAFEB16357FE43E6F848F1DDC66C12.sec";

    // NIST P-256 keys (from store directory, same password)
    const NISTP256_PUBLIC_KEY: &str = "tests/files/store/nistp256_public.asc";
    const NISTP256_SECRET_KEY: &str = "tests/files/store/nistp256_secret.asc";

    // NIST P-384 keys
    const NISTP384_PUBLIC_KEY: &str = "tests/files/store/nistp384_public.asc";
    const NISTP384_SECRET_KEY: &str = "tests/files/store/nistp384_secret.asc";

    // NIST P-521 keys
    const NISTP521_PUBLIC_KEY: &str = "tests/files/store/nistp521_public.asc";
    const NISTP521_SECRET_KEY: &str = "tests/files/store/nistp521_secret.asc";

    // ==================== PINs ====================

    const USER_PIN: &[u8] = b"123456";
    const ADMIN_PIN: &[u8] = b"12345678";
    const KEY_PASSWORD: &[u8] = b"redhat";
    const NIST_KEY_PASSWORD: &[u8] = b"testpassword"; // NIST keys in store/ use different password

    // ==================== Expected Fingerprints ====================

    // CV25519 key fingerprints
    const CV25519_PRIMARY_FP: &str = "5286c32e7c71e14c4c82f9ae0b207108925cb162";
    const CV25519_SIGNING_FP: &str = "30a697c27f90eaed0b78c8235e0bdc772a2cf037";
    const CV25519_ENCRYPT_FP: &str = "5d22ec7757df42ed9c21ac9e7020c6d7b564d455";
    const CV25519_AUTH_FP: &str = "50bac98d4adfd5d4485a1b04deecb8b1546ed530";

    // RSA key fingerprints
    const RSA_PRIMARY_FP: &str = "2184df8af2cafeb16357fe43e6f848f1ddc66c12";
    const RSA_SIGNING_FP: &str = "e89ef5363c6f3e47a2067199067dc0b8054d00b1";
    const RSA_ENCRYPT_FP: &str = "2366949147f5da0306657b76c6f6ec57d4dfb9ec";
    const RSA_AUTH_FP: &str = "b5871e65b9f6e5cf02c43e49b85db676bef37b03";

    // NIST P-256 key fingerprints
    const NISTP256_PRIMARY_FP: &str = "ea05a76601daef5cd035a2cf015f97430a6fd047";
    const NISTP256_SIGNING_FP: &str = "0c2987bbc6f594f93bb69f3de800ca48a39efa1a";
    const NISTP256_ENCRYPT_FP: &str = "30f08a9908f8dcc812598d8ddc808202a07f17ac";
    const NISTP256_AUTH_FP: &str = "685dc145a492e63b984a948381efce6f3d51fdbc";

    // NIST P-384 key fingerprints
    const NISTP384_PRIMARY_FP: &str = "41f3eede2e88cd725eda15d98b0ea682f000ed61";
    const NISTP384_SIGNING_FP: &str = "9850241faa91b89c4528299cb1b1e916eaeebdd1";
    const NISTP384_ENCRYPT_FP: &str = "3f092693762a1864b7cdedc546d95dbe5bcb67da";
    const NISTP384_AUTH_FP: &str = "6f98ef07f705a9c12afaf8d9fd412a1563e6fdf2";

    // NIST P-521 key fingerprints
    const NISTP521_PRIMARY_FP: &str = "c18f906d8776698d73b08a9496211be971a86030";
    const NISTP521_SIGNING_FP: &str = "d4af1821f5f0cda5594d126a4665cfb34310e908";
    const NISTP521_ENCRYPT_FP: &str = "932ed7a86a9e587d5026dbf2dea8a57e7f4bc1d9";
    const NISTP521_AUTH_FP: &str = "f18ab9f7e1a1ff88f76a4025bf2ea49f18178c08";

    // ==================== Helper Functions ====================

    /// Reset the card to factory defaults and restore default PINs.
    /// This blocks the admin PIN by entering wrong PIN 3 times, then resets.
    fn reset_card_to_defaults() {
        println!("Resetting card to factory defaults...");

        // Block admin PIN by entering it wrong 3 times
        for i in 1..=3 {
            let _ = verify_admin_pin(b"00000000");
            println!("  Wrong PIN attempt {}/3", i);
        }

        // Reset the card
        reset_card().expect("Failed to reset card");
        println!("Card reset successful. PINs restored to defaults.");
    }

    /// Verify that the fingerprint on the card matches expected
    fn verify_card_fingerprint(slot: &str, expected_fp: &str) {
        let info = get_card_details().expect("Failed to get card details");

        let actual_fp = match slot {
            "signature" => info.signature_fingerprint,
            "encryption" => info.encryption_fingerprint,
            "authentication" => info.authentication_fingerprint,
            _ => panic!("Unknown slot: {}", slot),
        };

        match actual_fp {
            Some(fp) => {
                println!("  {} fingerprint: {}", slot, fp);
                assert_eq!(
                    fp.to_lowercase(),
                    expected_fp.to_lowercase(),
                    "{} fingerprint mismatch! Expected: {}, Got: {}",
                    slot,
                    expected_fp,
                    fp
                );
                println!("  ✓ {} fingerprint verified", slot);
            }
            None => panic!("No {} fingerprint found on card", slot),
        }
    }

    // ==================== Connection Tests ====================

    #[test]
    #[ignore = "requires physical smart card"]
    fn test_is_card_connected() {
        let connected = is_card_connected();
        println!("Card connected: {}", connected);
        assert!(connected, "No smart card detected. Please insert a YubiKey.");
    }

    #[test]
    #[ignore = "requires physical smart card"]
    fn test_get_card_details() {
        let info = get_card_details().expect("Failed to get card details");

        println!("Card Details:");
        println!("  Serial: {}", info.serial_number);
        println!("  Manufacturer: {:?}", info.manufacturer);
        println!("  Cardholder: {:?}", info.cardholder_name);
        println!("  URL: {:?}", info.public_key_url);
        println!("  Signature FP: {:?}", info.signature_fingerprint);
        println!("  Encryption FP: {:?}", info.encryption_fingerprint);
        println!("  Auth FP: {:?}", info.authentication_fingerprint);
        println!("  Signature count: {}", info.signature_counter);
        println!("  PIN retries: {}", info.pin_retry_counter);
        println!("  Admin PIN retries: {}", info.admin_pin_retry_counter);

        assert!(!info.serial_number.is_empty(), "Serial number should not be empty");
    }

    #[test]
    #[ignore = "requires physical smart card"]
    fn test_get_card_version() {
        let version = get_card_version().expect("Failed to get card version");
        println!("Card version: {}", version);
        assert!(!version.is_empty(), "Version should not be empty");
    }

    #[test]
    #[ignore = "requires physical smart card"]
    fn test_get_card_serial() {
        let serial = get_card_serial().expect("Failed to get card serial");
        println!("Card serial: {}", serial);
        assert!(!serial.is_empty(), "Serial should not be empty");
        assert_eq!(serial.len(), 8, "Serial should be 8 hex characters");
    }

    #[test]
    #[ignore = "requires physical smart card"]
    fn test_get_pin_retry_counters() {
        let (user, reset, admin) = get_pin_retry_counters().expect("Failed to get PIN counters");

        println!("PIN retry counters:");
        println!("  User PIN: {}", user);
        println!("  Reset code: {}", reset);
        println!("  Admin PIN: {}", admin);

        assert!(user <= 3, "User PIN retries should be <= 3");
        assert!(admin <= 3, "Admin PIN retries should be <= 3");
    }

    // ==================== PIN Verification Tests ====================

    #[test]
    #[ignore = "requires physical smart card with default PIN"]
    fn test_verify_user_pin() {
        let result = verify_user_pin(USER_PIN);
        assert!(result.is_ok(), "User PIN verification failed: {:?}", result.err());
        assert!(result.unwrap(), "User PIN should be verified");
    }

    #[test]
    #[ignore = "requires physical smart card with default PIN"]
    fn test_verify_admin_pin() {
        let result = verify_admin_pin(ADMIN_PIN);
        assert!(result.is_ok(), "Admin PIN verification failed: {:?}", result.err());
        assert!(result.unwrap(), "Admin PIN should be verified");
    }

    // ==================== CV25519 Subkey Upload + Verify Tests ====================

    #[test]
    #[ignore = "requires physical smart card"]
    fn test_upload_cv25519_signing_subkey_verify_fingerprint() {
        reset_card_to_defaults();

        let secret_key = fs::read(CV25519_SECRET_KEY)
            .expect("Failed to read CV25519 secret key");

        println!("Uploading CV25519 signing subkey to card...");
        upload_key_to_card(&secret_key, KEY_PASSWORD, CardKeySlot::Signing, ADMIN_PIN)
            .expect("Failed to upload signing key");
        println!("Signing key uploaded successfully.");

        // Verify fingerprint on card
        println!("Verifying fingerprint on card...");
        verify_card_fingerprint("signature", CV25519_SIGNING_FP);
    }

    #[test]
    #[ignore = "requires physical smart card"]
    fn test_upload_cv25519_encryption_subkey_verify_fingerprint() {
        reset_card_to_defaults();

        let secret_key = fs::read(CV25519_SECRET_KEY)
            .expect("Failed to read CV25519 secret key");

        println!("Uploading CV25519 encryption subkey to card...");
        upload_key_to_card(&secret_key, KEY_PASSWORD, CardKeySlot::Decryption, ADMIN_PIN)
            .expect("Failed to upload decryption key");
        println!("Decryption key uploaded successfully.");

        // Verify fingerprint on card
        println!("Verifying fingerprint on card...");
        verify_card_fingerprint("encryption", CV25519_ENCRYPT_FP);
    }

    // ==================== RSA Subkey Upload + Verify Tests ====================

    #[test]
    #[ignore = "requires physical smart card"]
    fn test_upload_rsa_signing_subkey_verify_fingerprint() {
        reset_card_to_defaults();

        let secret_key = fs::read(RSA_SECRET_KEY)
            .expect("Failed to read RSA secret key");

        println!("Uploading RSA signing subkey to card...");
        upload_key_to_card(&secret_key, KEY_PASSWORD, CardKeySlot::Signing, ADMIN_PIN)
            .expect("Failed to upload signing key");
        println!("Signing key uploaded successfully.");

        // Verify fingerprint on card
        println!("Verifying fingerprint on card...");
        verify_card_fingerprint("signature", RSA_SIGNING_FP);
    }

    #[test]
    #[ignore = "requires physical smart card"]
    fn test_upload_rsa_encryption_subkey_verify_fingerprint() {
        reset_card_to_defaults();

        let secret_key = fs::read(RSA_SECRET_KEY)
            .expect("Failed to read RSA secret key");

        println!("Uploading RSA encryption subkey to card...");
        upload_key_to_card(&secret_key, KEY_PASSWORD, CardKeySlot::Decryption, ADMIN_PIN)
            .expect("Failed to upload decryption key");
        println!("Decryption key uploaded successfully.");

        // Verify fingerprint on card
        println!("Verifying fingerprint on card...");
        verify_card_fingerprint("encryption", RSA_ENCRYPT_FP);
    }

    // ==================== Primary Key Upload Tests ====================

    #[test]
    #[ignore = "requires physical smart card"]
    fn test_upload_cv25519_primary_key_to_signing_slot() {
        reset_card_to_defaults();

        let secret_key = fs::read(CV25519_SECRET_KEY)
            .expect("Failed to read CV25519 secret key");

        println!("Uploading CV25519 PRIMARY key to signing slot...");
        upload_primary_key_to_card(&secret_key, KEY_PASSWORD, CardKeySlot::Signing, ADMIN_PIN)
            .expect("Failed to upload primary key");
        println!("Primary key uploaded successfully.");

        // Verify fingerprint on card - should be PRIMARY key fingerprint
        println!("Verifying PRIMARY key fingerprint on card...");
        verify_card_fingerprint("signature", CV25519_PRIMARY_FP);
    }

    #[test]
    #[ignore = "requires physical smart card"]
    fn test_upload_rsa_primary_key_to_signing_slot() {
        reset_card_to_defaults();

        let secret_key = fs::read(RSA_SECRET_KEY)
            .expect("Failed to read RSA secret key");

        println!("Uploading RSA PRIMARY key to signing slot...");
        upload_primary_key_to_card(&secret_key, KEY_PASSWORD, CardKeySlot::Signing, ADMIN_PIN)
            .expect("Failed to upload primary key");
        println!("Primary key uploaded successfully.");

        // Verify fingerprint on card - should be PRIMARY key fingerprint
        println!("Verifying PRIMARY key fingerprint on card...");
        verify_card_fingerprint("signature", RSA_PRIMARY_FP);
    }

    // ==================== Upload By Fingerprint Tests ====================

    #[test]
    #[ignore = "requires physical smart card"]
    fn test_upload_cv25519_subkey_by_fingerprint() {
        reset_card_to_defaults();

        let secret_key = fs::read(CV25519_SECRET_KEY)
            .expect("Failed to read CV25519 secret key");

        println!("Uploading CV25519 auth subkey by fingerprint to auth slot...");
        upload_subkey_by_fingerprint(
            &secret_key,
            KEY_PASSWORD,
            CV25519_AUTH_FP,
            CardKeySlot::Authentication,
            ADMIN_PIN,
        ).expect("Failed to upload auth key by fingerprint");
        println!("Auth key uploaded successfully.");

        // Verify fingerprint on card
        println!("Verifying fingerprint on card...");
        verify_card_fingerprint("authentication", CV25519_AUTH_FP);
    }

    #[test]
    #[ignore = "requires physical smart card"]
    fn test_upload_rsa_subkey_by_fingerprint() {
        reset_card_to_defaults();

        let secret_key = fs::read(RSA_SECRET_KEY)
            .expect("Failed to read RSA secret key");

        println!("Uploading RSA auth subkey by fingerprint to auth slot...");
        upload_subkey_by_fingerprint(
            &secret_key,
            KEY_PASSWORD,
            RSA_AUTH_FP,
            CardKeySlot::Authentication,
            ADMIN_PIN,
        ).expect("Failed to upload auth key by fingerprint");
        println!("Auth key uploaded successfully.");

        // Verify fingerprint on card
        println!("Verifying fingerprint on card...");
        verify_card_fingerprint("authentication", RSA_AUTH_FP);
    }

    // ==================== Full Workflow Tests (like johnnycanencrypt) ====================

    /// Test full CV25519 workflow: upload subkeys, verify fingerprints, sign, decrypt
    #[test]
    #[ignore = "requires physical smart card"]
    fn test_cv25519_full_workflow() {
        reset_card_to_defaults();

        let secret_key = fs::read(CV25519_SECRET_KEY)
            .expect("Failed to read CV25519 secret key");
        let public_key = fs::read(CV25519_PUBLIC_KEY)
            .expect("Failed to read CV25519 public key");

        // Upload signing subkey
        println!("Step 1: Uploading CV25519 signing subkey...");
        upload_key_to_card(&secret_key, KEY_PASSWORD, CardKeySlot::Signing, ADMIN_PIN)
            .expect("Failed to upload signing key");

        // Verify signing fingerprint
        println!("Step 2: Verifying signing key fingerprint...");
        verify_card_fingerprint("signature", CV25519_SIGNING_FP);

        // Upload encryption subkey
        println!("Step 3: Uploading CV25519 encryption subkey...");
        upload_key_to_card(&secret_key, KEY_PASSWORD, CardKeySlot::Decryption, ADMIN_PIN)
            .expect("Failed to upload encryption key");

        // Verify encryption fingerprint
        println!("Step 4: Verifying encryption key fingerprint...");
        verify_card_fingerprint("encryption", CV25519_ENCRYPT_FP);

        // Test signing
        println!("Step 5: Testing signing...");
        let msg = b"OpenPGP on smartcard.";
        let signature = sign_bytes_detached_on_card(msg, &public_key, USER_PIN)
            .expect("Failed to sign");
        println!("Signature created.");

        // Verify signature
        println!("Step 6: Verifying signature...");
        let is_valid = verify_bytes_detached(&public_key, msg, signature.as_bytes())
            .expect("Failed to verify signature");
        assert!(is_valid, "Signature verification failed");
        println!("✓ Signature verified successfully!");

        // Test encryption/decryption
        println!("Step 7: Testing encryption...");
        let encrypted = encrypt_bytes(&public_key, msg, true)
            .expect("Failed to encrypt");
        println!("Encrypted {} bytes", encrypted.len());

        println!("Step 8: Testing decryption on card...");
        let decrypted = decrypt_bytes_on_card(&encrypted, &public_key, USER_PIN)
            .expect("Failed to decrypt");
        assert_eq!(msg.to_vec(), decrypted, "Decryption mismatch");
        println!("✓ Decryption verified successfully!");

        println!("\n=== CV25519 full workflow completed successfully! ===");
    }

    /// Test full RSA workflow: upload subkeys, verify fingerprints, sign, decrypt
    #[test]
    #[ignore = "requires physical smart card"]
    fn test_rsa_full_workflow() {
        reset_card_to_defaults();

        let secret_key = fs::read(RSA_SECRET_KEY)
            .expect("Failed to read RSA secret key");
        let public_key = fs::read(RSA_PUBLIC_KEY)
            .expect("Failed to read RSA public key");

        // Upload signing subkey
        println!("Step 1: Uploading RSA signing subkey...");
        upload_key_to_card(&secret_key, KEY_PASSWORD, CardKeySlot::Signing, ADMIN_PIN)
            .expect("Failed to upload signing key");

        // Verify signing fingerprint
        println!("Step 2: Verifying signing key fingerprint...");
        verify_card_fingerprint("signature", RSA_SIGNING_FP);

        // Upload encryption subkey
        println!("Step 3: Uploading RSA encryption subkey...");
        upload_key_to_card(&secret_key, KEY_PASSWORD, CardKeySlot::Decryption, ADMIN_PIN)
            .expect("Failed to upload encryption key");

        // Verify encryption fingerprint
        println!("Step 4: Verifying encryption key fingerprint...");
        verify_card_fingerprint("encryption", RSA_ENCRYPT_FP);

        // Test signing
        println!("Step 5: Testing signing...");
        let msg = b"OpenPGP on smartcard with RSA4096.";
        let signature = sign_bytes_detached_on_card(msg, &public_key, USER_PIN)
            .expect("Failed to sign");
        println!("Signature created.");

        // Verify signature
        println!("Step 6: Verifying signature...");
        let is_valid = verify_bytes_detached(&public_key, msg, signature.as_bytes())
            .expect("Failed to verify signature");
        assert!(is_valid, "Signature verification failed");
        println!("✓ Signature verified successfully!");

        // Test encryption/decryption
        println!("Step 7: Testing encryption...");
        let encrypted = encrypt_bytes(&public_key, msg, true)
            .expect("Failed to encrypt");
        println!("Encrypted {} bytes", encrypted.len());

        println!("Step 8: Testing decryption on card...");
        let decrypted = decrypt_bytes_on_card(&encrypted, &public_key, USER_PIN)
            .expect("Failed to decrypt");
        assert_eq!(msg.to_vec(), decrypted, "Decryption mismatch");
        println!("✓ Decryption verified successfully!");

        println!("\n=== RSA full workflow completed successfully! ===");
    }

    /// Test full NIST P-256 workflow: upload subkeys, verify fingerprints, sign, decrypt
    #[test]
    #[ignore = "requires physical smart card"]
    fn test_nistp256_full_workflow() {
        reset_card_to_defaults();

        let secret_key = fs::read(NISTP256_SECRET_KEY)
            .expect("Failed to read NIST P-256 secret key");
        let public_key = fs::read(NISTP256_PUBLIC_KEY)
            .expect("Failed to read NIST P-256 public key");

        // Upload signing subkey
        println!("Step 1: Uploading NIST P-256 signing subkey...");
        upload_key_to_card(&secret_key, NIST_KEY_PASSWORD, CardKeySlot::Signing, ADMIN_PIN)
            .expect("Failed to upload signing key");

        // Verify signing fingerprint
        println!("Step 2: Verifying signing key fingerprint...");
        verify_card_fingerprint("signature", NISTP256_SIGNING_FP);

        // Upload encryption subkey
        println!("Step 3: Uploading NIST P-256 encryption subkey...");
        upload_key_to_card(&secret_key, NIST_KEY_PASSWORD, CardKeySlot::Decryption, ADMIN_PIN)
            .expect("Failed to upload encryption key");

        // Verify encryption fingerprint
        println!("Step 4: Verifying encryption key fingerprint...");
        verify_card_fingerprint("encryption", NISTP256_ENCRYPT_FP);

        // Test signing
        println!("Step 5: Testing signing...");
        let msg = b"OpenPGP on smartcard with NIST P-256.";
        let signature = sign_bytes_detached_on_card(msg, &public_key, USER_PIN)
            .expect("Failed to sign");
        println!("Signature created.");

        // Verify signature
        println!("Step 6: Verifying signature...");
        let is_valid = verify_bytes_detached(&public_key, msg, signature.as_bytes())
            .expect("Failed to verify signature");
        assert!(is_valid, "Signature verification failed");
        println!("✓ Signature verified successfully!");

        // Test encryption/decryption
        println!("Step 7: Testing encryption...");
        let encrypted = encrypt_bytes(&public_key, msg, true)
            .expect("Failed to encrypt");
        println!("Encrypted {} bytes", encrypted.len());

        println!("Step 8: Testing decryption on card...");
        let decrypted = decrypt_bytes_on_card(&encrypted, &public_key, USER_PIN)
            .expect("Failed to decrypt");
        assert_eq!(msg.to_vec(), decrypted, "Decryption mismatch");
        println!("✓ Decryption verified successfully!");

        println!("\n=== NIST P-256 full workflow completed successfully! ===");
    }

    /// Test full NIST P-384 workflow: upload subkeys, verify fingerprints, sign, decrypt
    #[test]
    #[ignore = "requires physical smart card"]
    fn test_nistp384_full_workflow() {
        reset_card_to_defaults();

        let secret_key = fs::read(NISTP384_SECRET_KEY)
            .expect("Failed to read NIST P-384 secret key");
        let public_key = fs::read(NISTP384_PUBLIC_KEY)
            .expect("Failed to read NIST P-384 public key");

        // Upload signing subkey
        println!("Step 1: Uploading NIST P-384 signing subkey...");
        upload_key_to_card(&secret_key, NIST_KEY_PASSWORD, CardKeySlot::Signing, ADMIN_PIN)
            .expect("Failed to upload signing key");

        // Verify signing fingerprint
        println!("Step 2: Verifying signing key fingerprint...");
        verify_card_fingerprint("signature", NISTP384_SIGNING_FP);

        // Upload encryption subkey
        println!("Step 3: Uploading NIST P-384 encryption subkey...");
        upload_key_to_card(&secret_key, NIST_KEY_PASSWORD, CardKeySlot::Decryption, ADMIN_PIN)
            .expect("Failed to upload encryption key");

        // Verify encryption fingerprint
        println!("Step 4: Verifying encryption key fingerprint...");
        verify_card_fingerprint("encryption", NISTP384_ENCRYPT_FP);

        // Test signing
        println!("Step 5: Testing signing...");
        let msg = b"OpenPGP on smartcard with NIST P-384.";
        let signature = sign_bytes_detached_on_card(msg, &public_key, USER_PIN)
            .expect("Failed to sign");
        println!("Signature created.");

        // Verify signature
        println!("Step 6: Verifying signature...");
        let is_valid = verify_bytes_detached(&public_key, msg, signature.as_bytes())
            .expect("Failed to verify signature");
        assert!(is_valid, "Signature verification failed");
        println!("✓ Signature verified successfully!");

        // Test encryption/decryption
        println!("Step 7: Testing encryption...");
        let encrypted = encrypt_bytes(&public_key, msg, true)
            .expect("Failed to encrypt");
        println!("Encrypted {} bytes", encrypted.len());

        println!("Step 8: Testing decryption on card...");
        let decrypted = decrypt_bytes_on_card(&encrypted, &public_key, USER_PIN)
            .expect("Failed to decrypt");
        assert_eq!(msg.to_vec(), decrypted, "Decryption mismatch");
        println!("✓ Decryption verified successfully!");

        println!("\n=== NIST P-384 full workflow completed successfully! ===");
    }

    /// Test NIST P-521 upload: upload subkeys, verify fingerprints
    /// Note: YubiKey does NOT support P-521 operations, so we only test key upload
    /// and fingerprint verification. The signing/decryption steps are skipped.
    #[test]
    #[ignore = "requires physical smart card"]
    fn test_nistp521_upload_workflow() {
        reset_card_to_defaults();

        let secret_key = fs::read(NISTP521_SECRET_KEY)
            .expect("Failed to read NIST P-521 secret key");
        let _public_key = fs::read(NISTP521_PUBLIC_KEY)
            .expect("Failed to read NIST P-521 public key");

        // Upload signing subkey
        println!("Step 1: Uploading NIST P-521 signing subkey...");
        upload_key_to_card(&secret_key, NIST_KEY_PASSWORD, CardKeySlot::Signing, ADMIN_PIN)
            .expect("Failed to upload signing key");

        // Verify signing fingerprint
        println!("Step 2: Verifying signing key fingerprint...");
        verify_card_fingerprint("signature", NISTP521_SIGNING_FP);

        // Upload encryption subkey
        println!("Step 3: Uploading NIST P-521 encryption subkey...");
        upload_key_to_card(&secret_key, NIST_KEY_PASSWORD, CardKeySlot::Decryption, ADMIN_PIN)
            .expect("Failed to upload encryption key");

        // Verify encryption fingerprint
        println!("Step 4: Verifying encryption key fingerprint...");
        verify_card_fingerprint("encryption", NISTP521_ENCRYPT_FP);

        // Note: YubiKey doesn't support P-521 for signing/decryption operations
        // The key upload and fingerprint verification prove our code works correctly
        println!("\nNote: Skipping sign/decrypt tests - YubiKey doesn't support P-521 operations");

        println!("\n=== NIST P-521 upload workflow completed successfully! ===");
    }

    /// Test primary key signing workflow (like smartcards_for_primary.py)
    #[test]
    #[ignore = "requires physical smart card"]
    fn test_primary_key_signing_workflow() {
        reset_card_to_defaults();

        let secret_key = fs::read(CV25519_SECRET_KEY)
            .expect("Failed to read CV25519 secret key");
        let public_key = fs::read(CV25519_PUBLIC_KEY)
            .expect("Failed to read CV25519 public key");

        // Upload PRIMARY key to signing slot (not subkey!)
        println!("Step 1: Uploading PRIMARY key to signing slot...");
        upload_primary_key_to_card(&secret_key, KEY_PASSWORD, CardKeySlot::Signing, ADMIN_PIN)
            .expect("Failed to upload primary key");

        // Verify PRIMARY key fingerprint (not subkey!)
        println!("Step 2: Verifying PRIMARY key fingerprint on card...");
        verify_card_fingerprint("signature", CV25519_PRIMARY_FP);

        // Upload encryption subkey
        println!("Step 3: Uploading encryption subkey...");
        upload_key_to_card(&secret_key, KEY_PASSWORD, CardKeySlot::Decryption, ADMIN_PIN)
            .expect("Failed to upload encryption key");

        // Verify encryption fingerprint
        println!("Step 4: Verifying encryption key fingerprint...");
        verify_card_fingerprint("encryption", CV25519_ENCRYPT_FP);

        // Test signing with PRIMARY key
        println!("Step 5: Testing signing with PRIMARY key...");
        let msg = b"Signed with primary key on smartcard.";
        let signature = sign_bytes_detached_on_card(msg, &public_key, USER_PIN)
            .expect("Failed to sign with primary key");
        println!("Signature created with primary key.");

        // Verify signature
        println!("Step 6: Verifying signature...");
        let is_valid = verify_bytes_detached(&public_key, msg, signature.as_bytes())
            .expect("Failed to verify signature");
        assert!(is_valid, "Signature verification failed");
        println!("✓ Primary key signature verified successfully!");

        println!("\n=== Primary key signing workflow completed successfully! ===");
    }

    // ==================== Basic Signing Tests ====================

    #[test]
    #[ignore = "requires physical smart card"]
    fn test_sign_bytes_cv25519() {
        reset_card_to_defaults();

        let secret_key = fs::read(CV25519_SECRET_KEY)
            .expect("Failed to read CV25519 secret key");
        let public_key = fs::read(CV25519_PUBLIC_KEY)
            .expect("Failed to read CV25519 public key");

        println!("Uploading CV25519 signing key to card...");
        upload_key_to_card(&secret_key, KEY_PASSWORD, CardKeySlot::Signing, ADMIN_PIN)
            .expect("Failed to upload signing key");

        let message = b"OpenPGP on smartcard with CV25519.";

        println!("Signing message with CV25519 key on card...");
        let signature = sign_bytes_detached_on_card(message, &public_key, USER_PIN)
            .expect("Failed to sign on card");

        println!("Signature created:");
        println!("{}", signature);

        let is_valid = verify_bytes_detached(&public_key, message, signature.as_bytes())
            .expect("Failed to verify signature");

        assert!(is_valid, "Signature verification failed");
        println!("Signature verified successfully!");
    }

    #[test]
    #[ignore = "requires physical smart card"]
    fn test_sign_bytes_rsa() {
        reset_card_to_defaults();

        let secret_key = fs::read(RSA_SECRET_KEY)
            .expect("Failed to read RSA secret key");
        let public_key = fs::read(RSA_PUBLIC_KEY)
            .expect("Failed to read RSA public key");

        println!("Uploading RSA signing key to card...");
        upload_key_to_card(&secret_key, KEY_PASSWORD, CardKeySlot::Signing, ADMIN_PIN)
            .expect("Failed to upload signing key");

        let message = b"OpenPGP on smartcard with RSA4096.";

        println!("Signing message with RSA key on card...");
        let signature = sign_bytes_detached_on_card(message, &public_key, USER_PIN)
            .expect("Failed to sign on card");

        println!("Signature created:");
        println!("{}", signature);

        let is_valid = verify_bytes_detached(&public_key, message, signature.as_bytes())
            .expect("Failed to verify signature");

        assert!(is_valid, "Signature verification failed");
        println!("Signature verified successfully!");
    }

    // ==================== Basic Decryption Tests ====================

    #[test]
    #[ignore = "requires physical smart card"]
    fn test_decrypt_bytes_cv25519() {
        reset_card_to_defaults();

        let secret_key = fs::read(CV25519_SECRET_KEY)
            .expect("Failed to read CV25519 secret key");
        let public_key = fs::read(CV25519_PUBLIC_KEY)
            .expect("Failed to read CV25519 public key");

        println!("Uploading CV25519 decryption key to card...");
        upload_key_to_card(&secret_key, KEY_PASSWORD, CardKeySlot::Decryption, ADMIN_PIN)
            .expect("Failed to upload decryption key");

        let message = b"Secret message for CV25519 card decryption.";

        println!("Encrypting message to CV25519 key...");
        let encrypted = encrypt_bytes(&public_key, message, true)
            .expect("Failed to encrypt");

        println!("Encrypted message length: {} bytes", encrypted.len());

        println!("Decrypting with card...");
        let decrypted = decrypt_bytes_on_card(&encrypted, &public_key, USER_PIN)
            .expect("Failed to decrypt on card");

        assert_eq!(message.to_vec(), decrypted, "Decrypted message doesn't match original");
        println!("Decryption successful!");
        println!("Original:  {:?}", String::from_utf8_lossy(message));
        println!("Decrypted: {:?}", String::from_utf8_lossy(&decrypted));
    }

    #[test]
    #[ignore = "requires physical smart card"]
    fn test_decrypt_bytes_rsa() {
        reset_card_to_defaults();

        let secret_key = fs::read(RSA_SECRET_KEY)
            .expect("Failed to read RSA secret key");
        let public_key = fs::read(RSA_PUBLIC_KEY)
            .expect("Failed to read RSA public key");

        println!("Uploading RSA decryption key to card...");
        upload_key_to_card(&secret_key, KEY_PASSWORD, CardKeySlot::Decryption, ADMIN_PIN)
            .expect("Failed to upload decryption key");

        let message = b"Secret message for RSA4096 card decryption.";

        println!("Encrypting message to RSA key...");
        let encrypted = encrypt_bytes(&public_key, message, true)
            .expect("Failed to encrypt");

        println!("Encrypted message length: {} bytes", encrypted.len());

        println!("Decrypting with card...");
        let decrypted = decrypt_bytes_on_card(&encrypted, &public_key, USER_PIN)
            .expect("Failed to decrypt on card");

        assert_eq!(message.to_vec(), decrypted, "Decrypted message doesn't match original");
        println!("Decryption successful!");
        println!("Original:  {:?}", String::from_utf8_lossy(message));
        println!("Decrypted: {:?}", String::from_utf8_lossy(&decrypted));
    }

    // ==================== Round-trip Tests ====================

    #[test]
    #[ignore = "requires physical smart card"]
    fn test_sign_and_verify_roundtrip_cv25519() {
        reset_card_to_defaults();

        let secret_key = fs::read(CV25519_SECRET_KEY)
            .expect("Failed to read CV25519 secret key");
        let public_key = fs::read(CV25519_PUBLIC_KEY)
            .expect("Failed to read CV25519 public key");

        upload_key_to_card(&secret_key, KEY_PASSWORD, CardKeySlot::Signing, ADMIN_PIN)
            .expect("Failed to upload signing key");

        let messages: Vec<&[u8]> = vec![
            b"Short",
            b"A medium length message for testing.",
            b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. \
              Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.",
        ];

        for (i, message) in messages.iter().enumerate() {
            println!("Test {}: message length = {} bytes", i + 1, message.len());

            let signature = sign_bytes_detached_on_card(message, &public_key, USER_PIN)
                .expect("Failed to sign");

            let is_valid = verify_bytes_detached(&public_key, message, signature.as_bytes())
                .expect("Failed to verify");

            assert!(is_valid, "Signature verification failed for message {}", i + 1);
            println!("  Signature verified");
        }
    }

    #[test]
    #[ignore = "requires physical smart card"]
    fn test_encrypt_decrypt_roundtrip_rsa() {
        reset_card_to_defaults();

        let secret_key = fs::read(RSA_SECRET_KEY)
            .expect("Failed to read RSA secret key");
        let public_key = fs::read(RSA_PUBLIC_KEY)
            .expect("Failed to read RSA public key");

        upload_key_to_card(&secret_key, KEY_PASSWORD, CardKeySlot::Decryption, ADMIN_PIN)
            .expect("Failed to upload decryption key");

        let messages: Vec<&[u8]> = vec![
            b"Short",
            b"A medium length message for testing.",
            b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. \
              Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.",
        ];

        for (i, message) in messages.iter().enumerate() {
            println!("Test {}: message length = {} bytes", i + 1, message.len());

            let encrypted = encrypt_bytes(&public_key, message, true)
                .expect("Failed to encrypt");

            let decrypted = decrypt_bytes_on_card(&encrypted, &public_key, USER_PIN)
                .expect("Failed to decrypt");

            assert_eq!(message.to_vec(), decrypted, "Decryption mismatch for message {}", i + 1);
            println!("  Decryption verified");
        }
    }

    // ==================== Error Handling Tests ====================

    #[test]
    #[ignore = "requires physical smart card"]
    fn test_wrong_pin_error() {
        let result = verify_user_pin(b"000000");

        match result {
            Ok(_) => panic!("Should have failed with wrong PIN"),
            Err(e) => {
                println!("Expected error with wrong PIN: {}", e);
                let error_str = format!("{}", e);
                assert!(
                    error_str.contains("PIN")
                        || error_str.contains("Password")
                        || error_str.contains("63C")
                        || error_str.contains("retries"),
                    "Error should mention PIN/Password or return status 63Cx: {}",
                    error_str
                );
            }
        }
    }

    #[test]
    fn test_no_card_connected() {
        let connected = is_card_connected();
        if !connected {
            println!("No card connected - testing error handling");

            let result = get_card_details();
            assert!(result.is_err(), "Should return error when no card connected");

            let error = result.unwrap_err();
            println!("Error when no card: {}", error);
        } else {
            println!("Card is connected - skipping no-card test");
        }
    }

    // ==================== Key Expiry Update Tests ====================

    /// Test updating primary key expiry using the card.
    /// This test uploads the primary key to the card, then updates the expiry.
    #[test]
    #[ignore = "requires physical smart card - will reset card"]
    fn test_update_primary_expiry_on_card_cv25519() {
        use wecanencrypt::parse_cert_bytes;

        println!("\n=== Testing Primary Key Expiry Update (CV25519) ===\n");

        // 1. Reset card to factory defaults
        reset_card_to_defaults();

        // 2. Read the test keys
        let secret_key = fs::read(CV25519_SECRET_KEY).expect("Failed to read secret key");
        let public_key = fs::read(CV25519_PUBLIC_KEY).expect("Failed to read public key");

        // 3. Upload primary key to card's signature slot
        println!("Uploading primary key to card...");
        upload_primary_key_to_card(&secret_key, KEY_PASSWORD, CardKeySlot::Signing, ADMIN_PIN)
            .expect("Failed to upload primary key");
        verify_card_fingerprint("signature", CV25519_PRIMARY_FP);

        // 4. Get original expiry info
        let original_info = parse_cert_bytes(&public_key, true)
            .expect("Failed to parse original certificate");
        println!("Original certificate info:");
        println!("  Primary fingerprint: {}", original_info.fingerprint);
        println!("  Expiration: {:?}", original_info.expiration_time);

        // 5. Update primary key expiry (1 year from now = ~31536000 seconds)
        println!("\nUpdating primary key expiry to 1 year from now...");
        let one_year_seconds: u64 = 365 * 24 * 60 * 60;
        let updated_cert = update_primary_expiry_on_card(&public_key, one_year_seconds, USER_PIN)
            .expect("Failed to update primary expiry on card");

        // 6. Verify the updated certificate
        let updated_info = parse_cert_bytes(&updated_cert, true)
            .expect("Failed to parse updated certificate");
        println!("\nUpdated certificate info:");
        println!("  Primary fingerprint: {}", updated_info.fingerprint);
        println!("  Expiration: {:?}", updated_info.expiration_time);

        // Verify fingerprint is unchanged
        assert_eq!(
            original_info.fingerprint, updated_info.fingerprint,
            "Fingerprint should not change when updating expiry"
        );

        // Verify expiration is now set (was previously None or different)
        assert!(
            updated_info.expiration_time.is_some(),
            "Updated certificate should have an expiration date"
        );

        println!("\n✓ Primary key expiry update successful!");
    }

    /// Test updating subkey expiry using the card.
    /// This test uploads the primary key to the card, then updates subkey expiry.
    #[test]
    #[ignore = "requires physical smart card - will reset card"]
    fn test_update_subkeys_expiry_on_card_cv25519() {
        use wecanencrypt::parse_cert_bytes;

        println!("\n=== Testing Subkey Expiry Update (CV25519) ===\n");

        // 1. Reset card to factory defaults
        reset_card_to_defaults();

        // 2. Read the test keys
        let secret_key = fs::read(CV25519_SECRET_KEY).expect("Failed to read secret key");
        let public_key = fs::read(CV25519_PUBLIC_KEY).expect("Failed to read public key");

        // 3. Upload primary key to card's signature slot
        println!("Uploading primary key to card...");
        upload_primary_key_to_card(&secret_key, KEY_PASSWORD, CardKeySlot::Signing, ADMIN_PIN)
            .expect("Failed to upload primary key");
        verify_card_fingerprint("signature", CV25519_PRIMARY_FP);

        // 4. Get original certificate info including subkeys
        let original_info = parse_cert_bytes(&public_key, true)
            .expect("Failed to parse original certificate");
        println!("Original certificate info:");
        println!("  Primary fingerprint: {}", original_info.fingerprint);
        println!("  Number of subkeys: {}", original_info.subkeys.len());
        for sk in &original_info.subkeys {
            println!("    - {} (expires: {:?})", sk.fingerprint, sk.expiration_time);
        }

        // 5. Get subkey fingerprints to update
        let subkey_fps: Vec<&str> = original_info.subkeys
            .iter()
            .map(|sk| sk.fingerprint.as_str())
            .collect();
        println!("\nSubkey fingerprints to update: {:?}", subkey_fps);

        // 6. Update subkey expiry (6 months from now)
        println!("\nUpdating subkey expiry to 6 months from now...");
        let six_months_seconds: u64 = 180 * 24 * 60 * 60;
        let updated_cert = update_subkeys_expiry_on_card(
            &public_key,
            &subkey_fps,
            six_months_seconds,
            USER_PIN,
        ).expect("Failed to update subkeys expiry on card");

        // 7. Verify the updated certificate
        let updated_info = parse_cert_bytes(&updated_cert, true)
            .expect("Failed to parse updated certificate");
        println!("\nUpdated certificate info:");
        println!("  Primary fingerprint: {}", updated_info.fingerprint);
        println!("  Number of subkeys: {}", updated_info.subkeys.len());
        for sk in &updated_info.subkeys {
            println!("    - {} (expires: {:?})", sk.fingerprint, sk.expiration_time);
        }

        // Verify fingerprint is unchanged
        assert_eq!(
            original_info.fingerprint, updated_info.fingerprint,
            "Primary fingerprint should not change"
        );

        // Verify subkey count is unchanged
        assert_eq!(
            original_info.subkeys.len(), updated_info.subkeys.len(),
            "Number of subkeys should not change"
        );

        // Verify all updated subkeys now have expiration
        for sk in &updated_info.subkeys {
            assert!(
                sk.expiration_time.is_some(),
                "Updated subkey {} should have an expiration date",
                sk.fingerprint
            );
        }

        println!("\n✓ Subkey expiry update successful!");
    }

    /// Test updating both primary and subkey expiry in sequence.
    #[test]
    #[ignore = "requires physical smart card - will reset card"]
    fn test_update_full_key_expiry_on_card_cv25519() {
        use wecanencrypt::parse_cert_bytes;

        println!("\n=== Testing Full Key Expiry Update (CV25519) ===\n");

        // 1. Reset card to factory defaults
        reset_card_to_defaults();

        // 2. Read the test keys
        let secret_key = fs::read(CV25519_SECRET_KEY).expect("Failed to read secret key");
        let public_key = fs::read(CV25519_PUBLIC_KEY).expect("Failed to read public key");

        // 3. Upload primary key to card's signature slot
        println!("Uploading primary key to card...");
        upload_primary_key_to_card(&secret_key, KEY_PASSWORD, CardKeySlot::Signing, ADMIN_PIN)
            .expect("Failed to upload primary key");
        verify_card_fingerprint("signature", CV25519_PRIMARY_FP);

        // 4. Update primary key expiry first
        println!("\nStep 1: Updating primary key expiry...");
        let one_year_seconds: u64 = 365 * 24 * 60 * 60;
        let updated_with_primary = update_primary_expiry_on_card(&public_key, one_year_seconds, USER_PIN)
            .expect("Failed to update primary expiry");

        // 5. Get subkey fingerprints
        let info = parse_cert_bytes(&updated_with_primary, true)
            .expect("Failed to parse certificate");
        let subkey_fps: Vec<&str> = info.subkeys
            .iter()
            .map(|sk| sk.fingerprint.as_str())
            .collect();

        // 6. Update subkey expiry
        println!("\nStep 2: Updating subkey expiry...");
        let updated_full = update_subkeys_expiry_on_card(
            &updated_with_primary,
            &subkey_fps,
            one_year_seconds,
            USER_PIN,
        ).expect("Failed to update subkeys expiry");

        // 7. Verify final certificate
        let final_info = parse_cert_bytes(&updated_full, true)
            .expect("Failed to parse final certificate");
        println!("\nFinal certificate info:");
        println!("  Primary fingerprint: {}", final_info.fingerprint);
        println!("  Primary expiration: {:?}", final_info.expiration_time);
        for sk in &final_info.subkeys {
            println!("    - {} (expires: {:?})", sk.fingerprint, sk.expiration_time);
        }

        // Verify all keys have expiration
        assert!(final_info.expiration_time.is_some(), "Primary key should have expiration");
        for sk in &final_info.subkeys {
            assert!(sk.expiration_time.is_some(), "Subkey {} should have expiration", sk.fingerprint);
        }

        println!("\n✓ Full key expiry update successful!");
    }
}
