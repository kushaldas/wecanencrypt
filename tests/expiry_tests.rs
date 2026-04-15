//! Tests for key expiry functionality.
//!
//! These tests port the expiry-related tests from johnnycanencrypt's test suite.

use std::path::PathBuf;

use chrono::{Duration, NaiveDate, Utc};
use wecanencrypt::{
    add_uid, certify_key, create_key, create_key_simple, get_pub_key, parse_cert_bytes,
    revoke_key, revoke_uid, sign_bytes_detached, update_primary_expiry,
    update_subkeys_expiry, CertificationType, CipherSuite, Error, SubkeyFlags,
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
    std::fs::read(path).unwrap_or_else(|_| panic!("Failed to read file: {:?}", path))
}

// =============================================================================
// Tests using existing update_*_expiry functions (should pass without code changes)
// =============================================================================

/// Port of JCE test_rust.py::test_update_primary_expiry_in_cert
#[test]
fn test_update_primary_expiry_with_fixture() {
    // Known values from the fixture key
    let expected_creation = NaiveDate::from_ymd_opt(2025, 1, 22).unwrap();
    let expected_expiry = NaiveDate::from_ymd_opt(2026, 1, 22).unwrap();

    let keypath = store_dir().join("363F0180891AB46098F4463864AB0060FAB80A18.sec");
    let keydata = read_file(&keypath);

    // Verify initial dates
    let info = parse_cert_bytes(&keydata, false).unwrap();
    assert_eq!(info.creation_time.date_naive(), expected_creation);
    assert_eq!(info.expiration_time.unwrap().date_naive(), expected_expiry);
    assert!(info.can_primary_sign);

    // Update primary expiry to 2050-10-25
    let new_expiry = chrono::NaiveDate::from_ymd_opt(2050, 10, 25)
        .unwrap()
        .and_hms_opt(10, 0, 0)
        .unwrap()
        .and_utc();
    let updated = update_primary_expiry(&keydata, new_expiry, "redhat").unwrap();

    // Verify creation preserved, expiry updated
    let updated_info = parse_cert_bytes(&updated, true).unwrap();
    assert_eq!(updated_info.creation_time.date_naive(), expected_creation);
    assert_eq!(
        updated_info.expiration_time.unwrap().date_naive(),
        NaiveDate::from_ymd_opt(2050, 10, 25).unwrap()
    );
}

#[test]
fn test_expired_key_cannot_sign_data_but_can_extend_expiry() {
    let keypath = store_dir().join("363F0180891AB46098F4463864AB0060FAB80A18.sec");
    let keydata = read_file(&keypath);

    let sign_result = sign_bytes_detached(&keydata, b"fresh data", "redhat");
    assert!(matches!(sign_result, Err(Error::KeyExpired)));

    let new_expiry = chrono::NaiveDate::from_ymd_opt(2050, 10, 25)
        .unwrap()
        .and_hms_opt(10, 0, 0)
        .unwrap()
        .and_utc();
    let updated = update_primary_expiry(&keydata, new_expiry, "redhat").unwrap();

    let updated_info = parse_cert_bytes(&updated, true).unwrap();
    assert_eq!(
        updated_info.expiration_time.unwrap().date_naive(),
        NaiveDate::from_ymd_opt(2050, 10, 25).unwrap()
    );

    let post_update_sign = sign_bytes_detached(&updated, b"fresh data", "redhat");
    assert!(post_update_sign.is_ok());
}

#[test]
fn test_expired_key_can_do_self_maintenance_but_not_third_party_certification() {
    let keypath = store_dir().join("363F0180891AB46098F4463864AB0060FAB80A18.sec");
    let keydata = read_file(&keypath);

    let with_uid = add_uid(&keydata, "Expiry Maint <expiry@example.com>", "redhat").unwrap();
    let with_uid_info = parse_cert_bytes(&with_uid, true).unwrap();
    assert!(
        with_uid_info
            .user_ids
            .iter()
            .any(|uid| uid.value == "Expiry Maint <expiry@example.com>"),
    );

    let revoked_uid = revoke_uid(&with_uid, "Expiry Maint <expiry@example.com>", "redhat")
        .unwrap();
    let revoked_uid_info = parse_cert_bytes(&revoked_uid, true).unwrap();
    assert!(
        revoked_uid_info
            .user_ids
            .iter()
            .any(|uid| uid.value == "Expiry Maint <expiry@example.com>" && uid.revoked),
    );

    let target = create_key_simple("redhat", &["Target <target@example.com>"]).unwrap();
    let target_pub = get_pub_key(&target.secret_key).unwrap();
    let certification = certify_key(
        &keydata,
        target_pub.as_bytes(),
        CertificationType::Casual,
        None,
        "redhat",
    );
    assert!(matches!(certification, Err(Error::KeyExpired)));
}

/// Port of JCE test_keystore.py::test_ks_update_expiry_time_for_subkeys
#[test]
fn test_update_subkey_expiry_with_fixture() {
    let keypath = store_dir().join("secret.asc");
    let keydata = read_file(&keypath);

    let subkey_fp = "102EBD23BD5D2D340FBBDE0ADFD1C55926648D2F";
    let new_expiry = chrono::NaiveDate::from_ymd_opt(2050, 10, 25)
        .unwrap()
        .and_hms_opt(10, 0, 0)
        .unwrap()
        .and_utc();

    let updated = update_subkeys_expiry(&keydata, &[subkey_fp], new_expiry, "redhat").unwrap();

    let updated_info = parse_cert_bytes(&updated, true).unwrap();
    for subkey in &updated_info.subkeys {
        if subkey.fingerprint == subkey_fp {
            assert_eq!(
                subkey.expiration_time.unwrap().date_naive(),
                NaiveDate::from_ymd_opt(2050, 10, 25).unwrap()
            );
        }
    }
}

/// Port of JCE test_keystore.py::test_ks_update_expiry_time_for_primary
#[test]
fn test_update_primary_expiry_fixture_key() {
    let keypath = store_dir().join("secret.asc");
    let keydata = read_file(&keypath);

    let new_expiry = chrono::NaiveDate::from_ymd_opt(2050, 10, 25)
        .unwrap()
        .and_hms_opt(10, 0, 0)
        .unwrap()
        .and_utc();

    let updated = update_primary_expiry(&keydata, new_expiry, "redhat").unwrap();

    let updated_info = parse_cert_bytes(&updated, true).unwrap();
    assert!(updated_info.expiration_time.is_some());
    assert_eq!(
        updated_info.expiration_time.unwrap().date_naive(),
        NaiveDate::from_ymd_opt(2050, 10, 25).unwrap()
    );
}

#[test]
fn test_revoked_key_cannot_sign_or_extend_expiry() {
    let key = create_key_simple("redhat", &["Revoked <revoked@example.com>"]).unwrap();
    let revoked = revoke_key(&key.secret_key, "redhat").unwrap();

    let sign_result = sign_bytes_detached(&revoked, b"fresh data", "redhat");
    assert!(matches!(sign_result, Err(Error::KeyRevoked)));

    let new_expiry = chrono::NaiveDate::from_ymd_opt(2050, 10, 25)
        .unwrap()
        .and_hms_opt(10, 0, 0)
        .unwrap()
        .and_utc();

    let primary_update = update_primary_expiry(&revoked, new_expiry, "redhat");
    assert!(matches!(primary_update, Err(Error::KeyRevoked)));

    let info = parse_cert_bytes(&revoked, true).unwrap();
    let subkey_fps: Vec<&str> = info.subkeys.iter().map(|s| s.fingerprint.as_str()).collect();
    let subkey_update = update_subkeys_expiry(&revoked, &subkey_fps, new_expiry, "redhat");
    assert!(matches!(subkey_update, Err(Error::KeyRevoked)));

    let add_uid_result = add_uid(&revoked, "Revoked Extra <revoked2@example.com>", "redhat");
    assert!(matches!(add_uid_result, Err(Error::KeyRevoked)));

    let first_uid = info.user_ids.first().unwrap().value.clone();
    let revoke_uid_result = revoke_uid(&revoked, &first_uid, "redhat");
    assert!(matches!(revoke_uid_result, Err(Error::KeyRevoked)));

    let target = create_key_simple("redhat", &["Target <target@example.com>"]).unwrap();
    let target_pub = get_pub_key(&target.secret_key).unwrap();
    let certification = certify_key(
        &revoked,
        target_pub.as_bytes(),
        CertificationType::Casual,
        None,
        "redhat",
    );
    assert!(matches!(certification, Err(Error::KeyRevoked)));
}

/// Port of JCE test_keystore.py::test_update_subkey_expiry_time (duration-based)
#[test]
fn test_update_subkey_expiry_duration() {
    let keypath = store_dir().join("secret.asc");
    let keydata = read_file(&keypath);

    let subkey_fp = "102EBD23BD5D2D340FBBDE0ADFD1C55926648D2F";
    let tomorrow = Utc::now() + Duration::days(1);

    let updated = update_subkeys_expiry(&keydata, &[subkey_fp], tomorrow, "redhat").unwrap();

    let updated_info = parse_cert_bytes(&updated, true).unwrap();
    let tomorrow_date = (Utc::now() + Duration::days(1)).date_naive();
    for subkey in &updated_info.subkeys {
        if subkey.fingerprint == subkey_fp {
            assert_eq!(subkey.expiration_time.unwrap().date_naive(), tomorrow_date);
        }
    }
}

/// Port of JCE error case: passing past date for expiry should fail
#[test]
fn test_update_subkey_expiry_past_fails() {
    let keypath = store_dir().join("secret.asc");
    let keydata = read_file(&keypath);

    let subkey_fp = "102EBD23BD5D2D340FBBDE0ADFD1C55926648D2F";
    let past = chrono::NaiveDate::from_ymd_opt(2000, 1, 1)
        .unwrap()
        .and_hms_opt(0, 0, 0)
        .unwrap()
        .and_utc();

    let result = update_subkeys_expiry(&keydata, &[subkey_fp], past, "redhat");
    assert!(result.is_err());
}

/// Port of JCE test_keystore.py::test_create_primary_key_with_encryption
#[test]
fn test_create_primary_key_with_sign() {
    let key = create_key(
        "redhat",
        &["test key42 <42@example.com>"],
        CipherSuite::Cv25519,
        None,
        None,
        None,
        SubkeyFlags::encryption_only(),
        true, // can_primary_sign
        true,
    )
    .unwrap();

    let info = parse_cert_bytes(&key.secret_key, true).unwrap();
    assert!(info.can_primary_sign);
}

// =============================================================================
// Tests that require the create_key() fix (creation_time, expiration_time, etc.)
// =============================================================================

/// Port of JCE test_keystore.py::test_ks_creation_expiration_time (creation time part)
#[test]
fn test_create_key_with_creation_time() {
    let ctime = chrono::NaiveDate::from_ymd_opt(2010, 10, 10)
        .unwrap()
        .and_hms_opt(20, 53, 47)
        .unwrap()
        .and_utc();

    let key = create_key(
        "redhat",
        &["Another test key <test@example.com>"],
        CipherSuite::Cv25519,
        Some(ctime),
        None,
        None,
        SubkeyFlags::all(),
        false,
        true,
    )
    .unwrap();

    let info = parse_cert_bytes(&key.secret_key, true).unwrap();
    assert_eq!(
        info.creation_time.date_naive(),
        NaiveDate::from_ymd_opt(2010, 10, 10).unwrap()
    );
    assert!(info.expiration_time.is_none());
}

/// Port of JCE test_keystore.py::test_ks_creation_expiration_time (primary expiry part)
#[test]
fn test_create_key_with_primary_expiration() {
    let etime = chrono::NaiveDate::from_ymd_opt(2035, 12, 15)
        .unwrap()
        .and_hms_opt(20, 53, 47)
        .unwrap()
        .and_utc();

    let key = create_key(
        "redhat",
        &["Another test key <test@example.com>"],
        CipherSuite::Cv25519,
        None,
        Some(etime),
        None,
        SubkeyFlags::all(),
        false,
        true, // can_primary_expire
    )
    .unwrap();

    let info = parse_cert_bytes(&key.secret_key, true).unwrap();
    assert_eq!(info.creation_time.date_naive(), Utc::now().date_naive());
    assert_eq!(
        info.expiration_time.unwrap().date_naive(),
        NaiveDate::from_ymd_opt(2035, 12, 15).unwrap()
    );
}

/// Port of JCE test_keystore.py::test_ks_creation_expiration_time (subkeys expiry part)
#[test]
fn test_create_key_with_subkeys_expiration() {
    let ctime = chrono::NaiveDate::from_ymd_opt(2008, 10, 10)
        .unwrap()
        .and_hms_opt(20, 53, 47)
        .unwrap()
        .and_utc();
    let etime = chrono::NaiveDate::from_ymd_opt(2029, 12, 15)
        .unwrap()
        .and_hms_opt(20, 53, 47)
        .unwrap()
        .and_utc();

    let key = create_key(
        "redhat",
        &["Test key with subkey expiration <test@example.com>"],
        CipherSuite::Cv25519,
        Some(ctime),
        Some(etime),
        Some(etime), // subkeys_expiration
        SubkeyFlags::all(),
        false,
        false, // can_primary_expire = false
    )
    .unwrap();

    let info = parse_cert_bytes(&key.secret_key, true).unwrap();
    assert_eq!(
        info.creation_time.date_naive(),
        NaiveDate::from_ymd_opt(2008, 10, 10).unwrap()
    );

    // Verify all subkeys have the expiry date
    for subkey in &info.subkeys {
        assert!(
            subkey.expiration_time.is_some(),
            "Subkey {} should have expiration",
            subkey.fingerprint
        );
        assert_eq!(
            subkey.expiration_time.unwrap().date_naive(),
            NaiveDate::from_ymd_opt(2029, 12, 15).unwrap()
        );
    }
}

/// Port of JCE: subkeys expire but primary does NOT
#[test]
fn test_create_key_subkeys_only_expiration() {
    let etime = chrono::NaiveDate::from_ymd_opt(2030, 6, 5)
        .unwrap()
        .and_hms_opt(20, 53, 47)
        .unwrap()
        .and_utc();

    let key = create_key(
        "redhat",
        &["Test key with subkey expiration <test@example.com>"],
        CipherSuite::Cv25519,
        None,
        Some(etime),
        Some(etime),
        SubkeyFlags::all(),
        false,
        false, // can_primary_expire = false, so primary should NOT expire
    )
    .unwrap();

    let info = parse_cert_bytes(&key.secret_key, true).unwrap();
    assert_eq!(info.creation_time.date_naive(), Utc::now().date_naive());
    assert!(info.expiration_time.is_none(), "Primary should NOT expire");

    for subkey in &info.subkeys {
        assert!(
            subkey.expiration_time.is_some(),
            "Subkey {} should have expiration",
            subkey.fingerprint
        );
        assert_eq!(
            subkey.expiration_time.unwrap().date_naive(),
            NaiveDate::from_ymd_opt(2030, 6, 5).unwrap()
        );
    }
}

/// Port of JCE: both primary and subkeys expire at same date
#[test]
fn test_create_key_both_primary_and_subkeys_expire() {
    let etime = chrono::NaiveDate::from_ymd_opt(2030, 6, 5)
        .unwrap()
        .and_hms_opt(20, 53, 47)
        .unwrap()
        .and_utc();

    let key = create_key(
        "redhat",
        &["Test key with subkey expiration <test@example.com>"],
        CipherSuite::Cv25519,
        None,
        Some(etime),
        Some(etime),
        SubkeyFlags::all(),
        false,
        true, // can_primary_expire = true
    )
    .unwrap();

    let info = parse_cert_bytes(&key.secret_key, true).unwrap();
    assert_eq!(info.creation_time.date_naive(), Utc::now().date_naive());
    assert_eq!(
        info.expiration_time.unwrap().date_naive(),
        NaiveDate::from_ymd_opt(2030, 6, 5).unwrap()
    );

    for subkey in &info.subkeys {
        assert!(
            subkey.expiration_time.is_some(),
            "Subkey {} should have expiration",
            subkey.fingerprint
        );
        assert_eq!(
            subkey.expiration_time.unwrap().date_naive(),
            NaiveDate::from_ymd_opt(2030, 6, 5).unwrap()
        );
    }
}

/// Port of JCE: custom creation time + primary expiry together
#[test]
fn test_create_key_with_creation_and_primary_expiry() {
    let ctime = chrono::NaiveDate::from_ymd_opt(2008, 10, 10)
        .unwrap()
        .and_hms_opt(20, 53, 47)
        .unwrap()
        .and_utc();
    let etime = chrono::NaiveDate::from_ymd_opt(2025, 12, 15)
        .unwrap()
        .and_hms_opt(20, 53, 47)
        .unwrap()
        .and_utc();

    let key = create_key(
        "redhat",
        &["Another test key <test@example.com>"],
        CipherSuite::Cv25519,
        Some(ctime),
        Some(etime),
        None,
        SubkeyFlags::all(),
        false,
        true,
    )
    .unwrap();

    let info = parse_cert_bytes(&key.secret_key, true).unwrap();
    assert_eq!(
        info.creation_time.date_naive(),
        NaiveDate::from_ymd_opt(2008, 10, 10).unwrap()
    );
    assert_eq!(
        info.expiration_time.unwrap().date_naive(),
        NaiveDate::from_ymd_opt(2025, 12, 15).unwrap()
    );
}
