//! Fixture-driven V6 (RFC 9580) tests.
//!
//! These tests load committed V6 artifacts from `tests/fixtures/v6/` and
//! verify the library can parse, verify, and decrypt them. The fixture
//! contract is owned by `examples/gen_v6_fixtures.rs` — run that to
//! regenerate if the contract changes.

use std::path::PathBuf;

use wecanencrypt::{
    decrypt_bytes, parse_key_bytes, verify_and_extract_bytes, verify_bytes_detached, KeyVersion,
};

const FIXTURE_PASSWORD: &str = "v6-fixture-password";

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("v6")
}

fn read(name: &str) -> Vec<u8> {
    let path = fixtures_dir().join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e))
}

#[test]
fn alice_v6_public_key_parses_as_v6() {
    let pub_bytes = read("alice_v6_cv25519modern_pub.asc");
    let info = parse_key_bytes(&pub_bytes, false).unwrap();

    assert_eq!(info.key_version, KeyVersion::V6);
    assert_eq!(info.fingerprint.len(), 64, "V6 fingerprint is SHA-256");
    for sk in &info.subkeys {
        assert_eq!(sk.key_version, KeyVersion::V6);
    }
}

#[test]
fn bob_v6_ed448_public_key_parses_as_v6() {
    let pub_bytes = read("bob_v6_cv448modern_pub.asc");
    let info = parse_key_bytes(&pub_bytes, false).unwrap();

    assert_eq!(info.key_version, KeyVersion::V6);
    assert_eq!(info.fingerprint.len(), 64);
}

#[test]
fn alice_v6_secret_key_parses_as_v6() {
    let sec_bytes = read("alice_v6_cv25519modern_sec.asc");
    let info = parse_key_bytes(&sec_bytes, false).unwrap();

    assert!(info.is_secret);
    assert_eq!(info.key_version, KeyVersion::V6);
}

#[test]
fn verify_alice_v6_inline_signature() {
    let pub_bytes = read("alice_v6_cv25519modern_pub.asc");
    let signed = read("alice_v6_signed_inline.pgp");
    let expected = read("signed_payload.txt");

    let extracted = verify_and_extract_bytes(&pub_bytes, &signed).unwrap();
    assert_eq!(extracted, expected);
}

#[test]
fn verify_alice_v6_detached_signature() {
    let pub_bytes = read("alice_v6_cv25519modern_pub.asc");
    let payload = read("signed_payload.txt");
    let sig = read("alice_v6_signed_detached.asc");

    assert!(verify_bytes_detached(&pub_bytes, &payload, &sig).unwrap());
}

#[test]
fn decrypt_v6_seipdv2_message_to_alice() {
    let sec_bytes = read("alice_v6_cv25519modern_sec.asc");
    let ciphertext = read("alice_v6_encrypted_seipdv2.asc");
    let expected = read("encrypted_payload.txt");

    let plaintext = decrypt_bytes(&sec_bytes, &ciphertext, FIXTURE_PASSWORD).unwrap();
    assert_eq!(plaintext, expected);
}
