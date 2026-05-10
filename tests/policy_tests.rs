//! Crypto-policy enforcement tests.
//!
//! These tests exercise wecanencrypt's perimeter policy gate using
//! programmatically-built policies. They live in their own
//! integration test binary so the policy-state global in
//! `crypto_policy.rs` doesn't collide with other tests that touch it.
//!
//! Pattern: each test mints a fresh key under `NullPolicy` (so the
//! key-parse gate doesn't trip), then installs a strict policy via
//! `__test_install_policy_from_toml`, and asserts the strict policy
//! rejects the operation under test. No disk fixtures required —
//! everything is generated in-process.

use std::sync::Mutex;

use wecanencrypt::{
    create_key_simple, decrypt_bytes, encrypt_bytes_to_multiple_with_algo, get_pub_key,
    parse_key_bytes, sign_bytes_detached_with_hash, verify_bytes_detached, Error,
    HashAlgorithm, SymmetricKeyAlgorithm,
};

/// Serialize policy tests within this binary. Cargo runs `#[test]`
/// functions on multiple threads by default, but the active policy
/// is process-global mutable state — concurrent tests would race on
/// each other's `__test_disable_policy` / `install_strict` calls.
static POLICY_LOCK: Mutex<()> = Mutex::new(());

/// A strict-DEFAULT-ish policy: bans MD5/SHA-1, IDEA/3DES/CAST5/Blowfish,
/// requires RSA ≥ 2048. Mirrors what Fedora ships at
/// /etc/crypto-policies/back-ends/sequoia.config under the DEFAULT
/// profile, trimmed to the algorithms these tests actually exercise.
const STRICT_POLICY_TOML: &str = r#"
[hash_algorithms]
md5.collision_resistance = "never"
md5.second_preimage_resistance = "never"
sha1.collision_resistance = "never"
sha1.second_preimage_resistance = "never"
sha256.collision_resistance = "always"
sha256.second_preimage_resistance = "always"
sha512.collision_resistance = "always"
sha512.second_preimage_resistance = "always"
default_disposition = "never"

[symmetric_algorithms]
idea = "never"
tripledes = "never"
cast5 = "never"
blowfish = "never"
aes128 = "always"
aes256 = "always"
default_disposition = "never"

[asymmetric_algorithms]
rsa1024 = "never"
rsa2048 = "always"
rsa4096 = "always"
cv25519 = "always"
nistp256 = "always"
nistp384 = "always"
nistp521 = "always"
ed25519 = "always"
x25519 = "always"
"#;

fn install_strict() {
    wecanencrypt::__test_install_policy_from_toml(STRICT_POLICY_TOML)
        .expect("test policy TOML must parse");
}

fn fresh_curve25519_key() -> wecanencrypt::GeneratedKey {
    create_key_simple("pw", &["alice@example.com"]).expect("key generation must succeed")
}

#[test]
fn fresh_modern_key_loads_under_strict() {
    // A freshly minted Curve25519 key uses SHA-256 for its
    // self-signatures — strict policy accepts it.
    let _guard = POLICY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    wecanencrypt::__test_disable_policy();
    let key = fresh_curve25519_key();

    install_strict();
    let info = parse_key_bytes(&key.public_key.as_bytes(), false).expect("modern key must load");
    assert!(!info.fingerprint.is_empty());
}

#[test]
fn sign_with_sha1_hash_rejected_under_strict() {
    // The outbound sign path with an explicit SHA-1 hash override
    // is gated at function entry — strict policy rejects before
    // touching the secret key.
    let _guard = POLICY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    wecanencrypt::__test_disable_policy();
    let key = fresh_curve25519_key();

    install_strict();
    let result = sign_bytes_detached_with_hash(
        &key.secret_key,
        b"data",
        "pw",
        Some(HashAlgorithm::Sha1),
    );
    match result {
        Err(Error::PolicyViolation { what }) => {
            assert!(
                what.to_lowercase().contains("sha1"),
                "policy error must mention SHA1: {what}"
            );
        }
        other => panic!("expected PolicyViolation, got {other:?}"),
    }
}

// Note: a "verify SHA-1 signature → policy rejects" test would
// need either a committed SHA-1-signed fixture or an RSA key (which
// can sign with SHA-1, unlike Ed25519 — rpgp itself rejects SHA-1
// with Ed25519 keys via a PQC-mandated minimum-hash-strength check
// that runs before our policy hook). The outbound sign hook is
// already tested by `sign_with_sha1_hash_rejected_under_strict`,
// which exercises the same `policy.hash_algorithm()` chokepoint.

#[test]
fn verify_default_signature_accepted_under_strict() {
    // Control: a SHA-256 default signature still verifies under
    // the same strict policy.
    let _guard = POLICY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    wecanencrypt::__test_disable_policy();
    let key = fresh_curve25519_key();
    let pub_pem = get_pub_key(&key.secret_key).unwrap();
    let signed = sign_bytes_detached_with_hash(&key.secret_key, b"data", "pw", None)
        .expect("sign under null policy (default-hash)");

    install_strict();
    let ok =
        verify_bytes_detached(pub_pem.as_bytes(), b"data", signed.armored.as_bytes()).unwrap();
    assert!(ok);
}

#[test]
fn encrypt_with_idea_rejected_under_strict() {
    // Outbound symmetric-algorithm gate at the encrypt entry point.
    let _guard = POLICY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    wecanencrypt::__test_disable_policy();
    let key = fresh_curve25519_key();

    install_strict();
    let result = encrypt_bytes_to_multiple_with_algo(
        &[key.public_key.as_bytes()],
        b"hello",
        true,
        SymmetricKeyAlgorithm::IDEA,
    );
    match result {
        Err(Error::PolicyViolation { what }) => {
            assert!(
                what.to_lowercase().contains("idea"),
                "policy error must mention IDEA: {what}"
            );
        }
        other => panic!("expected PolicyViolation, got {other:?}"),
    }
}

#[test]
fn encrypt_decrypt_roundtrip_under_strict() {
    // Control: AES-256 encrypt / decrypt round-trips under strict
    // policy without tripping any gate.
    let _guard = POLICY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    wecanencrypt::__test_disable_policy();
    let key = fresh_curve25519_key();

    install_strict();
    let ct = encrypt_bytes_to_multiple_with_algo(
        &[key.public_key.as_bytes()],
        b"hello",
        true,
        SymmetricKeyAlgorithm::AES256,
    )
    .expect("aes256 encrypt under strict");
    let pt = decrypt_bytes(&key.secret_key, &ct, "pw").expect("decrypt");
    assert_eq!(pt, b"hello");
}

#[test]
fn null_policy_baseline_modern_roundtrip() {
    // Regression baseline: with NullPolicy a default-hash sign /
    // verify round-trips. Confirms NullPolicy doesn't accidentally
    // reject anything modern.
    let _guard = POLICY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    wecanencrypt::__test_disable_policy();
    let key = fresh_curve25519_key();
    let pub_pem = get_pub_key(&key.secret_key).unwrap();
    let signed = sign_bytes_detached_with_hash(&key.secret_key, b"data", "pw", None)
        .expect("default-hash sign under null");
    let ok =
        verify_bytes_detached(pub_pem.as_bytes(), b"data", signed.armored.as_bytes()).unwrap();
    assert!(ok);
}
