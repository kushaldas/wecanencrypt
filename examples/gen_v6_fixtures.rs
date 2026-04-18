//! Regenerate the committed V6 (RFC 9580) test fixtures.
//!
//! Run with: `cargo run --example gen_v6_fixtures`. Writes armored V6 keys and
//! round-tripped artifacts into `tests/fixtures/v6/`. Commit the output so CI
//! has stable inputs; regeneration is only needed if the fixture contract
//! (filenames, UIDs, password) changes.

use std::fs;
use std::path::PathBuf;

use wecanencrypt::{
    create_key_v6_simple, encrypt_bytes, get_pub_key, sign_bytes, sign_bytes_detached, CipherSuite,
};

const FIXTURE_PASSWORD: &str = "v6-fixture-password";
const ALICE_UID: &str = "V6 Alice <alice@v6.example.com>";
const BOB_UID: &str = "V6 Bob <bob@v6.example.com>";
const SIGNED_PAYLOAD: &[u8] = b"Committed V6 fixture payload\n";
const ENCRYPTED_PAYLOAD: &[u8] = b"This is a committed V6 fixture plaintext.\n";

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("v6")
}

fn write(name: &str, data: &[u8]) {
    let path = fixtures_dir().join(name);
    fs::write(&path, data).unwrap_or_else(|e| panic!("write {}: {}", path.display(), e));
    println!("wrote {}", path.display());
}

fn main() {
    let dir = fixtures_dir();
    fs::create_dir_all(&dir).expect("create fixtures/v6");

    // Alice: Ed25519 + X25519 V6 key.
    let alice = create_key_v6_simple(FIXTURE_PASSWORD, &[ALICE_UID], CipherSuite::Cv25519Modern)
        .expect("generate Alice V6 (Cv25519Modern)");
    let alice_pub = get_pub_key(&alice.secret_key).expect("extract Alice public");
    write(
        "alice_v6_cv25519modern_sec.asc",
        alice.secret_key.as_slice(),
    );
    write("alice_v6_cv25519modern_pub.asc", alice_pub.as_bytes());

    // Bob: Ed448 + X448 V6 key.
    let bob = create_key_v6_simple(FIXTURE_PASSWORD, &[BOB_UID], CipherSuite::Cv448Modern)
        .expect("generate Bob V6 (Cv448Modern)");
    let bob_pub = get_pub_key(&bob.secret_key).expect("extract Bob public");
    write("bob_v6_cv448modern_sec.asc", bob.secret_key.as_slice());
    write("bob_v6_cv448modern_pub.asc", bob_pub.as_bytes());

    // Inline signed message from Alice (V6 signature auto-selected).
    let signed = sign_bytes(&alice.secret_key, SIGNED_PAYLOAD, FIXTURE_PASSWORD)
        .expect("sign SIGNED_PAYLOAD with V6 Alice");
    write("alice_v6_signed_inline.pgp", &signed);
    write("signed_payload.txt", SIGNED_PAYLOAD);

    // Detached signature.
    let detached = sign_bytes_detached(&alice.secret_key, SIGNED_PAYLOAD, FIXTURE_PASSWORD)
        .expect("detached sign with V6 Alice");
    write("alice_v6_signed_detached.asc", detached.as_bytes());

    // Encrypted-to-Alice message (auto-dispatches SEIPDv2 because Alice is V6).
    let encrypted =
        encrypt_bytes(alice_pub.as_bytes(), ENCRYPTED_PAYLOAD, true).expect("encrypt to V6 Alice");
    write("alice_v6_encrypted_seipdv2.asc", &encrypted);
    write("encrypted_payload.txt", ENCRYPTED_PAYLOAD);

    println!(
        "\nAll V6 fixtures regenerated. Password: {}",
        FIXTURE_PASSWORD
    );
}
