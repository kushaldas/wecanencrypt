//! Interop tests between wecanencrypt (rpgp backend) and sequoia-sop's `sqop`
//! CLI (Sequoia backend).
//!
//! Verifies that keys and messages produced by wecanencrypt are consumable by
//! an independent OpenPGP implementation, and vice versa, across both
//! encrypt/decrypt and sign/verify.
//!
//! Requires the pinned `sqop` binary. Run `just install-sqop` first. If the
//! binary is absent, tests soft-skip with a message so `cargo test` stays
//! green for contributors who haven't installed it yet. CI installs it.

use std::ffi::OsStr;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use wecanencrypt::{
    create_key, decrypt_bytes, encrypt_bytes, get_pub_key, sign_bytes_detached,
    verify_bytes_detached, CipherSuite, GeneratedKey, SubkeyFlags,
};

const SQOP_PINNED_VERSION: &str = "0.37.3";
const TEST_PASSWORD: &str = "test-password-123";
const TEST_UID: &str = "Interop Test <interop@example.com>";
const PLAINTEXT: &[u8] = b"hello from the wecanencrypt <-> sqop interop test";

fn sqop_binary() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("WECANENCRYPT_SQOP") {
        let p = PathBuf::from(explicit);
        if p.exists() {
            return Some(p);
        }
    }
    let local = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("sop-bin")
        .join("bin")
        .join("sqop");
    if local.exists() {
        return Some(local);
    }
    if Command::new("sqop")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        return Some(PathBuf::from("sqop"));
    }
    None
}

fn skip_if_no_sqop() -> Option<PathBuf> {
    match sqop_binary() {
        Some(p) => Some(p),
        None => {
            eprintln!(
                "sqop not found at target/sop-bin/bin/sqop or on PATH — \
                 run 'just install-sqop' to enable interop tests"
            );
            None
        }
    }
}

fn assert_sqop_version(bin: &Path) {
    let out = Command::new(bin)
        .arg("version")
        .output()
        .expect("run `sqop version`");
    assert!(
        out.status.success(),
        "sqop version exited with {:?}: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(SQOP_PINNED_VERSION),
        "sqop version mismatch — expected {}, got: {}",
        SQOP_PINNED_VERSION,
        stdout.trim()
    );
}

fn generate_key() -> GeneratedKey {
    create_key(
        TEST_PASSWORD,
        &[TEST_UID],
        CipherSuite::Cv25519Modern,
        None,
        None,
        None,
        SubkeyFlags::all(),
        false,
        true,
    )
    .expect("generate V4 Cv25519Modern key")
}

fn write_temp(prefix: &str, contents: &[u8]) -> tempfile::NamedTempFile {
    let mut f = tempfile::Builder::new()
        .prefix(prefix)
        .tempfile()
        .expect("create tempfile");
    f.write_all(contents).expect("write tempfile");
    f.flush().expect("flush tempfile");
    f
}

fn write_password_file() -> tempfile::NamedTempFile {
    write_temp("sqop-pw-", TEST_PASSWORD.as_bytes())
}

fn run_sqop_with_stdin(bin: &Path, args: Vec<&OsStr>, stdin_bytes: &[u8]) -> Vec<u8> {
    let label: Vec<String> = args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let mut child = Command::new(bin)
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn sqop {label:?}: {e}"));
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(stdin_bytes)
        .expect("pipe stdin into sqop");
    let out = child.wait_with_output().expect("wait for sqop");
    assert!(
        out.status.success(),
        "sqop {label:?} failed (status {:?}): {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

#[test]
fn wecanencrypt_encrypt_sqop_decrypt() {
    let Some(sqop) = skip_if_no_sqop() else {
        return;
    };
    assert_sqop_version(&sqop);

    let key = generate_key();
    let pub_key = get_pub_key(&key.secret_key).expect("export public key");
    let ciphertext =
        encrypt_bytes(pub_key.as_bytes(), PLAINTEXT, true).expect("encrypt with wecanencrypt");

    let secret_file = write_temp("sqop-sec-", &key.secret_key);
    let pw_file = write_password_file();
    let plaintext = run_sqop_with_stdin(
        &sqop,
        vec![
            OsStr::new("decrypt"),
            OsStr::new("--with-key-password"),
            pw_file.path().as_os_str(),
            secret_file.path().as_os_str(),
        ],
        &ciphertext,
    );
    assert_eq!(plaintext, PLAINTEXT);
}

#[test]
fn sqop_encrypt_wecanencrypt_decrypt() {
    let Some(sqop) = skip_if_no_sqop() else {
        return;
    };
    assert_sqop_version(&sqop);

    let key = generate_key();
    let pub_key = get_pub_key(&key.secret_key).expect("export public key");

    let pub_file = write_temp("sqop-pub-", pub_key.as_bytes());
    let ciphertext = run_sqop_with_stdin(
        &sqop,
        vec![OsStr::new("encrypt"), pub_file.path().as_os_str()],
        PLAINTEXT,
    );

    let plaintext = decrypt_bytes(&key.secret_key, &ciphertext, TEST_PASSWORD)
        .expect("decrypt with wecanencrypt");
    assert_eq!(plaintext, PLAINTEXT);
}

#[test]
fn wecanencrypt_sign_sqop_verify() {
    let Some(sqop) = skip_if_no_sqop() else {
        return;
    };
    assert_sqop_version(&sqop);

    let key = generate_key();
    let pub_key = get_pub_key(&key.secret_key).expect("export public key");

    let sig = sign_bytes_detached(&key.secret_key, PLAINTEXT, TEST_PASSWORD)
        .expect("sign with wecanencrypt");

    let sig_file = write_temp("sqop-sig-", sig.as_bytes());
    let pub_file = write_temp("sqop-pub-", pub_key.as_bytes());
    // sqop verify exits 0 on success; stdout carries verification info we ignore.
    run_sqop_with_stdin(
        &sqop,
        vec![
            OsStr::new("verify"),
            sig_file.path().as_os_str(),
            pub_file.path().as_os_str(),
        ],
        PLAINTEXT,
    );
}

#[test]
fn sqop_sign_wecanencrypt_verify() {
    let Some(sqop) = skip_if_no_sqop() else {
        return;
    };
    assert_sqop_version(&sqop);

    let key = generate_key();
    let pub_key = get_pub_key(&key.secret_key).expect("export public key");

    let secret_file = write_temp("sqop-sec-", &key.secret_key);
    let pw_file = write_password_file();
    let sig = run_sqop_with_stdin(
        &sqop,
        vec![
            OsStr::new("sign"),
            OsStr::new("--with-key-password"),
            pw_file.path().as_os_str(),
            secret_file.path().as_os_str(),
        ],
        PLAINTEXT,
    );

    let valid =
        verify_bytes_detached(pub_key.as_bytes(), PLAINTEXT, &sig).expect("verify_bytes_detached");
    assert!(
        valid,
        "wecanencrypt should accept sqop's detached signature"
    );
}
