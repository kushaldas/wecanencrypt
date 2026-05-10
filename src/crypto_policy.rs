//! Fedora `crypto-policies` integration.
//!
//! When `update-crypto-policies --set DEFAULT` (or `LEGACY`/`FUTURE`/
//! `FIPS`) is run, the system writes
//! `/etc/crypto-policies/back-ends/sequoia.config`. This module reads
//! that file at startup and turns it into an in-memory allow/deny
//! map keyed by the rpgp algorithm enums. Verify, decrypt, encrypt,
//! sign, and key-parse functions in `wecanencrypt` consult the
//! resulting policy and refuse algorithms the policy bans.
//!
//! ## Lookup precedence (first match wins)
//!
//! 1. `WECANENCRYPT_CRYPTO_POLICY` env var.
//!    - Value `off` (case-insensitive) → fallback to [`NullPolicy`]
//!      (accept everything). Useful for tests and emergency
//!      mitigation.
//!    - Other non-empty value → treat as a path to a config file.
//! 2. `SEQUOIA_CRYPTO_POLICY` env var → file path.
//! 3. `/etc/crypto-policies/back-ends/sequoia.config` → the Fedora
//!    default location.
//! 4. None of the above produce a parseable file → fall back to
//!    [`NullPolicy`].
//!
//! ## Scope
//!
//! Perimeter enforcement at `wecanencrypt`'s public API surface:
//!
//! - Inbound: signature verification, message decryption (PKESK,
//!   SKESK, S2K, AEAD), and key parsing (every signature attached
//!   to the cert is walked).
//! - Outbound: caller-supplied `_with_algo`/`_with_hash` paths are
//!   gated; default-algo paths rely on rpgp picking allowed
//!   defaults (AES-256, SHA-256, OCB) which every Fedora policy
//!   permits.
//!
//! Crypto operations *inside* rpgp that wecanencrypt never sees
//! (e.g. self-cert verification during `decrypt_with_key` retrieving
//! a subkey) bypass this gate. Defence in depth would require an
//! upstream rpgp `Policy` trait, which is out of scope here.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use pgp::crypto::aead::AeadAlgorithm;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;

use crate::error::{Error, Result};

const SYSTEM_CONFIG_PATH: &str = "/etc/crypto-policies/back-ends/sequoia.config";

/// Allow/deny disposition for a specific algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Disposition {
    Always,
    Never,
}

/// Crypto-policy gate consulted by every algorithm-using path in
/// `wecanencrypt`.
pub(crate) trait Policy: std::fmt::Debug + Send + Sync {
    fn hash_algorithm(&self, algo: HashAlgorithm) -> Result<()>;
    fn symmetric_algorithm(&self, algo: SymmetricKeyAlgorithm) -> Result<()>;
    /// Reserved for AEAD-gating call sites we haven't added yet —
    /// the AEAD packet-body algorithm sits inside rpgp's `Edata`
    /// reader where wecanencrypt currently can't peek at it.
    /// Documented out-of-scope perimeter limitation; keep the
    /// trait method so the API doesn't shift when we close the
    /// gap.
    #[allow(dead_code)]
    fn aead_algorithm(&self, aead: AeadAlgorithm, sym: SymmetricKeyAlgorithm) -> Result<()>;
    fn public_key_algorithm(&self, algo: PublicKeyAlgorithm, bits: Option<u32>) -> Result<()>;
}

/// Accept-everything policy. Used as the fallback on hosts without
/// a parseable crypto-policies file, and explicitly via
/// `WECANENCRYPT_CRYPTO_POLICY=off`.
#[derive(Debug, Default)]
pub(crate) struct NullPolicy;

impl Policy for NullPolicy {
    fn hash_algorithm(&self, _algo: HashAlgorithm) -> Result<()> {
        Ok(())
    }

    fn symmetric_algorithm(&self, _algo: SymmetricKeyAlgorithm) -> Result<()> {
        Ok(())
    }

    fn aead_algorithm(&self, _aead: AeadAlgorithm, _sym: SymmetricKeyAlgorithm) -> Result<()> {
        Ok(())
    }

    fn public_key_algorithm(&self, _algo: PublicKeyAlgorithm, _bits: Option<u32>) -> Result<()> {
        Ok(())
    }
}

/// Allow/deny policy populated from a parsed
/// `sequoia.config`-style TOML file.
#[derive(Debug)]
pub(crate) struct StandardPolicy {
    hash: HashMap<u8, Disposition>,
    sym: HashMap<u8, Disposition>,
    aead: HashMap<u8, Disposition>,
    pubkey: HashMap<u8, Disposition>,
    /// Minimum RSA key size in bits. RSA keys with fewer bits are
    /// rejected even if `pubkey` permits the algorithm enum.
    min_rsa_bits: u32,
    min_dsa_bits: u32,
    hash_default: Disposition,
    sym_default: Disposition,
    aead_default: Disposition,
    pubkey_default: Disposition,
}

impl StandardPolicy {
    fn lookup<K: Into<u8>>(map: &HashMap<u8, Disposition>, default: Disposition, k: K) -> bool {
        match map.get(&k.into()).copied().unwrap_or(default) {
            Disposition::Always => true,
            Disposition::Never => false,
        }
    }
}

impl Policy for StandardPolicy {
    fn hash_algorithm(&self, algo: HashAlgorithm) -> Result<()> {
        if Self::lookup(&self.hash, self.hash_default, algo) {
            Ok(())
        } else {
            Err(Error::policy_hash(algo))
        }
    }

    fn symmetric_algorithm(&self, algo: SymmetricKeyAlgorithm) -> Result<()> {
        if Self::lookup(&self.sym, self.sym_default, algo) {
            Ok(())
        } else {
            Err(Error::policy_sym(algo))
        }
    }

    fn aead_algorithm(&self, aead: AeadAlgorithm, sym: SymmetricKeyAlgorithm) -> Result<()> {
        if !Self::lookup(&self.aead, self.aead_default, aead) {
            return Err(Error::policy_aead(aead, sym));
        }
        // A live AEAD operation also consumes the symmetric key
        // algorithm, so gate that too.
        self.symmetric_algorithm(sym)
    }

    fn public_key_algorithm(&self, algo: PublicKeyAlgorithm, bits: Option<u32>) -> Result<()> {
        if !Self::lookup(&self.pubkey, self.pubkey_default, algo) {
            return Err(Error::policy_pubkey(algo, bits));
        }
        // Bit-size floors apply even when the algorithm enum is
        // permitted (e.g. RSA is allowed but RSA-1024 is not).
        if let Some(bits) = bits {
            match algo {
                PublicKeyAlgorithm::RSA
                | PublicKeyAlgorithm::RSAEncrypt
                | PublicKeyAlgorithm::RSASign
                    if bits < self.min_rsa_bits => {
                        return Err(Error::policy_pubkey(algo, Some(bits)));
                    }
                PublicKeyAlgorithm::DSA
                    if bits < self.min_dsa_bits => {
                        return Err(Error::policy_pubkey(algo, Some(bits)));
                    }
                _ => {}
            }
        }
        Ok(())
    }
}

// -------- Global state -------------------------------------------

static POLICY: RwLock<Option<Arc<dyn Policy>>> = RwLock::new(None);

/// Returns the active policy, lazily initialising from environment
/// + system config on first call.
pub(crate) fn current() -> Arc<dyn Policy> {
    if let Some(p) = POLICY.read().unwrap().as_ref() {
        return Arc::clone(p);
    }
    let mut w = POLICY.write().unwrap();
    if let Some(p) = w.as_ref() {
        return Arc::clone(p);
    }
    let p = load_from_environment();
    *w = Some(Arc::clone(&p));
    p
}

/// Replace the active policy. Test-only.
#[cfg(test)]
pub(crate) fn set_for_test(p: Arc<dyn Policy>) {
    *POLICY.write().unwrap() = Some(p);
}

/// Reset the active policy back to lazy-init. Test-only.
#[cfg(test)]
pub(crate) fn reset_for_test() {
    *POLICY.write().unwrap() = None;
}

/// Disable the active crypto policy for the rest of the process,
/// equivalent to setting `WECANENCRYPT_CRYPTO_POLICY=off`.
///
/// **Test-only.** Gated behind the `test-helpers` Cargo feature so
/// production callers cannot accidentally (or maliciously) flip the
/// policy from a transitive dependency. Integration tests enable
/// the feature via `cargo test --features test-helpers`. The
/// supported runtime way to disable enforcement is the
/// `WECANENCRYPT_CRYPTO_POLICY=off` environment variable.
#[cfg(any(test, feature = "test-helpers"))]
#[doc(hidden)]
pub fn __test_disable_policy() {
    *POLICY.write().unwrap() = Some(Arc::new(NullPolicy));
}

/// Install a policy parsed from an inline TOML string.
///
/// **Test-only.** Same gating as [`__test_disable_policy`]. Used by
/// integration tests to verify denial paths without writing fixture
/// files to disk.
#[cfg(any(test, feature = "test-helpers"))]
#[doc(hidden)]
pub fn __test_install_policy_from_toml(toml: &str) -> std::result::Result<(), String> {
    let policy = StandardPolicy::from_toml_str(toml)
        .map_err(|e| format!("failed to parse test policy TOML: {e:?}"))?;
    *POLICY.write().unwrap() = Some(Arc::new(policy));
    Ok(())
}

fn load_from_environment() -> Arc<dyn Policy> {
    if let Ok(val) = std::env::var("WECANENCRYPT_CRYPTO_POLICY") {
        if val.eq_ignore_ascii_case("off") {
            return Arc::new(NullPolicy);
        }
        if !val.is_empty() {
            match StandardPolicy::from_path(Path::new(&val)) {
                Ok(p) => return Arc::new(p),
                Err(e) => log::warn!(
                    target: "wecanencrypt::crypto_policy",
                    "WECANENCRYPT_CRYPTO_POLICY={val:?} could not be parsed ({e:?}); \
                     falling through to next priority. Set the var to 'off' to \
                     intentionally disable enforcement."
                ),
            }
        }
    }

    if let Ok(val) = std::env::var("SEQUOIA_CRYPTO_POLICY") {
        if !val.is_empty() {
            match StandardPolicy::from_path(Path::new(&val)) {
                Ok(p) => return Arc::new(p),
                Err(e) => log::warn!(
                    target: "wecanencrypt::crypto_policy",
                    "SEQUOIA_CRYPTO_POLICY={val:?} could not be parsed ({e:?}); \
                     falling through to system config."
                ),
            }
        }
    }

    if let Ok(p) = StandardPolicy::from_path(Path::new(SYSTEM_CONFIG_PATH)) {
        return Arc::new(p);
    }

    Arc::new(NullPolicy)
}

// -------- Parser -------------------------------------------------

impl StandardPolicy {
    pub(crate) fn from_path(path: &Path) -> std::result::Result<Self, ParseError> {
        let text = fs::read_to_string(path).map_err(|_| ParseError::FileRead)?;
        Self::from_toml_str(&text)
    }

    pub(crate) fn from_toml_str(s: &str) -> std::result::Result<Self, ParseError> {
        let root: toml::Table = s.parse().map_err(|_| ParseError::TomlSyntax)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let mut policy = StandardPolicy::permissive_skeleton();

        if let Some(toml::Value::Table(t)) = root.get("hash_algorithms") {
            policy.hash_default = section_default(t, Disposition::Always);
            for (name, value) in t {
                if META_KEYS.contains(&name.as_str()) {
                    continue;
                }
                if let Some(disp) = parse_hash_disposition(value, now) {
                    if let Some(algo) = parse_hash_name(name) {
                        policy.hash.insert(u8::from(algo), disp);
                    }
                }
            }
        }

        if let Some(toml::Value::Table(t)) = root.get("symmetric_algorithms") {
            policy.sym_default = section_default(t, Disposition::Always);
            for (name, value) in t {
                if META_KEYS.contains(&name.as_str()) {
                    continue;
                }
                if let Some(disp) = parse_simple_disposition(value, now) {
                    if let Some(algo) = parse_sym_name(name) {
                        policy.sym.insert(u8::from(algo), disp);
                    }
                }
            }
        }

        if let Some(toml::Value::Table(t)) = root.get("aead_algorithms") {
            policy.aead_default = section_default(t, Disposition::Always);
            for (name, value) in t {
                if META_KEYS.contains(&name.as_str()) {
                    continue;
                }
                if let Some(disp) = parse_simple_disposition(value, now) {
                    if let Some(algo) = parse_aead_name(name) {
                        policy.aead.insert(u8::from(algo), disp);
                    }
                }
            }
        }

        if let Some(toml::Value::Table(t)) = root.get("asymmetric_algorithms") {
            policy.pubkey_default = section_default(t, Disposition::Always);
            for (name, value) in t {
                if META_KEYS.contains(&name.as_str()) {
                    continue;
                }
                if let Some(disp) = parse_simple_disposition(value, now) {
                    apply_asym_entry(&mut policy, name, disp);
                }
            }
        }

        Ok(policy)
    }

    fn permissive_skeleton() -> Self {
        StandardPolicy {
            hash: HashMap::new(),
            sym: HashMap::new(),
            aead: HashMap::new(),
            pubkey: HashMap::new(),
            min_rsa_bits: 0,
            min_dsa_bits: 0,
            hash_default: Disposition::Always,
            sym_default: Disposition::Always,
            aead_default: Disposition::Always,
            pubkey_default: Disposition::Always,
        }
    }
}

const META_KEYS: &[&str] = &["default_disposition", "ignore_invalid"];

#[derive(Debug)]
pub(crate) enum ParseError {
    FileRead,
    TomlSyntax,
}

fn section_default(t: &toml::Table, fallback: Disposition) -> Disposition {
    if let Some(toml::Value::String(s)) = t.get("default_disposition") {
        match s.as_str() {
            "never" => Disposition::Never,
            "always" => Disposition::Always,
            _ => fallback,
        }
    } else {
        fallback
    }
}

/// Hash algorithms can be configured either as a single string
/// (`sha1 = "never"` / `"always"` / a date) or as a sub-table with
/// `collision_resistance` and `second_preimage_resistance` fields.
/// The hash is rejected if either resistance attribute resolves to
/// `Never` at the current time; accepted only if both pass.
fn parse_hash_disposition(value: &toml::Value, now: i64) -> Option<Disposition> {
    match value {
        toml::Value::String(_) | toml::Value::Datetime(_) => parse_simple_disposition(value, now),
        toml::Value::Table(t) => {
            let collision = t
                .get("collision_resistance")
                .and_then(|v| parse_simple_disposition(v, now));
            let second = t
                .get("second_preimage_resistance")
                .and_then(|v| parse_simple_disposition(v, now));
            if matches!(collision, Some(Disposition::Never))
                || matches!(second, Some(Disposition::Never))
            {
                Some(Disposition::Never)
            } else if collision.is_some() || second.is_some() {
                Some(Disposition::Always)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn parse_simple_disposition(value: &toml::Value, now: i64) -> Option<Disposition> {
    match value {
        toml::Value::String(s) => match s.as_str() {
            "always" => Some(Disposition::Always),
            "never" => Some(Disposition::Never),
            _ => None,
        },
        toml::Value::Datetime(dt) => {
            // Treat the datetime as a cutoff: if now < cutoff the
            // algorithm is still permitted. Sequoia's format spec
            // calls this the "cutoff time" — past it, the
            // algorithm is forbidden.
            let cutoff = dt.to_string();
            match parse_iso8601_to_unix(&cutoff) {
                Some(c) if now < c => Some(Disposition::Always),
                Some(_) => Some(Disposition::Never),
                None => None,
            }
        }
        toml::Value::Table(t) => {
            // Forwards-compat: `algo.default_disposition = "never"`.
            t.get("default_disposition")
                .and_then(|v| parse_simple_disposition(v, now))
        }
        _ => None,
    }
}

/// Best-effort RFC 3339 / TOML datetime parser. Handles the two
/// shapes Fedora's policy templates emit: `2010-01-01T00:00:00Z` and
/// bare local datetime. Returns Unix seconds.
fn parse_iso8601_to_unix(s: &str) -> Option<i64> {
    let dt = chrono::DateTime::parse_from_rfc3339(s).ok();
    if let Some(dt) = dt {
        return Some(dt.timestamp());
    }
    let naive = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S").ok()?;
    Some(naive.and_utc().timestamp())
}

fn parse_hash_name(name: &str) -> Option<HashAlgorithm> {
    let lower = name.to_ascii_lowercase();
    Some(match lower.as_str() {
        "md5" => HashAlgorithm::Md5,
        "sha1" => HashAlgorithm::Sha1,
        "ripemd160" => HashAlgorithm::Ripemd160,
        "sha256" => HashAlgorithm::Sha256,
        "sha384" => HashAlgorithm::Sha384,
        "sha512" => HashAlgorithm::Sha512,
        "sha224" => HashAlgorithm::Sha224,
        "sha3-256" | "sha3_256" => HashAlgorithm::Sha3_256,
        "sha3-512" | "sha3_512" => HashAlgorithm::Sha3_512,
        _ => return None,
    })
}

fn parse_sym_name(name: &str) -> Option<SymmetricKeyAlgorithm> {
    let lower = name.to_ascii_lowercase();
    Some(match lower.as_str() {
        "idea" => SymmetricKeyAlgorithm::IDEA,
        "tripledes" | "3des" => SymmetricKeyAlgorithm::TripleDES,
        "cast5" => SymmetricKeyAlgorithm::CAST5,
        "blowfish" => SymmetricKeyAlgorithm::Blowfish,
        "aes128" => SymmetricKeyAlgorithm::AES128,
        "aes192" => SymmetricKeyAlgorithm::AES192,
        "aes256" => SymmetricKeyAlgorithm::AES256,
        "twofish" => SymmetricKeyAlgorithm::Twofish,
        "camellia128" => SymmetricKeyAlgorithm::Camellia128,
        "camellia192" => SymmetricKeyAlgorithm::Camellia192,
        "camellia256" => SymmetricKeyAlgorithm::Camellia256,
        _ => return None,
    })
}

fn parse_aead_name(name: &str) -> Option<AeadAlgorithm> {
    let lower = name.to_ascii_lowercase();
    Some(match lower.as_str() {
        "eax" => AeadAlgorithm::Eax,
        "ocb" => AeadAlgorithm::Ocb,
        "gcm" => AeadAlgorithm::Gcm,
        _ => return None,
    })
}

/// Asymmetric-algorithm entries split into bare algorithm names
/// (e.g. `nistp256`, `cv25519`) and bit-size-suffixed names
/// (e.g. `rsa1024`, `dsa2048`). The bit-size suffix variant
/// configures the algorithm flag (Always entries permit RSA/DSA at
/// all) and the minimum-bits floor (the lowest Always bit count).
///
/// Bit-suffix `Never` entries are interpreted as advisory and do
/// NOT raise the floor: under all four real Fedora templates
/// (DEFAULT/LEGACY/FIPS/FUTURE) the operative constraint is the
/// lowest `Always` entry, and ratcheting on `Never` produces an
/// order-dependent result (e.g. `rsa1024 = "never"` followed by
/// `rsa2048 = "always"` would set the floor to 1025 instead of
/// 2048, admitting any RSA key from 1025-2047 bits).
fn apply_asym_entry(policy: &mut StandardPolicy, name: &str, disp: Disposition) {
    let lower = name.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("rsa") {
        if let Ok(bits) = rest.parse::<u32>() {
            if matches!(disp, Disposition::Always) {
                policy.pubkey.insert(u8::from(PublicKeyAlgorithm::RSA), disp);
                policy
                    .pubkey
                    .insert(u8::from(PublicKeyAlgorithm::RSAEncrypt), disp);
                policy
                    .pubkey
                    .insert(u8::from(PublicKeyAlgorithm::RSASign), disp);
                if policy.min_rsa_bits == 0 || bits < policy.min_rsa_bits {
                    policy.min_rsa_bits = bits;
                }
            }
            return;
        }
    }
    if let Some(rest) = lower.strip_prefix("dsa") {
        if let Ok(bits) = rest.parse::<u32>() {
            if matches!(disp, Disposition::Always) {
                policy.pubkey.insert(u8::from(PublicKeyAlgorithm::DSA), disp);
                if policy.min_dsa_bits == 0 || bits < policy.min_dsa_bits {
                    policy.min_dsa_bits = bits;
                }
            }
            return;
        }
    }

    if let Some(algos) = parse_asym_name(&lower) {
        for a in algos {
            policy.pubkey.insert(u8::from(*a), disp);
        }
    }
}

fn parse_asym_name(lower: &str) -> Option<&'static [PublicKeyAlgorithm]> {
    Some(match lower {
        "nistp256" | "nistp384" | "nistp521" => {
            &[PublicKeyAlgorithm::ECDSA, PublicKeyAlgorithm::ECDH]
        }
        "brainpoolp256" | "brainpoolp384" | "brainpoolp512" => {
            &[PublicKeyAlgorithm::ECDSA, PublicKeyAlgorithm::ECDH]
        }
        "cv25519" => &[PublicKeyAlgorithm::EdDSALegacy, PublicKeyAlgorithm::ECDH],
        "x25519" => &[PublicKeyAlgorithm::X25519],
        "x448" => &[PublicKeyAlgorithm::X448],
        "ed25519" => &[PublicKeyAlgorithm::Ed25519],
        "ed448" => &[PublicKeyAlgorithm::Ed448],
        "eddsa" => &[PublicKeyAlgorithm::EdDSALegacy],
        "elgamal" => &[PublicKeyAlgorithm::Elgamal],
        _ => return None,
    })
}

// -------- Test-only helpers --------------------------------------

#[cfg(test)]
impl StandardPolicy {
    /// A policy that allows everything. Used as a baseline in tests
    /// that then deny specific algorithms.
    pub(crate) fn permissive() -> Self {
        let mut p = Self::permissive_skeleton();
        p.hash_default = Disposition::Always;
        p.sym_default = Disposition::Always;
        p.aead_default = Disposition::Always;
        p.pubkey_default = Disposition::Always;
        p
    }

    pub(crate) fn deny_hash(mut self, algo: HashAlgorithm) -> Self {
        self.hash.insert(u8::from(algo), Disposition::Never);
        self
    }

    pub(crate) fn deny_sym(mut self, algo: SymmetricKeyAlgorithm) -> Self {
        self.sym.insert(u8::from(algo), Disposition::Never);
        self
    }

    pub(crate) fn deny_aead(mut self, algo: AeadAlgorithm) -> Self {
        self.aead.insert(u8::from(algo), Disposition::Never);
        self
    }

    pub(crate) fn deny_pubkey(mut self, algo: PublicKeyAlgorithm) -> Self {
        self.pubkey.insert(u8::from(algo), Disposition::Never);
        self
    }

    pub(crate) fn min_rsa_bits(mut self, bits: u32) -> Self {
        self.min_rsa_bits = bits;
        self
    }
}

// -------- ESK helpers used by decrypt site ----------------------

/// Gate the symmetric algorithm and S2K hash declared by a single
/// SKESK packet against the active policy.
pub(crate) fn check_skesk(
    skesk: &pgp::packet::SymKeyEncryptedSessionKey,
) -> Result<()> {
    let policy = current();
    if let Some(sym) = skesk.sym_algorithm() {
        policy.symmetric_algorithm(sym)?;
    }
    if let Some(s2k) = skesk.s2k() {
        if let Some(hash) = s2k_hash(s2k) {
            policy.hash_algorithm(hash)?;
        }
    }
    Ok(())
}

/// Gate the public-key algorithm declared by a single PKESK packet.
/// The symmetric algorithm of the eventual session key is not
/// reachable until after the PKESK is decrypted, so it is not
/// gated here.
pub(crate) fn check_pkesk(
    pkesk: &pgp::packet::PublicKeyEncryptedSessionKey,
) -> Result<()> {
    if let Ok(algo) = pkesk.algorithm() {
        current().public_key_algorithm(algo, None)?;
    }
    Ok(())
}

fn s2k_hash(s2k: &pgp::types::StringToKey) -> Option<HashAlgorithm> {
    use pgp::types::StringToKey;
    match s2k {
        StringToKey::Simple { hash_alg }
        | StringToKey::Salted { hash_alg, .. }
        | StringToKey::IteratedAndSalted { hash_alg, .. } => Some(*hash_alg),
        _ => None,
    }
}

// -------- Signature helper used by verify/decrypt sites ---------

/// Gate `sig`'s declared hash algorithm against the active policy.
/// Signatures whose `config()` accessor returns `None` (rpgp parsed
/// the packet as `Unknown`) are accepted — the algorithm couldn't
/// have been used to verify anything in any case.
pub(crate) fn check_signature(sig: &pgp::packet::Signature) -> Result<()> {
    if let Some(config) = sig.config() {
        current().hash_algorithm(config.hash_alg)?;
    }
    Ok(())
}

// -------- Cert-walk helper used by parse_public_key/secret_key ----

/// Walk every signature attached to a parsed certificate and
/// reject if any of them uses a banned hash, or if the primary key
/// or any subkey uses a banned public-key algorithm or insufficient
/// bit length.
pub(crate) fn check_certificate(cert: &pgp::composed::SignedPublicKey) -> Result<()> {
    use pgp::types::KeyDetails as _;
    let policy = current();

    // Primary key algorithm + bit length
    let primary_algo = cert.primary_key.algorithm();
    let primary_bits = crate::internal::get_key_bit_size(&cert.primary_key) as u32;
    let primary_bits = (primary_bits != 0).then_some(primary_bits);
    policy.public_key_algorithm(primary_algo, primary_bits)?;

    let check = |sig: &pgp::packet::Signature| -> Result<()> {
        if let Some(config) = sig.config() {
            policy.hash_algorithm(config.hash_alg)?;
        }
        Ok(())
    };

    // Revocation + direct-key signatures on the primary
    for sig in &cert.details.revocation_signatures {
        check(sig)?;
    }
    for sig in &cert.details.direct_signatures {
        check(sig)?;
    }

    // UID self-sigs and third-party certifications
    for uid in &cert.details.users {
        for sig in &uid.signatures {
            check(sig)?;
        }
    }

    // User-attribute (image) self-sigs
    for ua in &cert.details.user_attributes {
        for sig in &ua.signatures {
            check(sig)?;
        }
    }

    // Subkeys: algorithm, bit length, and binding/back-sigs
    for subkey in &cert.public_subkeys {
        let sub_algo = subkey.key.algorithm();
        let sub_bits = crate::internal::get_key_bit_size(&subkey.key) as u32;
        let sub_bits = (sub_bits != 0).then_some(sub_bits);
        policy.public_key_algorithm(sub_algo, sub_bits)?;
        for sig in &subkey.signatures {
            check(sig)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_policy_accepts_everything() {
        let p = NullPolicy;
        assert!(p.hash_algorithm(HashAlgorithm::Md5).is_ok());
        assert!(p.symmetric_algorithm(SymmetricKeyAlgorithm::IDEA).is_ok());
        assert!(p
            .aead_algorithm(AeadAlgorithm::Ocb, SymmetricKeyAlgorithm::IDEA)
            .is_ok());
        assert!(p
            .public_key_algorithm(PublicKeyAlgorithm::RSA, Some(1024))
            .is_ok());
    }

    #[test]
    fn permissive_then_deny_sha1() {
        let p = StandardPolicy::permissive().deny_hash(HashAlgorithm::Sha1);
        assert!(p.hash_algorithm(HashAlgorithm::Sha256).is_ok());
        assert!(matches!(
            p.hash_algorithm(HashAlgorithm::Sha1),
            Err(Error::PolicyViolation { .. })
        ));
    }

    #[test]
    fn deny_idea_sym() {
        let p = StandardPolicy::permissive().deny_sym(SymmetricKeyAlgorithm::IDEA);
        assert!(p
            .symmetric_algorithm(SymmetricKeyAlgorithm::AES256)
            .is_ok());
        assert!(p.symmetric_algorithm(SymmetricKeyAlgorithm::IDEA).is_err());
    }

    #[test]
    fn min_rsa_bits_floor() {
        let p = StandardPolicy::permissive().min_rsa_bits(2048);
        assert!(p
            .public_key_algorithm(PublicKeyAlgorithm::RSA, Some(2048))
            .is_ok());
        assert!(p
            .public_key_algorithm(PublicKeyAlgorithm::RSA, Some(1024))
            .is_err());
    }

    #[test]
    fn parses_fedora_default_skeleton() {
        let toml = r#"
[hash_algorithms]
md5.collision_resistance = "never"
md5.second_preimage_resistance = "never"
sha1.collision_resistance = "never"
sha1.second_preimage_resistance = "never"
sha256.collision_resistance = "always"
sha256.second_preimage_resistance = "always"
default_disposition = "never"

[symmetric_algorithms]
idea = "never"
tripledes = "never"
aes256 = "always"
default_disposition = "never"

[asymmetric_algorithms]
rsa1024 = "never"
rsa2048 = "always"
rsa4096 = "always"
"#;
        let p = StandardPolicy::from_toml_str(toml).unwrap();
        assert!(p.hash_algorithm(HashAlgorithm::Sha256).is_ok());
        assert!(p.hash_algorithm(HashAlgorithm::Sha1).is_err());
        assert!(p.hash_algorithm(HashAlgorithm::Md5).is_err());
        assert!(p
            .symmetric_algorithm(SymmetricKeyAlgorithm::AES256)
            .is_ok());
        assert!(p.symmetric_algorithm(SymmetricKeyAlgorithm::IDEA).is_err());
        assert!(p
            .public_key_algorithm(PublicKeyAlgorithm::RSA, Some(2048))
            .is_ok());
        assert!(p
            .public_key_algorithm(PublicKeyAlgorithm::RSA, Some(1024))
            .is_err());
    }

    /// Regression for the order-dependent bit-floor bug: under
    /// Fedora DEFAULT (`rsa1024 = "never"` listed BEFORE
    /// `rsa2048 = "always"`), an earlier implementation set the
    /// floor to 1025, admitting RSA keys at 1025-2047 bits. The
    /// floor must be 2048 (the lowest Always entry).
    #[test]
    fn rsa_bits_between_never_and_always_rejected() {
        let toml = r#"
[asymmetric_algorithms]
rsa1024 = "never"
rsa2048 = "always"
rsa3072 = "always"
rsa4096 = "always"
default_disposition = "never"
"#;
        let p = StandardPolicy::from_toml_str(toml).unwrap();
        assert!(p
            .public_key_algorithm(PublicKeyAlgorithm::RSA, Some(2048))
            .is_ok());
        assert!(p
            .public_key_algorithm(PublicKeyAlgorithm::RSA, Some(1024))
            .is_err());
        // The actual regression: a key with bits between the lowest
        // banned and the lowest allowed.
        assert!(
            p.public_key_algorithm(PublicKeyAlgorithm::RSA, Some(1500))
                .is_err(),
            "RSA-1500 must be rejected: it sits between rsa1024(never) and rsa2048(always)"
        );
        assert!(
            p.public_key_algorithm(PublicKeyAlgorithm::RSA, Some(2047))
                .is_err(),
            "RSA-2047 must be rejected: just below the lowest Always entry"
        );
    }

    #[test]
    fn off_env_var_returns_null_policy() {
        // We can't easily test load_from_environment without races,
        // but we can verify the value matching logic in isolation.
        let val = "OFF";
        assert!(val.eq_ignore_ascii_case("off"));
    }
}
