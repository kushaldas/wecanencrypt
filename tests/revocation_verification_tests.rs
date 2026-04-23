//! Integration tests for cryptographic verification of revocation
//! signatures (ADR 0004).
//!
//! rpgp's parser admits any packet tagged `KeyRevocation` (0x20),
//! `SubkeyRevocation` (0x28), or `CertRevocation` (0x30) into the
//! parsed key without verifying the signature. wecanencrypt must
//! verify those signatures against the primary key before honoring
//! them, otherwise an attacker who can inject packets into a cert
//! (keyserver poisoning, MITM on HKP fetch, tampered file) could
//! forge revocations and cause denial-of-service on legitimate keys.
//!
//! Each test here constructs a forged or genuine revocation by
//! splicing a signature into a serialized key, then asserts that the
//! public API's verdict matches the cryptographic truth rather than
//! the packet-type tag.

use pgp::composed::{
    Deserializable, SignedKeyDetails, SignedPublicSubKey, SignedSecretKey, SignedSecretSubKey,
};
use pgp::packet::{self, SignatureConfig, SignatureType, Subpacket, SubpacketData};
use pgp::ser::Serialize;
use pgp::types::{KeyDetails, KeyVersion, Password, SignedUser, Tag, Timestamp};
use rand::thread_rng;

use wecanencrypt::{create_key_simple, parse_key_bytes, revoke_uid, sign_bytes, verify_bytes};

fn parse_secret(bytes: &[u8]) -> SignedSecretKey {
    let (parsed, _) = SignedSecretKey::from_armor_single(bytes)
        .or_else(|_| SignedSecretKey::from_bytes(bytes).map(|k| (k, Default::default())))
        .expect("parse secret key");
    parsed
}

/// Build a SubkeyRevocation signature over `subkey` issued by `signer`.
/// Uses rpgp's `sign_subkey_binding` which hashes primary+subkey; the
/// signature type byte (0x28) comes from the `SignatureConfig::typ`.
fn forge_subkey_revocation(
    signer: &SignedSecretKey,
    signer_pw: &str,
    subkey: &SignedSecretSubKey,
) -> packet::Signature {
    let mut rng = thread_rng();
    let mut config = SignatureConfig::from_key(
        &mut rng,
        &signer.primary_key,
        SignatureType::SubkeyRevocation,
    )
    .expect("config");
    config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now())).unwrap(),
        Subpacket::regular(SubpacketData::IssuerFingerprint(
            signer.primary_key.fingerprint(),
        ))
        .unwrap(),
    ];
    if signer.primary_key.version() <= KeyVersion::V4 {
        config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
            signer.primary_key.legacy_key_id(),
        ))
        .unwrap()];
    }
    // Hash over the public form of both keys so the signature verifies
    // against a SignedPublicSubKey (which is what `to_public_key()`
    // produces). Signing with the raw secret-key packet would hash a
    // different byte stream and always fail verification.
    config
        .sign_subkey_binding(
            &signer.primary_key,
            signer.primary_key.public_key(),
            &Password::from(signer_pw),
            subkey.key.public_key(),
        )
        .expect("sign subkey revocation")
}

/// Build a CertRevocation signature over `user` issued by `signer`.
fn forge_cert_revocation(
    signer: &SignedSecretKey,
    signer_pw: &str,
    user: &SignedUser,
) -> packet::Signature {
    let mut rng = thread_rng();
    let mut config =
        SignatureConfig::from_key(&mut rng, &signer.primary_key, SignatureType::CertRevocation)
            .expect("config");
    config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now())).unwrap(),
        Subpacket::regular(SubpacketData::IssuerFingerprint(
            signer.primary_key.fingerprint(),
        ))
        .unwrap(),
    ];
    if signer.primary_key.version() <= KeyVersion::V4 {
        config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
            signer.primary_key.legacy_key_id(),
        ))
        .unwrap()];
    }
    config
        .sign_certification(
            &signer.primary_key,
            signer.primary_key.public_key(),
            &Password::from(signer_pw),
            Tag::UserId,
            &user.id,
        )
        .expect("sign UID revocation")
}

/// Reassemble `victim` with `extra_sig` appended to the first secret
/// subkey's signatures. The signature is *not* cryptographically
/// verified during parse — rpgp stores any packet with matching type.
fn splice_into_subkey(victim: &SignedSecretKey, extra_sig: packet::Signature) -> Vec<u8> {
    assert!(
        !victim.secret_subkeys.is_empty(),
        "victim must have at least one secret subkey"
    );
    let mut new_subkeys = victim.secret_subkeys.clone();
    let target = &mut new_subkeys[0];
    let mut sigs = target.signatures.clone();
    sigs.push(extra_sig);
    *target = SignedSecretSubKey::new(target.key.clone(), sigs);

    let rebuilt = SignedSecretKey::new(
        victim.primary_key.clone(),
        victim.details.clone(),
        victim.public_subkeys.clone(),
        new_subkeys,
    );
    rebuilt.to_bytes().expect("serialize tampered key")
}

/// Reassemble `victim` with `extra_sig` appended to the first UID's
/// signatures.
fn splice_into_uid(victim: &SignedSecretKey, extra_sig: packet::Signature) -> Vec<u8> {
    assert!(
        !victim.details.users.is_empty(),
        "victim must have at least one user ID"
    );
    let mut new_users = victim.details.users.clone();
    let target = &mut new_users[0];
    let mut sigs = target.signatures.clone();
    sigs.push(extra_sig);
    *target = SignedUser::new(target.id.clone(), sigs);

    let new_details = SignedKeyDetails::new(
        victim.details.revocation_signatures.clone(),
        victim.details.direct_signatures.clone(),
        new_users,
        victim.details.user_attributes.clone(),
    );
    let rebuilt = SignedSecretKey::new(
        victim.primary_key.clone(),
        new_details,
        victim.public_subkeys.clone(),
        victim.secret_subkeys.clone(),
    );
    rebuilt.to_bytes().expect("serialize tampered key")
}

/// A SubkeyRevocation signed by an *unrelated* key must NOT mark the
/// victim's subkey as revoked. Trusting the packet-type tag would
/// let an attacker forge a DoS against any signing/encryption subkey.
#[test]
fn forged_subkey_revocation_is_ignored() {
    let victim = create_key_simple("pw_v", &["Victim <v@example.com>"]).unwrap();
    let attacker = create_key_simple("pw_a", &["Attacker <a@example.com>"]).unwrap();

    let victim_sec = parse_secret(&victim.secret_key);
    let attacker_sec = parse_secret(&attacker.secret_key);
    let victim_subkey = victim_sec
        .secret_subkeys
        .first()
        .expect("victim has a subkey");

    let forged = forge_subkey_revocation(&attacker_sec, "pw_a", victim_subkey);
    let tampered = splice_into_subkey(&victim_sec, forged);

    // Sanity: the packet landed in the parsed key — rpgp accepts it.
    let parsed = SignedSecretKey::from_bytes(&tampered[..]).expect("reparse");
    assert!(
        parsed.secret_subkeys[0]
            .signatures
            .iter()
            .any(|s| s.typ() == Some(SignatureType::SubkeyRevocation)),
        "forged SubkeyRevocation packet must be present after splice"
    );

    // The public API must not honor it.
    let info = parse_key_bytes(&tampered, false).expect("parse_key_bytes");
    assert!(
        !info.subkeys.is_empty(),
        "subkey must still be surfaced (forged revocation must not filter it)"
    );
    assert!(
        !info.subkeys[0].is_revoked,
        "forged SubkeyRevocation (wrong issuer) must not flip is_revoked"
    );
}

/// A genuine self-signed SubkeyRevocation must be honored. This is
/// the positive control — without it, a too-strict verifier could
/// reject all SubkeyRevocations including legitimate ones.
#[test]
fn genuine_subkey_revocation_is_honored() {
    let victim = create_key_simple("pw_v", &["Victim <v@example.com>"]).unwrap();
    let victim_sec = parse_secret(&victim.secret_key);
    let victim_subkey = victim_sec
        .secret_subkeys
        .first()
        .expect("victim has a subkey");
    let revoked_fp = hex::encode_upper(victim_subkey.key.fingerprint().as_bytes());

    let genuine = forge_subkey_revocation(&victim_sec, "pw_v", victim_subkey);
    let revoked_bytes = splice_into_subkey(&victim_sec, genuine);

    // With allow_expired=true, `extract_subkey_info` does not filter
    // revoked/expired subkeys, so the revoked subkey still surfaces
    // and we can inspect its `is_revoked` flag.
    let info = parse_key_bytes(&revoked_bytes, true).expect("parse_key_bytes");
    let sk = info
        .subkeys
        .iter()
        .find(|sk| sk.fingerprint == revoked_fp)
        .expect("revoked subkey must still be listed when allow_expired=true");
    assert!(
        sk.is_revoked,
        "genuine self-signed SubkeyRevocation must set is_revoked=true"
    );

    // With allow_expired=false, the revoked subkey must be filtered
    // out of the "available" view.
    let info_valid = parse_key_bytes(&revoked_bytes, false).expect("parse_key_bytes");
    assert!(
        info_valid
            .subkeys
            .iter()
            .all(|sk| sk.fingerprint != revoked_fp),
        "revoked subkey must not appear in the valid-only view"
    );
}

/// A CertRevocation signed by an unrelated key must NOT mark the
/// UID as revoked. Trusting the packet-type tag would let an attacker
/// surface a forged "revocation time" on someone else's key in
/// downstream UIs.
#[test]
fn forged_cert_revocation_is_ignored() {
    let victim = create_key_simple("pw_v", &["Victim <v@example.com>"]).unwrap();
    let attacker = create_key_simple("pw_a", &["Attacker <a@example.com>"]).unwrap();

    let victim_sec = parse_secret(&victim.secret_key);
    let attacker_sec = parse_secret(&attacker.secret_key);
    let victim_user = victim_sec.details.users.first().expect("victim has a UID");

    let forged = forge_cert_revocation(&attacker_sec, "pw_a", victim_user);
    let tampered = splice_into_uid(&victim_sec, forged);

    // Sanity: the packet landed in the parsed key.
    let parsed = SignedSecretKey::from_bytes(&tampered[..]).expect("reparse");
    assert!(
        parsed.details.users[0]
            .signatures
            .iter()
            .any(|s| s.typ() == Some(SignatureType::CertRevocation)),
        "forged CertRevocation packet must be present after splice"
    );

    // Public API must ignore it.
    let info = parse_key_bytes(&tampered, false).expect("parse_key_bytes");
    assert!(!info.user_ids.is_empty(), "UID must still be surfaced");
    assert!(
        !info.user_ids[0].revoked,
        "forged CertRevocation (wrong issuer) must not flip user_ids[].revoked"
    );
    assert!(
        info.user_ids[0].revocation_time.is_none(),
        "forged CertRevocation must not populate revocation_time"
    );
}

/// A genuine self-signed UID revocation (produced by `revoke_uid`)
/// must be honored. Positive control matching the forged-cert test.
#[test]
fn genuine_cert_revocation_is_honored() {
    let key = create_key_simple("pw", &["Alice <alice@example.com>"]).unwrap();
    let revoked =
        revoke_uid(&key.secret_key, "Alice <alice@example.com>", "pw").expect("revoke_uid");
    let info = parse_key_bytes(&revoked, false).expect("parse_key_bytes");
    let uid = info
        .user_ids
        .iter()
        .find(|u| u.value == "Alice <alice@example.com>")
        .expect("UID present");
    assert!(
        uid.revoked,
        "genuine self-signed CertRevocation must set revoked=true"
    );
    assert!(
        uid.revocation_time.is_some(),
        "genuine CertRevocation must populate revocation_time"
    );
}

/// A forged SubkeyRevocation must not block signature verification
/// when the victim's signing subkey is still usable. This is the
/// end-to-end signal that the fix closes a DoS vector in verify.rs.
#[test]
fn forged_subkey_revocation_does_not_block_verify() {
    let signer = create_key_simple("pw", &["Signer <s@example.com>"]).unwrap();
    let attacker = create_key_simple("pw_a", &["Attacker <a@example.com>"]).unwrap();

    // Signer produces a legitimate signature first (uses their signing subkey).
    let message = b"hello, world";
    let signed = sign_bytes(&signer.secret_key, message, "pw").expect("sign_bytes");

    // Attacker forges a SubkeyRevocation on the signer's subkey.
    let signer_sec = parse_secret(&signer.secret_key);
    let attacker_sec = parse_secret(&attacker.secret_key);
    let target = signer_sec.secret_subkeys.first().expect("signing subkey");
    let forged = forge_subkey_revocation(&attacker_sec, "pw_a", target);

    // Splice into a PUBLIC export of the signer's key (that's what a
    // verifier would have).
    let tampered = splice_into_subkey(&signer_sec, forged);
    // Reparse as public (to_bytes serializes as secret; we re-convert).
    let tampered_sec = SignedSecretKey::from_bytes(&tampered[..]).unwrap();
    let tampered_public: pgp::composed::SignedPublicKey = tampered_sec.into();
    let tampered_pub_bytes = tampered_public.to_bytes().expect("serialize public");

    // If the library trusted the forged revocation, it would reject
    // the signature. With verified revocation, it should still pass.
    let ok = verify_bytes(&tampered_pub_bytes, &signed).expect("verify_bytes");
    assert!(
        ok,
        "forged SubkeyRevocation must not cause a legitimate signature to fail verification"
    );
}

// Silence unused-import warnings when features are minimal.
#[allow(dead_code)]
fn _unused(_: SignedPublicSubKey) {}
