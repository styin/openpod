//! Integration tests: end-to-end identity chain.
//!
//! Exercises the full path from keypair generation through PodId derivation
//! to certificate generation — the same sequence a real OpenPod node performs
//! on first startup.

use pod_proto::identity::{Certificate, Keypair, PodId};

/// Reference epoch: 2025-01-01 00:00:00 UTC.
const JAN_1_2025: i64 = 1735689600;

// ---------------------------------------------------------------------------
// Full identity chain: keypair → PodId → certificate
// ---------------------------------------------------------------------------

#[test]
fn full_identity_chain() {
    // 1. Generate a keypair (node first boot).
    let keypair = Keypair::generate();

    // 2. Derive PodId from the public key.
    let pod_id = PodId::from_public_key(&keypair.public_key_bytes());

    // 3. Generate a self-signed certificate wrapping the same key.
    let cert =
        Certificate::generate(&keypair, JAN_1_2025).expect("certificate generation should succeed");

    // All three artifacts should be usable.
    assert_eq!(pod_id.to_display().len(), 31); // 28 chars + 3 dashes
    assert!(!cert.der().is_empty());
    assert!(cert.pem().starts_with("-----BEGIN CERTIFICATE-----"));
}

// ---------------------------------------------------------------------------
// Keypair persistence → PodId stability
// ---------------------------------------------------------------------------

#[test]
fn persisted_keypair_produces_same_pod_id() {
    let original = Keypair::generate();
    let pod_id_before = PodId::from_public_key(&original.public_key_bytes());

    // Simulate persisting and reloading.
    let secret = original.secret_bytes();
    let restored = Keypair::from_secret_bytes(&secret);
    let pod_id_after = PodId::from_public_key(&restored.public_key_bytes());

    assert_eq!(
        pod_id_before.to_display(),
        pod_id_after.to_display(),
        "PodId must be stable across keypair persist/reload"
    );
    assert_eq!(
        pod_id_before.as_bytes(),
        pod_id_after.as_bytes(),
        "full hash must match after reload"
    );
}

// ---------------------------------------------------------------------------
// Certificate rotation with same identity
// ---------------------------------------------------------------------------

#[test]
fn certificate_rotation_preserves_pod_id() {
    let keypair = Keypair::generate();
    let pod_id = PodId::from_public_key(&keypair.public_key_bytes());

    // Generate initial certificate.
    let cert1 = Certificate::generate(&keypair, JAN_1_2025).expect("first cert should succeed");

    // Day 23: rotation needed.
    assert!(cert1.needs_rotation(JAN_1_2025 + 23 * 86400));

    // Generate rotated certificate (same keypair, new validity window).
    let cert2 = Certificate::generate(&keypair, JAN_1_2025 + 23 * 86400)
        .expect("rotated cert should succeed");

    // PodId unchanged — identity is the key, not the cert.
    let pod_id_after = PodId::from_public_key(&keypair.public_key_bytes());
    assert_eq!(pod_id.to_display(), pod_id_after.to_display());

    // But the certificates are different (different validity windows).
    assert_ne!(cert1.der(), cert2.der());

    // New cert should not need immediate rotation.
    assert!(!cert2.needs_rotation(JAN_1_2025 + 23 * 86400));
}

// ---------------------------------------------------------------------------
// PodId display ↔ parse roundtrip from live keypair
// ---------------------------------------------------------------------------

#[test]
fn pod_id_display_parse_roundtrip_from_keypair() {
    let keypair = Keypair::generate();
    let pod_id = PodId::from_public_key(&keypair.public_key_bytes());
    let display = pod_id.to_display();

    // Parse from display string.
    let parsed = PodId::from_display(&display).expect("should parse own display output");

    // Display output must match.
    assert_eq!(parsed.to_display(), display);

    // The short_id must be the first group.
    let first_group = display.split('-').next().unwrap();
    assert_eq!(pod_id.short_id(), first_group);
}

// ---------------------------------------------------------------------------
// Two distinct nodes produce distinct identities
// ---------------------------------------------------------------------------

#[test]
fn two_nodes_have_distinct_identities() {
    let kp1 = Keypair::generate();
    let kp2 = Keypair::generate();

    let pod_id1 = PodId::from_public_key(&kp1.public_key_bytes());
    let pod_id2 = PodId::from_public_key(&kp2.public_key_bytes());

    assert_ne!(
        pod_id1, pod_id2,
        "two random keys must produce different PodIds"
    );
    assert_ne!(pod_id1.to_display(), pod_id2.to_display());
    assert_ne!(pod_id1.short_id(), pod_id2.short_id());
}

// ---------------------------------------------------------------------------
// PKCS#8 DER from keypair feeds into certificate generation
// ---------------------------------------------------------------------------

#[test]
fn pkcs8_bridge_works_end_to_end() {
    // This test explicitly exercises the ed25519-dalek → rcgen PKCS#8 bridge
    // that was identified as a technical risk.
    let keypair = Keypair::generate();

    // Step 1: Export PKCS#8 DER.
    let pkcs8_der = keypair
        .to_pkcs8_der()
        .expect("PKCS#8 export should succeed");
    assert!(!pkcs8_der.is_empty());

    // Step 2: Certificate generation uses the same PKCS#8 internally.
    let cert =
        Certificate::generate(&keypair, JAN_1_2025).expect("certificate generation should succeed");

    assert!(!cert.der().is_empty());
    assert_eq!(cert.not_after_epoch(), JAN_1_2025 + 30 * 86400);
}

// ---------------------------------------------------------------------------
// PodId from_hash roundtrip
// ---------------------------------------------------------------------------

#[test]
fn pod_id_from_hash_preserves_full_hash() {
    let keypair = Keypair::generate();
    let pod_id = PodId::from_public_key(&keypair.public_key_bytes());

    // Reconstruct from the full hash.
    let hash = *pod_id.as_bytes();
    let reconstructed = PodId::from_hash(hash);

    assert_eq!(pod_id, reconstructed);
    assert_eq!(pod_id.as_bytes(), reconstructed.as_bytes());
    assert_eq!(pod_id.to_display(), reconstructed.to_display());
}
