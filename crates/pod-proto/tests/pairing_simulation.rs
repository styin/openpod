//! Integration tests: pairing ceremony simulation.
//!
//! Simulates both sides of the TOFU + SAS pairing flow (Manifesto §2.7.3):
//!
//! 1. Both nodes generate keypairs and derive PodIds.
//! 2. They perform a TLS handshake (simulated by shared exporter key).
//! 3. Both independently derive the SAS — the codes must match.
//! 4. The QR/OOB path mixes in an additional nonce via HMAC.

use pod_proto::identity::{Keypair, PodId};
use pod_proto::sas::{derive_sas, derive_sas_with_oob};

// Simulated TLS exporter key (in a real pairing, this comes from
// TLS-Exporter("OPENPOD-SAS", "", 32) which already incorporates the full
// handshake transcript per RFC 8446 §7.5).
const TLS_EXPORTER_KEY: &[u8] = b"simulated-tls-exporter-32-bytes!";
const OOB_NONCE: &[u8] = b"qr-code-nonce-32-bytes-exactly!!";

// ---------------------------------------------------------------------------
// Manual pairing: both sides derive the same SAS
// ---------------------------------------------------------------------------

#[test]
fn both_sides_derive_same_sas() {
    // Client side.
    let client_sas = derive_sas(TLS_EXPORTER_KEY).expect("client SAS derivation should succeed");

    // Agent side — same exporter key, same result.
    let agent_sas = derive_sas(TLS_EXPORTER_KEY).expect("agent SAS derivation should succeed");

    assert_eq!(
        client_sas, agent_sas,
        "both sides must derive the same SAS code"
    );
    assert_eq!(client_sas.len(), 6);
    assert!(client_sas.chars().all(|c| c.is_ascii_digit()));
}

// ---------------------------------------------------------------------------
// QR pairing: OOB nonce changes the SAS
// ---------------------------------------------------------------------------

#[test]
fn oob_nonce_changes_sas() {
    let manual_sas = derive_sas(TLS_EXPORTER_KEY).expect("manual SAS should succeed");

    let qr_sas = derive_sas_with_oob(TLS_EXPORTER_KEY, OOB_NONCE).expect("QR SAS should succeed");

    assert_ne!(manual_sas, qr_sas, "OOB nonce must produce a different SAS");
    assert_eq!(qr_sas.len(), 6);
}

#[test]
fn both_sides_derive_same_oob_sas() {
    let client_sas =
        derive_sas_with_oob(TLS_EXPORTER_KEY, OOB_NONCE).expect("client OOB SAS should succeed");

    let agent_sas =
        derive_sas_with_oob(TLS_EXPORTER_KEY, OOB_NONCE).expect("agent OOB SAS should succeed");

    assert_eq!(
        client_sas, agent_sas,
        "both sides must derive the same OOB SAS code"
    );
}

// ---------------------------------------------------------------------------
// MITM detection: different TLS sessions produce different SAS
// ---------------------------------------------------------------------------

#[test]
fn mitm_produces_different_sas() {
    // Legitimate session.
    let legit_sas = derive_sas(TLS_EXPORTER_KEY).expect("legit SAS should succeed");

    // Attacker's session has different TLS exporter key (different session secret).
    let attacker_exporter = b"attacker-controls-tls-session!!!";
    let mitm_sas = derive_sas(attacker_exporter).expect("MITM SAS should succeed");

    assert_ne!(
        legit_sas, mitm_sas,
        "different TLS sessions must produce different SAS codes"
    );
}

// ---------------------------------------------------------------------------
// Full pairing ceremony: identities + SAS
// ---------------------------------------------------------------------------

#[test]
fn full_pairing_ceremony() {
    // --- Setup: both nodes generate identities ---
    let client_kp = Keypair::generate();
    let agent_kp = Keypair::generate();

    let client_pod_id = PodId::from_public_key(&client_kp.public_key_bytes());
    let agent_pod_id = PodId::from_public_key(&agent_kp.public_key_bytes());

    // Identities must be distinct.
    assert_ne!(client_pod_id, agent_pod_id);

    // --- Handshake: TLS session established (simulated) ---
    // In reality, TLS_EXPORTER_KEY comes from TLS-Exporter("OPENPOD-SAS", "", 32).
    // The exporter already incorporates the full handshake transcript (RFC 8446 §7.5).

    // --- SAS verification ---
    let client_sas = derive_sas(TLS_EXPORTER_KEY).expect("client SAS should succeed");
    let agent_sas = derive_sas(TLS_EXPORTER_KEY).expect("agent SAS should succeed");

    // Both sides display their SAS. User verifies they match.
    assert_eq!(client_sas, agent_sas);

    // --- After successful verification: both sides store each other's PodId ---
    // Trust store stores the full 32-byte SHA-256 PodId (from_public_key),
    // not the truncated display string.
    assert_eq!(agent_pod_id.as_bytes().len(), 32);
    assert_eq!(client_pod_id.as_bytes().len(), 32);

    // Display strings are for human identification only.
    assert_eq!(agent_pod_id.to_display().len(), 31); // 28 chars + 3 dashes
    assert_eq!(client_pod_id.to_display().len(), 31);
}

// ---------------------------------------------------------------------------
// SAS exporter label constant is accessible
// ---------------------------------------------------------------------------

#[test]
fn sas_exporter_label_is_defined() {
    assert_eq!(pod_proto::sas::SAS_EXPORTER_LABEL, "OPENPOD-SAS");
}
