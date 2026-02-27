//! Integration tests: pairing ceremony simulation.
//!
//! Simulates both sides of the TOFU + SAS pairing flow (Manifesto §2.7.3):
//!
//! 1. Both nodes generate keypairs and derive PodIds.
//! 2. They perform a TLS handshake (simulated by shared exporter/random values).
//! 3. Both independently derive the SAS — the codes must match.
//! 4. The QR/OOB path mixes in an additional nonce.

use pod_proto::identity::{Keypair, PodId};
use pod_proto::sas::{derive_sas, derive_sas_with_oob};

// Simulated TLS session material (in a real pairing, these come from the
// TLS-Exporter and handshake random values).
const TLS_EXPORTER_KEY: &[u8] = b"simulated-tls-exporter-32-bytes!";
const CLIENT_RANDOM: &[u8] = b"client-random-from-tls-handshak";
const SERVER_RANDOM: &[u8] = b"server-random-from-tls-handshak";
const OOB_NONCE: &[u8] = b"qr-code-nonce-32-bytes-exactly!!";

// ---------------------------------------------------------------------------
// Manual pairing: both sides derive the same SAS
// ---------------------------------------------------------------------------

#[test]
fn both_sides_derive_same_sas() {
    // Client side.
    let client_sas = derive_sas(TLS_EXPORTER_KEY, CLIENT_RANDOM, SERVER_RANDOM)
        .expect("client SAS derivation should succeed");

    // Agent side — same inputs, same result.
    let agent_sas = derive_sas(TLS_EXPORTER_KEY, CLIENT_RANDOM, SERVER_RANDOM)
        .expect("agent SAS derivation should succeed");

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
    let manual_sas = derive_sas(TLS_EXPORTER_KEY, CLIENT_RANDOM, SERVER_RANDOM)
        .expect("manual SAS should succeed");

    let qr_sas = derive_sas_with_oob(TLS_EXPORTER_KEY, CLIENT_RANDOM, SERVER_RANDOM, OOB_NONCE)
        .expect("QR SAS should succeed");

    assert_ne!(manual_sas, qr_sas, "OOB nonce must produce a different SAS");
    assert_eq!(qr_sas.len(), 6);
}

#[test]
fn both_sides_derive_same_oob_sas() {
    let client_sas = derive_sas_with_oob(TLS_EXPORTER_KEY, CLIENT_RANDOM, SERVER_RANDOM, OOB_NONCE)
        .expect("client OOB SAS should succeed");

    let agent_sas = derive_sas_with_oob(TLS_EXPORTER_KEY, CLIENT_RANDOM, SERVER_RANDOM, OOB_NONCE)
        .expect("agent OOB SAS should succeed");

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
    let legit_sas = derive_sas(TLS_EXPORTER_KEY, CLIENT_RANDOM, SERVER_RANDOM)
        .expect("legit SAS should succeed");

    // Attacker's session has different TLS exporter key.
    let attacker_exporter = b"attacker-controls-tls-session!!!";
    let mitm_sas = derive_sas(attacker_exporter, CLIENT_RANDOM, SERVER_RANDOM)
        .expect("MITM SAS should succeed");

    assert_ne!(
        legit_sas, mitm_sas,
        "different TLS sessions must produce different SAS codes"
    );
}

#[test]
fn different_randoms_produce_different_sas() {
    let sas1 =
        derive_sas(TLS_EXPORTER_KEY, CLIENT_RANDOM, SERVER_RANDOM).expect("SAS 1 should succeed");

    let sas2 = derive_sas(
        TLS_EXPORTER_KEY,
        b"different-client-random-value-ok",
        SERVER_RANDOM,
    )
    .expect("SAS 2 should succeed");

    assert_ne!(sas1, sas2);
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
    // In reality, TLS_EXPORTER_KEY comes from TLS-Exporter("OPENPOD-PAIRING", "", 32).
    // CLIENT_RANDOM and SERVER_RANDOM come from the TLS handshake.

    // --- SAS verification ---
    let client_sas = derive_sas(TLS_EXPORTER_KEY, CLIENT_RANDOM, SERVER_RANDOM)
        .expect("client SAS should succeed");
    let agent_sas = derive_sas(TLS_EXPORTER_KEY, CLIENT_RANDOM, SERVER_RANDOM)
        .expect("agent SAS should succeed");

    // Both sides display their SAS. User verifies they match.
    assert_eq!(client_sas, agent_sas);

    // --- After successful verification: both sides store each other's PodId ---
    // (Trust store population — not yet implemented, but the PodIds are ready.)
    let client_stores_agent = agent_pod_id.to_display();
    let agent_stores_client = client_pod_id.to_display();

    // Verify stored PodIds can be parsed back.
    let parsed_agent =
        PodId::from_display(&client_stores_agent).expect("stored agent PodId should parse");
    let parsed_client =
        PodId::from_display(&agent_stores_client).expect("stored client PodId should parse");

    assert_eq!(parsed_agent.to_display(), agent_pod_id.to_display());
    assert_eq!(parsed_client.to_display(), client_pod_id.to_display());
}

// ---------------------------------------------------------------------------
// SAS exporter label constant is accessible
// ---------------------------------------------------------------------------

#[test]
fn sas_exporter_label_is_defined() {
    assert_eq!(pod_proto::sas::SAS_EXPORTER_LABEL, "OPENPOD-PAIRING");
}
