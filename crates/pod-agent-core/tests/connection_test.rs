//! Integration tests: first online QUIC connection.
//!
//! These tests spin up an agent endpoint on localhost, connect a client,
//! and verify that the mTLS handshake + protocol handshake succeed.

use std::sync::Arc;

use pod_agent_core::AgentEndpoint;
use pod_client_core::ClientEndpoint;
use pod_proto::identity::{Certificate, Keypair, PodId};
use pod_proto::trust::{MemoryTrustStore, TrustPolicy, TrustStore};

/// Reference epoch: 2025-01-01 00:00:00 UTC.
const JAN_1_2025: i64 = 1735689600;

/// Helper: generate a keypair + certificate + PodId.
fn make_identity() -> (Keypair, Certificate, PodId) {
    let kp = Keypair::generate();
    let cert = Certificate::generate(&kp, JAN_1_2025).expect("cert gen");
    let pod_id = PodId::from_public_key(&kp.public_key_bytes());
    (kp, cert, pod_id)
}

// ---------------------------------------------------------------------------
// Test: client connects to agent and handshake succeeds (pairing mode)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn client_connects_to_agent_and_handshake_succeeds() {
    let (agent_kp, agent_cert, agent_pod_id) = make_identity();
    let (client_kp, client_cert, client_pod_id) = make_identity();

    // Both sides use pairing mode (TOFU) so they auto-trust each other.
    let agent_store = Arc::new(MemoryTrustStore::new());
    let client_store = Arc::new(MemoryTrustStore::new());

    // Agent binds to localhost:0 (OS assigns a free port).
    let agent = AgentEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        &agent_kp,
        &agent_cert,
        agent_store.clone(),
        TrustPolicy::PairingMode,
    )
    .expect("agent should bind");

    let agent_addr = agent.local_addr().expect("should have local addr");

    // Client connects to agent.
    let client_endpoint = ClientEndpoint::new(
        &client_kp,
        &client_cert,
        client_store.clone(),
        TrustPolicy::PairingMode,
    )
    .expect("client endpoint should create");

    // Run both sides concurrently.
    let (agent_result, client_result) =
        tokio::join!(agent.accept(), client_endpoint.connect(agent_addr));

    let agent_conn = agent_result.expect("agent should accept");
    let client_conn = client_result.expect("client should connect");

    // Verify peer PodIds match expectations.
    assert_eq!(
        agent_conn.peer_pod_id().as_bytes(),
        client_pod_id.as_bytes(),
        "agent should see client's PodId"
    );
    assert_eq!(
        client_conn.peer_pod_id().as_bytes(),
        agent_pod_id.as_bytes(),
        "client should see agent's PodId"
    );

    // Verify trust stores were populated (pairing mode auto-trusts).
    assert!(agent_store.is_trusted(&client_pod_id));
    assert!(client_store.is_trusted(&agent_pod_id));

    // Clean up.
    agent.close();
    client_endpoint.close();
}

// ---------------------------------------------------------------------------
// Test: denied PodId is rejected at TLS level
// ---------------------------------------------------------------------------

#[tokio::test]
async fn denied_pod_id_rejected_at_tls() {
    let (agent_kp, agent_cert, _agent_pod_id) = make_identity();
    let (client_kp, client_cert, client_pod_id) = make_identity();

    // Agent denies the client's PodId before any connection attempt.
    let agent_store = Arc::new(MemoryTrustStore::new());
    agent_store.deny(client_pod_id);

    let client_store = Arc::new(MemoryTrustStore::new());

    let agent = AgentEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        &agent_kp,
        &agent_cert,
        agent_store,
        TrustPolicy::PairingMode, // Even in pairing mode, denied peers are rejected.
    )
    .expect("agent should bind");

    let agent_addr = agent.local_addr().expect("should have local addr");

    let client_endpoint = ClientEndpoint::new(
        &client_kp,
        &client_cert,
        client_store,
        TrustPolicy::PairingMode,
    )
    .expect("client endpoint should create");

    // Run both sides — one or both should fail.
    let (agent_result, client_result) =
        tokio::join!(agent.accept(), client_endpoint.connect(agent_addr));

    // At least one side should fail (the denied peer's TLS handshake is rejected).
    let either_failed = agent_result.is_err() || client_result.is_err();
    assert!(
        either_failed,
        "denied PodId should cause connection failure"
    );

    agent.close();
    client_endpoint.close();
}

// ---------------------------------------------------------------------------
// Test: strict mode rejects unknown peers
// ---------------------------------------------------------------------------

#[tokio::test]
async fn strict_mode_rejects_unknown_peer() {
    let (agent_kp, agent_cert, _agent_pod_id) = make_identity();
    let (client_kp, client_cert, _client_pod_id) = make_identity();

    // Agent uses strict mode — only pre-trusted peers accepted.
    // The client is NOT pre-trusted.
    let agent_store = Arc::new(MemoryTrustStore::new());
    let client_store = Arc::new(MemoryTrustStore::new());

    let agent = AgentEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        &agent_kp,
        &agent_cert,
        agent_store,
        TrustPolicy::Strict,
    )
    .expect("agent should bind");

    let agent_addr = agent.local_addr().expect("should have local addr");

    let client_endpoint = ClientEndpoint::new(
        &client_kp,
        &client_cert,
        client_store,
        TrustPolicy::PairingMode, // Client is willing, but agent is strict.
    )
    .expect("client endpoint should create");

    let (agent_result, client_result) =
        tokio::join!(agent.accept(), client_endpoint.connect(agent_addr));

    let either_failed = agent_result.is_err() || client_result.is_err();
    assert!(either_failed, "strict mode should reject unknown peer");

    agent.close();
    client_endpoint.close();
}

// ---------------------------------------------------------------------------
// Test: both sides derive the same TLS exporter key for SAS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn both_sides_derive_same_tls_exporter_key() {
    let (agent_kp, agent_cert, _) = make_identity();
    let (client_kp, client_cert, _) = make_identity();

    let agent_store = Arc::new(MemoryTrustStore::new());
    let client_store = Arc::new(MemoryTrustStore::new());

    let agent = AgentEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        &agent_kp,
        &agent_cert,
        agent_store,
        TrustPolicy::PairingMode,
    )
    .expect("agent should bind");

    let agent_addr = agent.local_addr().unwrap();

    let client_endpoint = ClientEndpoint::new(
        &client_kp,
        &client_cert,
        client_store,
        TrustPolicy::PairingMode,
    )
    .expect("client endpoint should create");

    let (agent_conn, client_conn) =
        tokio::join!(agent.accept(), client_endpoint.connect(agent_addr));

    let agent_conn = agent_conn.expect("agent should accept");
    let client_conn = client_conn.expect("client should connect");

    // Both sides export keying material — must match.
    let agent_key = agent_conn
        .export_keying_material()
        .expect("agent keying material");
    let client_key = client_conn
        .export_keying_material()
        .expect("client keying material");

    assert_eq!(
        agent_key, client_key,
        "both sides must derive the same TLS exporter key"
    );
    assert_eq!(agent_key.len(), 32);

    agent.close();
    client_endpoint.close();
}
