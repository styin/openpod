//! Integration tests: first online QUIC connection.
//!
//! These tests spin up an agent endpoint on localhost, connect a client,
//! and verify that the mTLS handshake + protocol handshake succeed.
//!
//! Run with `--nocapture` to see verbose protocol trace output:
//! ```sh
//! cargo test -p pod-agent-core --test connection_test -- --nocapture
//! ```

use std::sync::Arc;

use pod_agent_core::AgentEndpoint;
use pod_client_core::ClientEndpoint;
use pod_proto::identity::{Certificate, Keypair, PodId};
use pod_proto::trust::{MemoryTrustStore, TrustPolicy, TrustStore};

/// Reference epoch: 2025-01-01 00:00:00 UTC.
const JAN_1_2025: i64 = 1735689600;

/// Hex-encode a byte slice (lowercase).
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Init tracing subscriber (idempotent across tests via try_init).
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_target(true)
        .with_level(true)
        .try_init();
}

/// Helper: generate a keypair + certificate + PodId, with verbose output.
fn make_identity(label: &str) -> (Keypair, Certificate, PodId) {
    eprintln!("\n-- {label}: generating Ed25519 keypair...");
    let kp = Keypair::generate();
    let pub_hex = hex(&kp.public_key_bytes());
    eprintln!("   public key : {pub_hex}");

    eprintln!("-- {label}: generating self-signed X.509 certificate (30-day validity)...");
    let cert = Certificate::generate(&kp, JAN_1_2025).expect("cert gen");
    eprintln!("   cert DER   : {} bytes", cert.der().len());

    let pod_id = PodId::from_public_key(&kp.public_key_bytes());
    eprintln!("   PodId      : {pod_id}");
    eprintln!("   short_id   : {}", pod_id.short_id());

    (kp, cert, pod_id)
}

// ---------------------------------------------------------------------------
// Test: client connects to agent and handshake succeeds (pairing mode)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn client_connects_to_agent_and_handshake_succeeds() {
    init_tracing();
    eprintln!("\n{}", "=".repeat(72));
    eprintln!("TEST: client_connects_to_agent_and_handshake_succeeds");
    eprintln!("{}", "=".repeat(72));

    let (agent_kp, agent_cert, agent_pod_id) = make_identity("AGENT");
    let (client_kp, client_cert, client_pod_id) = make_identity("CLIENT");

    // Both sides use pairing mode (TOFU) so they auto-trust each other.
    let agent_store = Arc::new(MemoryTrustStore::new());
    let client_store = Arc::new(MemoryTrustStore::new());
    eprintln!("\n-- Trust stores: empty (pairing mode -- TOFU)");
    eprintln!("   agent_store.is_trusted(client)  = {}", agent_store.is_trusted(&client_pod_id));
    eprintln!("   client_store.is_trusted(agent)  = {}", client_store.is_trusted(&agent_pod_id));

    // Agent binds to localhost:0 (OS assigns a free port).
    eprintln!("\n-- AGENT: binding QUIC endpoint on 127.0.0.1:0 (TrustPolicy::PairingMode)...");
    let agent = AgentEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        &agent_kp,
        &agent_cert,
        agent_store.clone(),
        TrustPolicy::PairingMode,
    )
    .expect("agent should bind");

    let agent_addr = agent.local_addr().expect("should have local addr");
    eprintln!("   bound to   : {agent_addr}");

    // Client connects to agent.
    eprintln!("\n-- CLIENT: creating QUIC endpoint (TrustPolicy::PairingMode)...");
    let client_endpoint = ClientEndpoint::new(
        &client_kp,
        &client_cert,
        client_store.clone(),
        TrustPolicy::PairingMode,
    )
    .expect("client endpoint should create");

    // Run both sides concurrently.
    eprintln!("\n-- Running agent.accept() || client.connect({agent_addr})...");
    let (agent_result, client_result) =
        tokio::join!(agent.accept(), client_endpoint.connect(agent_addr));

    let agent_conn = agent_result.expect("agent should accept");
    let client_conn = client_result.expect("client should connect");
    eprintln!("   [ok] Both sides connected successfully");

    // Verify peer PodIds match expectations.
    eprintln!("\n-- Verifying peer PodIds...");
    eprintln!("   agent sees peer  : {}", agent_conn.peer_pod_id());
    eprintln!("   expected (client): {client_pod_id}");
    assert_eq!(
        agent_conn.peer_pod_id().as_bytes(),
        client_pod_id.as_bytes(),
        "agent should see client's PodId"
    );
    eprintln!("   client sees peer : {}", client_conn.peer_pod_id());
    eprintln!("   expected (agent) : {agent_pod_id}");
    assert_eq!(
        client_conn.peer_pod_id().as_bytes(),
        agent_pod_id.as_bytes(),
        "client should see agent's PodId"
    );
    eprintln!("   [ok] Peer PodIds match");

    // Verify trust stores were populated (pairing mode auto-trusts).
    eprintln!("\n-- Checking trust stores after TOFU...");
    eprintln!("   agent_store.is_trusted(client)  = {}", agent_store.is_trusted(&client_pod_id));
    eprintln!("   client_store.is_trusted(agent)  = {}", client_store.is_trusted(&agent_pod_id));
    assert!(agent_store.is_trusted(&client_pod_id));
    assert!(client_store.is_trusted(&agent_pod_id));
    eprintln!("   [ok] Both peers auto-trusted via TOFU");

    // Clean up.
    agent.close();
    client_endpoint.close();
    eprintln!("\n   [ok] PASS\n");
}

// ---------------------------------------------------------------------------
// Test: denied PodId is rejected at TLS level
// ---------------------------------------------------------------------------

#[tokio::test]
async fn denied_pod_id_rejected_at_tls() {
    init_tracing();
    eprintln!("\n{}", "=".repeat(72));
    eprintln!("TEST: denied_pod_id_rejected_at_tls");
    eprintln!("{}", "=".repeat(72));

    let (agent_kp, agent_cert, _agent_pod_id) = make_identity("AGENT");
    let (client_kp, client_cert, client_pod_id) = make_identity("CLIENT");

    // Agent denies the client's PodId before any connection attempt.
    let agent_store = Arc::new(MemoryTrustStore::new());
    eprintln!("\n-- AGENT: denying client PodId {client_pod_id} before connection...");
    agent_store.deny(client_pod_id.clone());
    eprintln!("   agent_store.is_denied(client) = {}", agent_store.is_denied(&client_pod_id));

    let client_store = Arc::new(MemoryTrustStore::new());

    eprintln!("\n-- AGENT: binding (PairingMode, but client is pre-denied)...");
    let agent = AgentEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        &agent_kp,
        &agent_cert,
        agent_store,
        TrustPolicy::PairingMode, // Even in pairing mode, denied peers are rejected.
    )
    .expect("agent should bind");

    let agent_addr = agent.local_addr().expect("should have local addr");
    eprintln!("   bound to: {agent_addr}");

    eprintln!("\n-- CLIENT: creating endpoint and attempting connection...");
    let client_endpoint = ClientEndpoint::new(
        &client_kp,
        &client_cert,
        client_store,
        TrustPolicy::PairingMode,
    )
    .expect("client endpoint should create");

    // Run both sides -- one or both should fail.
    eprintln!("-- Running agent.accept() || client.connect({agent_addr})...");
    let (agent_result, client_result) =
        tokio::join!(agent.accept(), client_endpoint.connect(agent_addr));

    eprintln!("\n-- Results:");
    eprintln!("   agent  : {}", if agent_result.is_ok() { "ok" } else { "FAILED" });
    eprintln!("   client : {}", if client_result.is_ok() { "ok" } else { "FAILED" });
    if let Err(ref e) = agent_result {
        eprintln!("   agent error  : {e}");
    }
    if let Err(ref e) = client_result {
        eprintln!("   client error : {e}");
    }

    // At least one side should fail (the denied peer's TLS handshake is rejected).
    let either_failed = agent_result.is_err() || client_result.is_err();
    assert!(
        either_failed,
        "denied PodId should cause connection failure"
    );
    eprintln!("   [ok] Connection correctly rejected (denied PodId)");

    agent.close();
    client_endpoint.close();
    eprintln!("\n   [ok] PASS\n");
}

// ---------------------------------------------------------------------------
// Test: strict mode rejects unknown peers
// ---------------------------------------------------------------------------

#[tokio::test]
async fn strict_mode_rejects_unknown_peer() {
    init_tracing();
    eprintln!("\n{}", "=".repeat(72));
    eprintln!("TEST: strict_mode_rejects_unknown_peer");
    eprintln!("{}", "=".repeat(72));

    let (agent_kp, agent_cert, _agent_pod_id) = make_identity("AGENT");
    let (client_kp, client_cert, _client_pod_id) = make_identity("CLIENT");

    // Agent uses strict mode -- only pre-trusted peers accepted.
    // The client is NOT pre-trusted.
    let agent_store = Arc::new(MemoryTrustStore::new());
    let client_store = Arc::new(MemoryTrustStore::new());
    eprintln!("\n-- Trust stores: empty");
    eprintln!("   Agent policy : TrustPolicy::Strict (reject unknown peers)");
    eprintln!("   Client policy: TrustPolicy::PairingMode (willing to trust)");

    eprintln!("\n-- AGENT: binding with Strict mode...");
    let agent = AgentEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        &agent_kp,
        &agent_cert,
        agent_store,
        TrustPolicy::Strict,
    )
    .expect("agent should bind");

    let agent_addr = agent.local_addr().expect("should have local addr");
    eprintln!("   bound to: {agent_addr}");

    eprintln!("\n-- CLIENT: creating endpoint (PairingMode) and attempting connection...");
    let client_endpoint = ClientEndpoint::new(
        &client_kp,
        &client_cert,
        client_store,
        TrustPolicy::PairingMode, // Client is willing, but agent is strict.
    )
    .expect("client endpoint should create");

    eprintln!("-- Running agent.accept() || client.connect({agent_addr})...");
    let (agent_result, client_result) =
        tokio::join!(agent.accept(), client_endpoint.connect(agent_addr));

    eprintln!("\n-- Results:");
    eprintln!("   agent  : {}", if agent_result.is_ok() { "ok" } else { "FAILED" });
    eprintln!("   client : {}", if client_result.is_ok() { "ok" } else { "FAILED" });
    if let Err(ref e) = agent_result {
        eprintln!("   agent error  : {e}");
    }
    if let Err(ref e) = client_result {
        eprintln!("   client error : {e}");
    }

    let either_failed = agent_result.is_err() || client_result.is_err();
    assert!(either_failed, "strict mode should reject unknown peer");
    eprintln!("   [ok] Connection correctly rejected (strict mode, unknown peer)");

    agent.close();
    client_endpoint.close();
    eprintln!("\n   [ok] PASS\n");
}

// ---------------------------------------------------------------------------
// Test: both sides derive the same TLS exporter key for SAS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn both_sides_derive_same_tls_exporter_key() {
    init_tracing();
    eprintln!("\n{}", "=".repeat(72));
    eprintln!("TEST: both_sides_derive_same_tls_exporter_key");
    eprintln!("{}", "=".repeat(72));

    let (agent_kp, agent_cert, _) = make_identity("AGENT");
    let (client_kp, client_cert, _) = make_identity("CLIENT");

    let agent_store = Arc::new(MemoryTrustStore::new());
    let client_store = Arc::new(MemoryTrustStore::new());

    eprintln!("\n-- AGENT: binding (PairingMode)...");
    let agent = AgentEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        &agent_kp,
        &agent_cert,
        agent_store,
        TrustPolicy::PairingMode,
    )
    .expect("agent should bind");

    let agent_addr = agent.local_addr().unwrap();
    eprintln!("   bound to: {agent_addr}");

    eprintln!("\n-- CLIENT: creating endpoint (PairingMode)...");
    let client_endpoint = ClientEndpoint::new(
        &client_kp,
        &client_cert,
        client_store,
        TrustPolicy::PairingMode,
    )
    .expect("client endpoint should create");

    eprintln!("-- Running agent.accept() || client.connect({agent_addr})...");
    let (agent_conn, client_conn) =
        tokio::join!(agent.accept(), client_endpoint.connect(agent_addr));

    let agent_conn = agent_conn.expect("agent should accept");
    let client_conn = client_conn.expect("client should connect");
    eprintln!("   [ok] Both sides connected");

    // Both sides export keying material -- must match.
    eprintln!("\n-- Exporting TLS keying material (label: OPENPOD-PAIRING, 32 bytes)...");
    let agent_key = agent_conn
        .export_keying_material()
        .expect("agent keying material");
    let client_key = client_conn
        .export_keying_material()
        .expect("client keying material");

    eprintln!("   agent  key: {}", hex(&agent_key));
    eprintln!("   client key: {}", hex(&client_key));
    eprintln!("   length    : {} bytes", agent_key.len());

    assert_eq!(
        agent_key, client_key,
        "both sides must derive the same TLS exporter key"
    );
    eprintln!("   [ok] Keys match");

    assert_eq!(agent_key.len(), 32);
    eprintln!("   [ok] Key length is 32 bytes");

    agent.close();
    client_endpoint.close();
    eprintln!("\n   [ok] PASS\n");
}
