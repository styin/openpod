//! Integration tests: runtime session lifecycle over live QUIC connections.

use std::sync::Arc;

use pod_agent_core::AgentEndpoint;
use pod_client_core::ClientEndpoint;
use pod_proto::identity::{Certificate, Keypair, PodId};
use pod_proto::trust::{MemoryTrustStore, TrustPolicy};
use pod_proto::wire::SessionCloseReason;

/// Reference epoch: 2025-01-01 00:00:00 UTC.
const JAN_1_2025: i64 = 1735689600;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_target(true)
        .with_level(true)
        .try_init();
}

fn make_identity() -> (Keypair, Certificate, PodId) {
    let kp = Keypair::generate();
    let cert = Certificate::generate(&kp, JAN_1_2025).expect("cert gen");
    let pod_id = PodId::from_public_key(&kp.public_key_bytes());
    (kp, cert, pod_id)
}

#[tokio::test]
async fn session_establishment_and_client_initiated_close_work() {
    init_tracing();

    let (agent_kp, agent_cert, agent_pod_id) = make_identity();
    let (client_kp, client_cert, client_pod_id) = make_identity();

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

    let client = ClientEndpoint::new(
        &client_kp,
        &client_cert,
        client_store,
        TrustPolicy::PairingMode,
    )
    .expect("client should create");

    let agent_addr = agent.local_addr().expect("local addr");
    let (agent_result, client_result) =
        tokio::join!(agent.accept_session(), client.connect_session(agent_addr));

    let agent_session = agent_result.expect("agent session should establish");
    let client_session = client_result.expect("client session should establish");

    assert_eq!(agent_session.session_id(), client_session.session_id());
    assert_eq!(agent_session.client_last_ack_id(), 0);
    assert_eq!(client_session.agent_last_ack_id(), 0);
    assert_eq!(agent_session.connection().peer_pod_id().as_bytes(), client_pod_id.as_bytes());
    assert_eq!(client_session.connection().peer_pod_id().as_bytes(), agent_pod_id.as_bytes());

    let (agent_close_result, client_close_result) = tokio::join!(
        agent_session.accept_close(),
        client_session.close(SessionCloseReason::UserInitiated, "test shutdown")
    );

    let close = agent_close_result.expect("agent should receive close");
    client_close_result.expect("client close should complete");

    assert_eq!(close.reason(), SessionCloseReason::UserInitiated);
    assert_eq!(close.message, "test shutdown");

    agent.close();
    client.close();
}

#[tokio::test]
async fn agent_initiated_close_is_acknowledged_by_client() {
    init_tracing();

    let (agent_kp, agent_cert, _agent_pod_id) = make_identity();
    let (client_kp, client_cert, _client_pod_id) = make_identity();

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

    let client = ClientEndpoint::new(
        &client_kp,
        &client_cert,
        client_store,
        TrustPolicy::PairingMode,
    )
    .expect("client should create");

    let agent_addr = agent.local_addr().expect("local addr");
    let (agent_result, client_result) =
        tokio::join!(agent.accept_session(), client.connect_session(agent_addr));

    let agent_session = agent_result.expect("agent session should establish");
    let client_session = client_result.expect("client session should establish");

    let (agent_close_result, client_close_result) = tokio::join!(
        agent_session.close(SessionCloseReason::AgentShutdown, "agent stopping"),
        client_session.accept_close()
    );

    agent_close_result.expect("agent close should complete");
    let close = client_close_result.expect("client should receive close");

    assert_eq!(close.reason(), SessionCloseReason::AgentShutdown);
    assert_eq!(close.message, "agent stopping");

    agent.close();
    client.close();
}