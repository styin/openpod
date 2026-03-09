//! Integration tests: runtime session lifecycle over live QUIC connections.

use std::sync::Arc;

use pod_agent_core::AgentEndpoint;
use pod_client_core::{ClientEndpoint, SessionInitOptions};
use pod_proto::identity::{Certificate, Keypair, PodId};
use pod_proto::trust::{MemoryTrustStore, TrustPolicy};
use pod_proto::wire::{SemanticMessage, SessionCloseReason, channel_a_envelope::Payload};

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

fn semantic_payload(text: &str) -> Payload {
    Payload::Semantic(SemanticMessage {
        json_payload: text.as_bytes().to_vec(),
        pending_attachments: 0,
    })
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
    assert_eq!(
        agent_session.connection().peer_pod_id().as_bytes(),
        client_pod_id.as_bytes()
    );
    assert_eq!(
        client_session.connection().peer_pod_id().as_bytes(),
        agent_pod_id.as_bytes()
    );

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

#[tokio::test]
async fn session_resumption_replays_unacked_agent_messages() {
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

    let sent = agent_session
        .send_envelope(semantic_payload("agent-pending"))
        .await
        .expect("agent should send envelope");
    assert_eq!(sent.seq_id, 1);

    let resume_state = client_session.resume_state();

    client_session
        .connection()
        .inner()
        .close(0u32.into(), b"simulate disconnect");
    agent_session
        .connection()
        .inner()
        .close(0u32.into(), b"simulate disconnect");

    let (agent_result, client_result) = tokio::join!(
        agent.accept_session(),
        client.resume_session(agent_addr, resume_state)
    );

    let resumed_agent_session = agent_result.expect("agent should resume session");
    let resumed_client_session = client_result.expect("client should resume session");

    let replayed = resumed_client_session
        .accept_envelope()
        .await
        .expect("client should receive replayed envelope");

    assert_eq!(replayed.seq_id, 1);
    assert_eq!(replayed.ack_id, 0);
    match replayed.payload {
        Some(Payload::Semantic(message)) => {
            assert_eq!(message.json_payload, b"agent-pending");
        }
        other => panic!("expected semantic payload, got {other:?}"),
    }
    assert_eq!(resumed_agent_session.client_last_ack_id(), 0);

    agent.close();
    client.close();
}

#[tokio::test]
async fn session_resumption_replays_unacked_client_messages() {
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

    let sent = client_session
        .send_envelope(semantic_payload("client-pending"))
        .await
        .expect("client should send envelope");
    assert_eq!(sent.seq_id, 1);

    let resume_state = client_session.resume_state();

    client_session
        .connection()
        .inner()
        .close(0u32.into(), b"simulate disconnect");
    agent_session
        .connection()
        .inner()
        .close(0u32.into(), b"simulate disconnect");

    let (agent_result, client_result) = tokio::join!(
        agent.accept_session(),
        client.resume_session(agent_addr, resume_state)
    );

    let resumed_agent_session = agent_result.expect("agent should resume session");
    let resumed_client_session = client_result.expect("client should resume session");

    let replayed = resumed_agent_session
        .accept_envelope()
        .await
        .expect("agent should receive replayed envelope");

    assert_eq!(replayed.seq_id, 1);
    assert_eq!(replayed.ack_id, 0);
    match replayed.payload {
        Some(Payload::Semantic(message)) => {
            assert_eq!(message.json_payload, b"client-pending");
        }
        other => panic!("expected semantic payload, got {other:?}"),
    }
    assert_eq!(resumed_client_session.agent_last_ack_id(), 0);

    agent.close();
    client.close();
}

#[tokio::test]
async fn unknown_session_resumption_is_rejected() {
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
    let (agent_result, client_result) = tokio::join!(
        agent.accept_session(),
        client.connect_session_with_options(
            agent_addr,
            SessionInitOptions {
                resume_session_id: Some("sess-does-not-exist".into()),
                last_ack_id: 0,
            }
        )
    );

    assert!(agent_result.is_err() || client_result.is_err());

    agent.close();
    client.close();
}

#[tokio::test]
async fn graceful_close_removes_session_from_resume_cache() {
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
    let resume_state = client_session.resume_state();

    let (agent_close_result, client_close_result) = tokio::join!(
        agent_session.accept_close(),
        client_session.close(SessionCloseReason::UserInitiated, "test shutdown")
    );

    agent_close_result.expect("agent should receive close");
    client_close_result.expect("client close should complete");

    let (agent_result, client_result) = tokio::join!(
        agent.accept_session(),
        client.resume_session(agent_addr, resume_state)
    );

    assert!(agent_result.is_err() || client_result.is_err());

    agent.close();
    client.close();
}

#[tokio::test]
async fn resumption_with_different_client_identity_is_rejected() {
    init_tracing();

    let (agent_kp, agent_cert, _agent_pod_id) = make_identity();
    let (client_kp, client_cert, _client_pod_id) = make_identity();
    let (other_client_kp, other_client_cert, _other_client_pod_id) = make_identity();

    let agent_store = Arc::new(MemoryTrustStore::new());
    let client_store = Arc::new(MemoryTrustStore::new());
    let other_client_store = Arc::new(MemoryTrustStore::new());

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

    let other_client = ClientEndpoint::new(
        &other_client_kp,
        &other_client_cert,
        other_client_store,
        TrustPolicy::PairingMode,
    )
    .expect("other client should create");

    let agent_addr = agent.local_addr().expect("local addr");
    let (agent_result, client_result) =
        tokio::join!(agent.accept_session(), client.connect_session(agent_addr));

    let agent_session = agent_result.expect("agent session should establish");
    let client_session = client_result.expect("client session should establish");
    let resume_state = client_session.resume_state();

    client_session
        .connection()
        .inner()
        .close(0u32.into(), b"simulate disconnect");
    agent_session
        .connection()
        .inner()
        .close(0u32.into(), b"simulate disconnect");

    let (agent_result, client_result) = tokio::join!(
        agent.accept_session(),
        other_client.resume_session(agent_addr, resume_state)
    );

    assert!(agent_result.is_err() || client_result.is_err());

    agent.close();
    client.close();
    other_client.close();
}
