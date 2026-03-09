//! Integration tests: stream_io helpers over live QUIC connections.

use std::sync::Arc;

use pod_agent_core::{AgentEndpoint, stream_io as agent_stream_io};
use pod_client_core::{ClientEndpoint, stream_io as client_stream_io};
use pod_proto::identity::{Certificate, Keypair, PodId};
use pod_proto::trust::{MemoryTrustStore, TrustPolicy};
use pod_proto::wire::{
    self, ChannelAEnvelope, Handshake, HandshakeResponse, PermissionRequest, PermissionResponse,
    SemanticMessage, channel_a_envelope::Payload,
};

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

async fn connect_pair() -> (
    AgentEndpoint,
    ClientEndpoint,
    pod_agent_core::PodConnection,
    pod_client_core::PodConnection,
) {
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
    let (agent_result, client_result) = tokio::join!(agent.accept(), client.connect(agent_addr));

    let agent_conn = agent_result.expect("agent should accept connection");
    let client_conn = client_result.expect("client should connect");

    (agent, client, agent_conn, client_conn)
}

#[tokio::test]
async fn send_and_receive_handshake_over_quic_stream() {
    init_tracing();

    let (agent, client, agent_conn, client_conn) = connect_pair().await;

    let agent_task = async {
        let (mut send, mut recv) = agent_conn.inner().accept_bi().await.expect("accept bi");
        let handshake: Handshake = agent_stream_io::read_message(&mut recv)
            .await
            .expect("read handshake");

        assert_eq!(handshake.protocol_version, "stream-io-test");
        assert_eq!(handshake.feature_flags, 0x55aa);

        let response = HandshakeResponse {
            protocol_version: "stream-io-test-response".into(),
            feature_flags: handshake.feature_flags,
        };
        agent_stream_io::write_message(&mut send, &response)
            .await
            .expect("write response");
    };

    let client_task = async {
        let (mut send, mut recv) = client_conn.inner().open_bi().await.expect("open bi");
        let handshake = Handshake {
            protocol_version: "stream-io-test".into(),
            feature_flags: 0x55aa,
        };

        client_stream_io::write_message(&mut send, &handshake)
            .await
            .expect("write handshake");

        let response: HandshakeResponse = client_stream_io::read_message(&mut recv)
            .await
            .expect("read response");

        assert_eq!(response.protocol_version, "stream-io-test-response");
        assert_eq!(response.feature_flags, 0x55aa);
    };

    tokio::join!(agent_task, client_task);

    agent.close();
    client.close();
}

#[tokio::test]
async fn channel_a_envelope_over_quic_stream() {
    init_tracing();

    let (agent, client, agent_conn, client_conn) = connect_pair().await;

    let payload = br#"{"type":"user_message","text":"hello"}"#.to_vec();
    let envelope = ChannelAEnvelope {
        seq_id: 7,
        ack_id: 3,
        payload: Some(Payload::Semantic(SemanticMessage {
            json_payload: payload.clone(),
            pending_attachments: 0,
        })),
    };

    let agent_task = async {
        let (_send, mut recv) = agent_conn.inner().accept_bi().await.expect("accept bi");
        let received: ChannelAEnvelope = agent_stream_io::read_message(&mut recv)
            .await
            .expect("read envelope");

        assert_eq!(received.seq_id, 7);
        assert_eq!(received.ack_id, 3);

        match received.payload {
            Some(Payload::Semantic(message)) => {
                assert_eq!(message.json_payload, payload);
                assert_eq!(message.pending_attachments, 0);
            }
            other => panic!("expected semantic payload, got {other:?}"),
        }
    };

    let client_task = async {
        let (mut send, _recv) = client_conn.inner().open_bi().await.expect("open bi");
        client_stream_io::write_message(&mut send, &envelope)
            .await
            .expect("write envelope");
    };

    tokio::join!(agent_task, client_task);

    agent.close();
    client.close();
}

#[tokio::test]
async fn permission_request_response_over_quic_stream() {
    init_tracing();

    let (agent, client, agent_conn, client_conn) = connect_pair().await;

    let request = ChannelAEnvelope {
        seq_id: 11,
        ack_id: 4,
        payload: Some(Payload::PermissionRequest(PermissionRequest {
            request_id: "perm-1".into(),
            description_json: br#"{"action":"rm -rf /tmp/demo"}"#.to_vec(),
        })),
    };

    let response = ChannelAEnvelope {
        seq_id: 12,
        ack_id: 11,
        payload: Some(Payload::PermissionResponse(PermissionResponse {
            request_id: "perm-1".into(),
            approved: true,
        })),
    };

    let agent_task = async {
        let (mut send, mut recv) = agent_conn.inner().accept_bi().await.expect("accept bi");
        let received: ChannelAEnvelope = agent_stream_io::read_message(&mut recv)
            .await
            .expect("read request");

        match received.payload {
            Some(Payload::PermissionRequest(request)) => {
                assert_eq!(request.request_id, "perm-1");
                assert_eq!(
                    request.description_json,
                    br#"{"action":"rm -rf /tmp/demo"}"#
                );
            }
            other => panic!("expected permission request, got {other:?}"),
        }

        agent_stream_io::write_message(&mut send, &response)
            .await
            .expect("write response");
    };

    let client_task = async {
        let (mut send, mut recv) = client_conn.inner().open_bi().await.expect("open bi");
        client_stream_io::write_message(&mut send, &request)
            .await
            .expect("write request");

        let received: ChannelAEnvelope = client_stream_io::read_message(&mut recv)
            .await
            .expect("read response");

        assert_eq!(received.seq_id, 12);
        assert_eq!(received.ack_id, 11);
        match received.payload {
            Some(Payload::PermissionResponse(response)) => {
                assert_eq!(response.request_id, "perm-1");
                assert!(response.approved);
            }
            other => panic!("expected permission response, got {other:?}"),
        }
    };

    tokio::join!(agent_task, client_task);

    agent.close();
    client.close();
}

#[tokio::test]
async fn multiple_messages_on_separate_streams() {
    init_tracing();

    let (agent, client, agent_conn, client_conn) = connect_pair().await;

    let agent_task = async {
        for expected_seq in 1..=3 {
            let (_send, mut recv) = agent_conn.inner().accept_bi().await.expect("accept bi");
            let received: ChannelAEnvelope = agent_stream_io::read_message(&mut recv)
                .await
                .expect("read stream message");
            assert_eq!(received.seq_id, expected_seq);
            assert_eq!(received.ack_id, expected_seq - 1);
            match received.payload {
                Some(Payload::Semantic(message)) => {
                    let expected = format!("message-{expected_seq}");
                    assert_eq!(message.json_payload, expected.as_bytes());
                }
                other => panic!("expected semantic payload, got {other:?}"),
            }
        }
    };

    let client_task = async {
        for seq_id in 1..=3 {
            let (mut send, _recv) = client_conn.inner().open_bi().await.expect("open bi");
            let envelope = wire::ChannelAEnvelope {
                seq_id,
                ack_id: seq_id - 1,
                payload: Some(Payload::Semantic(SemanticMessage {
                    json_payload: format!("message-{seq_id}").into_bytes(),
                    pending_attachments: 0,
                })),
            };

            client_stream_io::write_message(&mut send, &envelope)
                .await
                .expect("write stream message");
        }
    };

    tokio::join!(agent_task, client_task);

    agent.close();
    client.close();
}
