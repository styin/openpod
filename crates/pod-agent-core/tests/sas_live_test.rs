//! Integration tests: SAS derivation from live QUIC/TLS sessions.

use std::sync::Arc;

use pod_agent_core::AgentEndpoint;
use pod_client_core::ClientEndpoint;
use pod_proto::identity::{Certificate, Keypair, PodId};
use pod_proto::sas::derive_sas;
use pod_proto::trust::{MemoryTrustStore, TrustPolicy};

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
async fn live_tls_sas_matches_on_both_sides() {
    init_tracing();

    let (agent, client, agent_conn, client_conn) = connect_pair().await;

    let agent_exporter = agent_conn
        .export_keying_material()
        .expect("agent exporter should succeed");
    let client_exporter = client_conn
        .export_keying_material()
        .expect("client exporter should succeed");

    assert_eq!(agent_exporter.len(), 32);
    assert_eq!(client_exporter.len(), 32);
    assert_eq!(agent_exporter, client_exporter);

    let agent_sas = derive_sas(&agent_exporter).expect("agent SAS should derive");
    let client_sas = derive_sas(&client_exporter).expect("client SAS should derive");

    assert_eq!(agent_sas, client_sas);
    assert_eq!(agent_sas.len(), 6);
    assert!(agent_sas.chars().all(|c| c.is_ascii_digit()));

    agent.close();
    client.close();
}

#[tokio::test]
async fn live_tls_sas_differs_across_sessions() {
    init_tracing();

    let (agent_one, client_one, agent_conn_one, client_conn_one) = connect_pair().await;
    let exporter_one = agent_conn_one
        .export_keying_material()
        .expect("first exporter should succeed");
    let mirrored_one = client_conn_one
        .export_keying_material()
        .expect("first mirrored exporter should succeed");

    let (agent_two, client_two, agent_conn_two, client_conn_two) = connect_pair().await;
    let exporter_two = agent_conn_two
        .export_keying_material()
        .expect("second exporter should succeed");
    let mirrored_two = client_conn_two
        .export_keying_material()
        .expect("second mirrored exporter should succeed");

    assert_eq!(exporter_one, mirrored_one);
    assert_eq!(exporter_two, mirrored_two);

    let sas_one = derive_sas(&exporter_one).expect("first SAS should derive");
    let sas_two = derive_sas(&exporter_two).expect("second SAS should derive");

    assert_ne!(exporter_one, exporter_two);
    assert_ne!(sas_one, sas_two);

    agent_one.close();
    client_one.close();
    agent_two.close();
    client_two.close();
}
