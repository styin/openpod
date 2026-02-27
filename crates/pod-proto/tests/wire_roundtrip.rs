//! Integration tests: protobuf encode → decode roundtrip for every message type.
//!
//! These tests verify that all wire-format types survive a full serialization
//! cycle, catching field numbering mistakes, missing derives, and enum value
//! mismatches that unit tests on individual modules would miss.

use prost::Message;

use pod_proto::wire::*;

// ---------------------------------------------------------------------------
// Session / Handshake
// ---------------------------------------------------------------------------

#[test]
fn handshake_roundtrip() {
    let original = Handshake {
        protocol_version: "0.1.0".into(),
        feature_flags: 0b1010,
    };

    let bytes = original.encode_to_vec();
    let decoded = Handshake::decode(bytes.as_slice()).expect("decode should succeed");

    assert_eq!(decoded.protocol_version, "0.1.0");
    assert_eq!(decoded.feature_flags, 0b1010);
}

#[test]
fn handshake_response_roundtrip() {
    let original = HandshakeResponse {
        protocol_version: "0.1.0".into(),
        feature_flags: 0b0010,
    };

    let bytes = original.encode_to_vec();
    let decoded = HandshakeResponse::decode(bytes.as_slice()).expect("decode should succeed");

    assert_eq!(decoded.protocol_version, "0.1.0");
    assert_eq!(decoded.feature_flags, 0b0010);
}

#[test]
fn session_init_roundtrip() {
    let original = SessionInit {
        client_pod_id: "ABCDEFG-HIJKLMN-OPQRSTU-VWXYZ23".into(),
        resume_session_id: "sess-abc-123".into(),
        last_ack_id: 42,
    };

    let bytes = original.encode_to_vec();
    let decoded = SessionInit::decode(bytes.as_slice()).expect("decode should succeed");

    assert_eq!(decoded.client_pod_id, "ABCDEFG-HIJKLMN-OPQRSTU-VWXYZ23");
    assert_eq!(decoded.resume_session_id, "sess-abc-123");
    assert_eq!(decoded.last_ack_id, 42);
}

#[test]
fn session_init_new_session_has_empty_resume() {
    let original = SessionInit {
        client_pod_id: "ABCDEFG-HIJKLMN-OPQRSTU-VWXYZ23".into(),
        resume_session_id: String::new(),
        last_ack_id: 0,
    };

    let bytes = original.encode_to_vec();
    let decoded = SessionInit::decode(bytes.as_slice()).expect("decode should succeed");

    assert!(decoded.resume_session_id.is_empty());
    assert_eq!(decoded.last_ack_id, 0);
}

#[test]
fn session_ack_roundtrip() {
    let original = SessionAck {
        session_id: "sess-xyz-789".into(),
        last_ack_id: 100,
    };

    let bytes = original.encode_to_vec();
    let decoded = SessionAck::decode(bytes.as_slice()).expect("decode should succeed");

    assert_eq!(decoded.session_id, "sess-xyz-789");
    assert_eq!(decoded.last_ack_id, 100);
}

#[test]
fn session_close_roundtrip() {
    let original = SessionClose {
        reason: SessionCloseReason::UserInitiated.into(),
        message: "user clicked disconnect".into(),
    };

    let bytes = original.encode_to_vec();
    let decoded = SessionClose::decode(bytes.as_slice()).expect("decode should succeed");

    assert_eq!(decoded.reason(), SessionCloseReason::UserInitiated);
    assert_eq!(decoded.message, "user clicked disconnect");
}

#[test]
fn session_close_all_reasons_survive_roundtrip() {
    let reasons = [
        SessionCloseReason::Unspecified,
        SessionCloseReason::UserInitiated,
        SessionCloseReason::AgentShutdown,
        SessionCloseReason::IdleTimeout,
        SessionCloseReason::ProtocolError,
    ];

    for reason in reasons {
        let original = SessionClose {
            reason: reason.into(),
            message: String::new(),
        };
        let bytes = original.encode_to_vec();
        let decoded = SessionClose::decode(bytes.as_slice()).expect("decode should succeed");
        assert_eq!(
            decoded.reason(),
            reason,
            "reason {reason:?} lost in roundtrip"
        );
    }
}

#[test]
fn session_close_ack_roundtrip() {
    let original = SessionCloseAck {};
    let bytes = original.encode_to_vec();
    let decoded = SessionCloseAck::decode(bytes.as_slice()).expect("decode should succeed");
    // No fields — just verify it decodes without error.
    let _ = decoded;
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[test]
fn error_roundtrip() {
    let original = Error {
        code: 2001,
        category: ErrorCategory::Auth.into(),
        message: "certificate rejected by trust store".into(),
        recoverable: false,
    };

    let bytes = original.encode_to_vec();
    let decoded = Error::decode(bytes.as_slice()).expect("decode should succeed");

    assert_eq!(decoded.code, 2001);
    assert_eq!(decoded.category(), ErrorCategory::Auth);
    assert_eq!(decoded.message, "certificate rejected by trust store");
    assert!(!decoded.recoverable);
}

#[test]
fn error_all_categories_survive_roundtrip() {
    let categories = [
        ErrorCategory::Unspecified,
        ErrorCategory::Transport,
        ErrorCategory::Auth,
        ErrorCategory::Session,
        ErrorCategory::Protocol,
        ErrorCategory::Gateway,
    ];

    for cat in categories {
        let original = Error {
            code: 1000,
            category: cat.into(),
            message: String::new(),
            recoverable: true,
        };
        let bytes = original.encode_to_vec();
        let decoded = Error::decode(bytes.as_slice()).expect("decode should succeed");
        assert_eq!(
            decoded.category(),
            cat,
            "category {cat:?} lost in roundtrip"
        );
    }
}

// ---------------------------------------------------------------------------
// Channel A
// ---------------------------------------------------------------------------

#[test]
fn channel_a_semantic_message_roundtrip() {
    let json = br#"{"role":"user","content":"Hello"}"#;

    let original = ChannelAEnvelope {
        seq_id: 1,
        ack_id: 0,
        payload: Some(channel_a_envelope::Payload::Semantic(SemanticMessage {
            json_payload: json.to_vec(),
            pending_attachments: 3,
        })),
    };

    let bytes = original.encode_to_vec();
    let decoded = ChannelAEnvelope::decode(bytes.as_slice()).expect("decode should succeed");

    assert_eq!(decoded.seq_id, 1);
    assert_eq!(decoded.ack_id, 0);

    match decoded.payload {
        Some(channel_a_envelope::Payload::Semantic(msg)) => {
            assert_eq!(msg.json_payload, json);
            assert_eq!(msg.pending_attachments, 3);
        }
        other => panic!("expected Semantic payload, got {other:?}"),
    }
}

#[test]
fn channel_a_permission_request_roundtrip() {
    let desc = br#"{"action":"rm -rf /tmp/build"}"#;

    let original = ChannelAEnvelope {
        seq_id: 5,
        ack_id: 4,
        payload: Some(channel_a_envelope::Payload::PermissionRequest(
            PermissionRequest {
                request_id: "perm-001".into(),
                description_json: desc.to_vec(),
            },
        )),
    };

    let bytes = original.encode_to_vec();
    let decoded = ChannelAEnvelope::decode(bytes.as_slice()).expect("decode should succeed");

    match decoded.payload {
        Some(channel_a_envelope::Payload::PermissionRequest(req)) => {
            assert_eq!(req.request_id, "perm-001");
            assert_eq!(req.description_json, desc);
        }
        other => panic!("expected PermissionRequest, got {other:?}"),
    }
}

#[test]
fn channel_a_permission_response_roundtrip() {
    let original = ChannelAEnvelope {
        seq_id: 6,
        ack_id: 5,
        payload: Some(channel_a_envelope::Payload::PermissionResponse(
            PermissionResponse {
                request_id: "perm-001".into(),
                approved: true,
            },
        )),
    };

    let bytes = original.encode_to_vec();
    let decoded = ChannelAEnvelope::decode(bytes.as_slice()).expect("decode should succeed");

    match decoded.payload {
        Some(channel_a_envelope::Payload::PermissionResponse(resp)) => {
            assert_eq!(resp.request_id, "perm-001");
            assert!(resp.approved);
        }
        other => panic!("expected PermissionResponse, got {other:?}"),
    }
}

#[test]
fn channel_a_error_payload_roundtrip() {
    let original = ChannelAEnvelope {
        seq_id: 10,
        ack_id: 9,
        payload: Some(channel_a_envelope::Payload::Error(Error {
            code: 4002,
            category: ErrorCategory::Protocol.into(),
            message: "malformed message".into(),
            recoverable: true,
        })),
    };

    let bytes = original.encode_to_vec();
    let decoded = ChannelAEnvelope::decode(bytes.as_slice()).expect("decode should succeed");

    match decoded.payload {
        Some(channel_a_envelope::Payload::Error(err)) => {
            assert_eq!(err.code, 4002);
            assert_eq!(err.category(), ErrorCategory::Protocol);
            assert!(err.recoverable);
        }
        other => panic!("expected Error payload, got {other:?}"),
    }
}

#[test]
fn channel_a_empty_payload_roundtrip() {
    // An envelope with no payload set — this is valid protobuf (oneof not set).
    let original = ChannelAEnvelope {
        seq_id: 99,
        ack_id: 98,
        payload: None,
    };

    let bytes = original.encode_to_vec();
    let decoded = ChannelAEnvelope::decode(bytes.as_slice()).expect("decode should succeed");

    assert_eq!(decoded.seq_id, 99);
    assert!(decoded.payload.is_none());
}

// ---------------------------------------------------------------------------
// Channel B — Telemetry
// ---------------------------------------------------------------------------

#[test]
fn telemetry_update_roundtrip() {
    let extra = br#"{"cpu_percent":42.5}"#;

    let original = TelemetryUpdate {
        cwd: "/home/user/project".into(),
        active_processes: vec!["cargo build".into(), "node server.js".into()],
        stdout_delta: "Compiling pod-proto v0.1.0\n".into(),
        stderr_delta: String::new(),
        context_tokens_used: 15000,
        context_tokens_total: 200000,
        timestamp_ms: 1_735_689_600_000,
        extra_json: extra.to_vec(),
    };

    let bytes = original.encode_to_vec();
    let decoded = TelemetryUpdate::decode(bytes.as_slice()).expect("decode should succeed");

    assert_eq!(decoded.cwd, "/home/user/project");
    assert_eq!(decoded.active_processes.len(), 2);
    assert_eq!(decoded.active_processes[0], "cargo build");
    assert_eq!(decoded.active_processes[1], "node server.js");
    assert_eq!(decoded.stdout_delta, "Compiling pod-proto v0.1.0\n");
    assert!(decoded.stderr_delta.is_empty());
    assert_eq!(decoded.context_tokens_used, 15000);
    assert_eq!(decoded.context_tokens_total, 200000);
    assert_eq!(decoded.timestamp_ms, 1_735_689_600_000);
    assert_eq!(decoded.extra_json, extra);
}

#[test]
fn telemetry_update_empty_fields_roundtrip() {
    // All default/zero values — still must survive roundtrip.
    let original = TelemetryUpdate {
        cwd: String::new(),
        active_processes: vec![],
        stdout_delta: String::new(),
        stderr_delta: String::new(),
        context_tokens_used: 0,
        context_tokens_total: 0,
        timestamp_ms: 0,
        extra_json: vec![],
    };

    let bytes = original.encode_to_vec();
    let decoded = TelemetryUpdate::decode(bytes.as_slice()).expect("decode should succeed");

    assert!(decoded.cwd.is_empty());
    assert!(decoded.active_processes.is_empty());
    assert_eq!(decoded.context_tokens_used, 0);
}

// ---------------------------------------------------------------------------
// Channel C — Control
// ---------------------------------------------------------------------------

#[test]
fn control_signal_brake_roundtrip() {
    let original = ControlSignal {
        signal_id: "sig-uuid-001".into(),
        signal_type: ControlSignalType::Brake.into(),
        timestamp_ms: 1_735_689_600_000,
    };

    let bytes = original.encode_to_vec();
    let decoded = ControlSignal::decode(bytes.as_slice()).expect("decode should succeed");

    assert_eq!(decoded.signal_id, "sig-uuid-001");
    assert_eq!(decoded.signal_type(), ControlSignalType::Brake);
    assert_eq!(decoded.timestamp_ms, 1_735_689_600_000);
}

#[test]
fn control_signal_interrupt_roundtrip() {
    let original = ControlSignal {
        signal_id: "sig-uuid-002".into(),
        signal_type: ControlSignalType::Interrupt.into(),
        timestamp_ms: 1_735_689_600_500,
    };

    let bytes = original.encode_to_vec();
    let decoded = ControlSignal::decode(bytes.as_slice()).expect("decode should succeed");

    assert_eq!(decoded.signal_type(), ControlSignalType::Interrupt);
}

#[test]
fn control_signal_ack_roundtrip() {
    let original = ControlSignalAck {
        signal_id: "sig-uuid-001".into(),
    };

    let bytes = original.encode_to_vec();
    let decoded = ControlSignalAck::decode(bytes.as_slice()).expect("decode should succeed");

    assert_eq!(decoded.signal_id, "sig-uuid-001");
}

// ---------------------------------------------------------------------------
// Cross-cutting: dual-path deduplication scenario
// ---------------------------------------------------------------------------

#[test]
fn same_control_signal_encodes_identically_for_both_paths() {
    // Channel C sends the same ControlSignal on datagram AND stream.
    // Both sides must encode to identical bytes so the receiver can
    // deduplicate by signal_id (not by byte equality, but this tests
    // deterministic encoding).
    let signal = ControlSignal {
        signal_id: "dedup-test-uuid".into(),
        signal_type: ControlSignalType::Brake.into(),
        timestamp_ms: 1_735_689_600_000,
    };

    let datagram_bytes = signal.encode_to_vec();
    let stream_bytes = signal.encode_to_vec();

    assert_eq!(
        datagram_bytes, stream_bytes,
        "same message must encode identically"
    );
}

// ---------------------------------------------------------------------------
// Sequencing: seq_id / ack_id semantics
// ---------------------------------------------------------------------------

#[test]
fn seq_id_ack_id_preserved_across_envelope_types() {
    // Verify that seq_id and ack_id are preserved regardless of payload type.
    let payloads: Vec<Option<channel_a_envelope::Payload>> = vec![
        Some(channel_a_envelope::Payload::Semantic(SemanticMessage {
            json_payload: b"{}".to_vec(),
            pending_attachments: 0,
        })),
        Some(channel_a_envelope::Payload::PermissionRequest(
            PermissionRequest {
                request_id: "r1".into(),
                description_json: b"{}".to_vec(),
            },
        )),
        Some(channel_a_envelope::Payload::PermissionResponse(
            PermissionResponse {
                request_id: "r1".into(),
                approved: false,
            },
        )),
        Some(channel_a_envelope::Payload::Error(Error {
            code: 1001,
            category: ErrorCategory::Transport.into(),
            message: "timeout".into(),
            recoverable: true,
        })),
        None,
    ];

    for (i, payload) in payloads.into_iter().enumerate() {
        let seq = (i as u64 + 1) * 100;
        let ack = seq - 1;

        let original = ChannelAEnvelope {
            seq_id: seq,
            ack_id: ack,
            payload,
        };

        let bytes = original.encode_to_vec();
        let decoded = ChannelAEnvelope::decode(bytes.as_slice()).expect("decode should succeed");

        assert_eq!(decoded.seq_id, seq, "seq_id lost for payload variant {i}");
        assert_eq!(decoded.ack_id, ack, "ack_id lost for payload variant {i}");
    }
}
