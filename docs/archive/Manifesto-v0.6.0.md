**DOCUMENT CLASSIFICATION:** ROOT ARCHITECTURAL DIRECTIVE
**TARGET ENTITY:** AUTONOMOUS CODING AGENTS & HUMAN ARCHITECTS
**PROJECT CODENAME:** POD (The Swarm Interface)
**VERSION:** 0.6.0 (The Definitive U2A Spec)

## 0. INITIATION DIRECTIVE
**To the autonomous AI reading this document:** You are initializing the codebase for Project Pod.

Pod is a native Peer-to-Peer (P2P), User-to-Agent (U2A) communication protocol and client. We are building the **"Functional SSH for Agentic AI."**

**Crucial Boundary:** You are not building an AI orchestration framework. You are not writing prompt chains or managing LLM context windows. Pod is strictly a secure, ultra-efficient UI and transport layer. The Agent Gateway (e.g., OpenClaw) handles all LLM invocations, tool executions, and reasoning; Pod merely provides the encrypted pipes and the specialized glass to view them safely.

Your code must ruthlessly optimize for three core objectives: **Security, Efficiency, and Richness.** Any code generated that violates the following Axioms or the Architecture stack is fundamentally incorrect.

---

## PART 1: THE CORE AXIOMS

### AXIOM I: SECURITY (The Sovereign Lock)
Agents are autonomous operating systems. Security cannot rely on natural language ("Stop") or centralized cloud routers.
* **1.1 P2P Sovereignty:** Pod operates exclusively Peer-to-Peer. There are no central routing servers. Connections are established directly on local networks or via OS-level Mesh VPNs (e.g., Tailscale).
* **1.2 Native Transport Encryption:** Mutual TLS (mTLS) over WebTransport provides native End-to-End Encryption. Plaintext local network connections are strictly forbidden to prevent packet sniffing and identity spoofing. mTLS trust is established via TOFU (Trust On First Use) with SAS (Short Authentication String) verification during initial pairing. See §2.7 for the full identity and pairing specification.
* **1.3 Out-of-Band Hardware Interrupts:** The UI features a hard "Brake" button. This sends a control interrupt payload over **both** a QUIC unreliable datagram (for minimum latency) **and** a QUIC reliable stream (for delivery guarantee). First arrival wins. This dual-path approach ensures the interrupt bypasses queued chat traffic while guaranteeing delivery even under packet loss. How the receiving Gateway translates this signal into process control (e.g., `killProcessTree`) is the Gateway's responsibility, not Pod's.
* **1.4 Permission Grants:** If the Agent Gateway requests permission for a destructive action, it yields execution and sends a permission request over Channel A. The client UI presents the request and sends an approval or denial response over the mTLS-authenticated channel. The transport-layer identity from mTLS is sufficient to authenticate the response — no additional cryptographic signature scheme is required.

### AXIOM II: EFFICIENCY (The Wire Protocol)
Legacy chat APIs force massive JSON objects and REST bottlenecks. Pod must support 60fps token streaming and real-time OS telemetry without draining mobile batteries or exhausting LLM context windows.
* **2.1 Protobuf on the Wire:** All network frames are strictly compiled Protocol Buffers. This guarantees microsecond deserialization and zero string-parsing overhead for the transport layer.
* **2.2 JSON Semantic Payloads:** Inside the Protobuf envelope, structured semantic payloads (user intents, agent responses, UI widget descriptors) are encoded as **JSON**. JSON is the default interchange format for its universal tooling, debuggability, and LLM compatibility. A future optimization pass may introduce a more token-efficient encoding (e.g., TOON — Token-Oriented Object Notation), but only after profiling demonstrates measurable gains.
* **2.3 Decoupling Intent from Mass**: Text prompts and semantic pointers are lightweight. They must be transmitted instantly to the agent gateway for it to initiate planning, completely unblocked by media downloads. Media files are uploaded separately and the agent is notified only after the upload completes (see §2.6).

### AXIOM III: RICHNESS (The Split Interface & Explicit Context)
A 1-dimensional chat UI is fatal for observing machine intelligence. Pod separates human intent from machine state. Human intent must be rich in terms of communication modalities, supporting multi-media, emojis, reactions, fostering both efficient HCI and enjoyable UX. Machine state must be rich in terms of transparency into the operations of the agent, its thinking, as well as its access boundaries.
* **3.1 Spatial Bifurcation:** The UI is strictly divided into two zones:
    *   *The Intent Stream (Main):* Human commands and polished Agent output natively rendered as interactive UI widgets, not raw Markdown.
    *   *The Telemetry Sidecar (Collapsible/Drawer):* A live dashboard streaming the Agent Gateway's remote state (Current Working Directory/`pwd`, CPU, raw `stdout`/`stderr` logs) in real-time.
* **3.2 OS-Native Context Only:** The client application does **not** persist, poll, or track local background shadow context. Context injection relies entirely on native OS-level invocations. To pass local context, the user utilizes standard OS functions (e.g., native long-press OS clipboard paste, native share-sheets). The Pod application acts strictly as a stateless passthrough for local intent.

---

## PART 2: THE ARCHITECTURE

### 2.1 The Demarcation Line
* **The SDK (`pod-sdk`):** A lightweight adapter library imported into the Agent Gateway. *It does not invoke LLMs.* It exposes a WebTransport server, decrypts the incoming Pod connection, extracts the semantic JSON payload, and hands it directly to the Gateway via callbacks/events.
* **The Gateway:** Handles all tool execution and LLM communication. It explicitly pushes its state (e.g., `pwd`, logs) back into the SDK to be routed to the Pod Client.

### 2.2 The Network Stack
* **Transport:** **WebTransport (HTTP/3 over QUIC)**. This natively supports both *Reliable Streams* (for Tokens/Logs) and *Unreliable Datagrams* (for immediate Control Interrupts).
* **Discovery:** **mDNS (ZeroConf/Bonjour)**. The SDK advertises `_openpod._udp.local`. The Client scans and connects. Advertisement is **opt-in** — the agent only broadcasts when explicitly started in pairing/discoverable mode. See §2.8 for discovery details.

### 2.3 The Tri-Channel Data Contract
The QUIC connection multiplexes three strictly typed channels over a single socket:
* **Channel A (Semantic):** *QUIC Reliable Stream.* High-speed JSON token deltas, UI intents, file-ready notifications, and permission request/response messages.
* **Channel B (Telemetry):** *QUIC Reliable Stream.* Live OS state (pwd, active processes, stdout) explicitly pushed by the Agent Gateway to be rendered in the Sidecar.
* **Channel C (Control):** *Dual-path delivery.* Control signals (interrupt/brake) are sent over **both** a QUIC Unreliable Datagram (low-latency, best-effort) **and** a QUIC Reliable Stream (guaranteed delivery). The receiver deduplicates by signal ID — first arrival triggers the action, the duplicate is discarded.

### 2.4 The Client Application (The Glass)
We employ a "Shared Core" architecture to ensure identical protocol logic across iOS, Android, macOS, and Windows.
* **The Engine (`libpod_client_core`):** Written purely in **Rust**. This headless core handles 100% of the WebTransport networking, Protobuf serialization, mDNS discovery, and mTLS cryptography.
* **The UI:** Written in **Flutter** (Dart). Binds to the Rust core via `flutter_rust_bridge`. Flutter compiles to native ARM machine code, provides high fps UI rendering, and seamlessly hooks into native OS file-picker and clipboard intents. WebViews are strictly forbidden.

### 2.5 The Agent SDK (The Adapter)
To support both Python-based Gateways (e.g., OpenClaw) and TypeScript-based Gateways (e.g., NanoClaw) without duplicating complex cryptography and QUIC logic, the `pod-sdk` must utilize a Core + Binding architecture.
* **The Daemon Core (`libpod_agent_core`):** Written purely in **Rust**. Handles mDNS advertising, WebTransport multiplexing, mTLS, session management, and `.pod_cache` file management. The core must be designed to support multiple concurrent client sessions in the future — all session state must be keyed by session ID, and no global mutable singleton patterns should be used.
* **The Python Target:** Bound via `PyO3`. Exposes standard `asyncio` interfaces and decorators. Published to PyPI as `pod-sdk`.
* **The Node.js Target:** Bound via `NAPI-RS`. Exposes standard Promises and EventEmitters. Published to npm as `pod-sdk`.

### 2.6 Media & VFS (The Session Cache)
Intent (Text) and Mass (Media) travel over separate QUIC streams but are delivered to the Gateway atomically.
*   **Separate streams, atomic delivery:** When the human sends a message with file attachments, the Pod Client sends the text prompt over Channel A and simultaneously opens a **dedicated QUIC stream per file** for upload. Each file stream is independent — files upload in parallel, and a failure in one does not affect others. The Channel A message carries a `pending_attachments` count in its protobuf envelope. The SDK buffers this message and defers firing the `on_message` callback to the Gateway until all referenced file streams have completed writing to `.pod_cache/session_id/`. The Gateway receives the text intent and all completed file paths as a single atomic event.
*   **Why separate streams:** Sending file bytes inline on Channel A would cause head-of-line blocking — a large upload would freeze all semantic traffic (token deltas, permission requests, other messages) until the transfer finishes. Dedicated per-file QUIC streams keep Channel A free for real-time traffic. QUIC stream creation is essentially free (a frame header, no round-trip handshake).
*   **Per-message hold, not per-channel:** The `pending_attachments` hold applies only to the specific message referencing files. Other text-only messages on Channel A continue to flow and are delivered to the Gateway immediately. The user can keep interacting with the Gateway (e.g., status queries, non-LLM commands) while a file-heavy message is still uploading.
*   **Persistence & GC:** The SDK manages the cache. If the Agent wishes to keep the file permanently, it uses standard OS tools (`cp`, `mv`) to move the file from `.pod_cache/` into its permanent workspace. When the chat session is terminated by the user, the SDK automatically purges the `.pod_cache/session_id/` directory.

### 2.7 Identity & Pairing (The Sovereign Lock)

#### 2.7.1 Node Identity
Every OpenPod node (client or agent) generates a persistent **Ed25519 keypair** at first startup. This keypair is the node's permanent identity.

* **PodId** = `SHA-256(Ed25519 public key)`, encoded as base32 with Luhn check digits.
* Display format: `XXXXXXX-XXXXXXX-XXXXXXX-XXXXXXX` (4 groups of 7 chars). Human-readable, typo-resistant.
* The identity keypair does not expire. Revoking a node means removing its PodId from the peer's trust store.

#### 2.7.2 TLS Certificates
For QUIC/WebTransport connections, each node uses a **self-signed X.509 certificate** containing its Ed25519 public key.

| Parameter | Value |
|-----------|-------|
| Identity key algorithm | Ed25519 |
| TLS key exchange | X25519 (ECDHE), forward secrecy |
| TLS cipher suites | TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256 |
| TLS certificate validity | **30 days** |
| Certificate rotation | Auto-regenerate at 75% of validity (day 22). Same identity key, fresh certificate. Transparent to peers. |

**Migration path:** When the Rust QUIC ecosystem (`quinn`) adds RFC 7250 Raw Public Key support, migrate from self-signed X.509 to raw public keys to eliminate X.509 overhead entirely. The PodId and trust model remain identical.

#### 2.7.3 Pairing Flow
Initial pairing establishes mutual trust between a client and an agent. This is a one-time ceremony per device pair.

**Agent initiates pairing mode:**
```
$ pod pair
Pairing mode active. Awaiting client connection.

Pod ID:  MFZWI3D-BONSGYC-YLTMRWG-C43ENRA
Verify:  847 291

[QR code rendered in terminal via Unicode block characters]
```

**Flow:**
1. Agent enters pairing mode, begins mDNS advertisement (`_openpod._udp.local`).
2. Client discovers agent via mDNS scan (or user enters IP manually).
3. Client initiates QUIC/WebTransport connection. Both sides exchange self-signed certs (mTLS handshake).
4. Both sides derive a **Short Authentication String (SAS)** from the TLS session:
   `SAS = truncate_20bits(HMAC-SHA256(TLS-Exporter("OPENPOD-PAIRING", "", 32), client_random || server_random))`
   Displayed as a 6-digit decimal code.
5. **QR path:** QR code contains `openpod://pair?id=<PodId>&oob=<base64url(32-byte-nonce)>&ip=<agent-ip>&port=<agent-port>`. The routing hints (`ip`, `port`) allow the client to connect directly, bypassing mDNS — making pairing work even when mDNS is blocked (corporate firewalls, VLANs). The OOB nonce is mixed into SAS derivation, allowing automatic verification — no manual code comparison needed.
6. **Manual path:** User visually compares the 6-digit code on both devices and confirms.
7. On confirmation, both nodes store the peer's PodId in their local trust store. Pairing is complete.

| Parameter | Value |
|-----------|-------|
| SAS length | 6 digits (20 bits) |
| QR URI scheme | `openpod://pair?id=<PodId>&oob=<nonce>&ip=<ip>&port=<port>` |
| Pairing code validity | 5 minutes (agent re-generates after timeout) |
| mDNS TXT record | `id=<PodId 7-char prefix>` |

#### 2.7.4 Certificate Lifecycle & Revocation

* **Rotation:** TLS certificates auto-rotate every 30 days. The identity key is unchanged, so the PodId is stable. Peers verify the PodId, not the certificate — rotation is seamless.
* **Revocation:** Each node maintains a local deny-list of revoked PodIds. When a user "unpairs" a device, the peer's PodId is added to the deny-list. Future TLS connections from that PodId are rejected at handshake. No OCSP or CRL infrastructure is needed.
* **Re-pairing after key loss:** If an identity key is lost or compromised, the node generates a new keypair (new PodId). All peers must re-pair. This is intentional — identity loss must be explicit, not silent.
* **Offline recovery:** If a node is offline for >30 days and its TLS certificate expires, it regenerates a new certificate wrapping the same identity key. Since PodId is derived from the key (not the certificate), the peer recognizes it without re-pairing.

### 2.8 Discovery & Connectivity

#### 2.8.1 mDNS (Opt-In)
The agent advertises `_openpod._udp.local` **only** when explicitly started in discoverable mode (e.g., `pod pair` or `pod serve --discoverable`). Outside of pairing, the agent does not broadcast its presence.

**Important:** Both the Rust core and the Flutter client must explicitly configure mDNS tooling to broadcast and query the `_udp` namespace. Default mDNS library configurations that favor `_tcp` service types must be overridden. The mDNS service type is `_openpod._udp`, reflecting the QUIC/UDP transport.

#### 2.8.2 Manual Connect (Fallback)
The Flutter client UI provides a **"Manual Connect"** option: an input field accepting a direct socket address (e.g., `192.168.1.42:8443` or a Tailscale IP `100.x.y.z:8443`). This bypasses mDNS entirely and is the primary connection method for remote/Tailscale scenarios.

#### 2.8.3 Already-Paired Reconnection
Once paired, the client stores the agent's last-known address alongside its PodId. Reconnection attempts the stored address first, falling back to mDNS scan, then prompting for manual entry.

### 2.9 Protocol Versioning

Every Pod connection begins with a version negotiation handshake immediately after the TLS handshake completes:

1. Client sends a `Handshake` message containing its protocol version and supported feature flags.
2. Agent responds with its protocol version and the negotiated feature set (intersection of both).
3. If versions are incompatible, the agent sends an error with a human-readable message and closes the connection.

The `Handshake` message is defined in `pod_protocol.proto`. Protocol version follows semver: major version bumps indicate breaking wire-format changes. Minor/patch bumps are backwards-compatible.

### 2.10 Error Semantics

All error conditions are communicated via a structured `Error` protobuf message on Channel A:

| Field | Type | Description |
|-------|------|-------------|
| `code` | `uint32` | Numeric error code (see error code table below) |
| `category` | `ErrorCategory` enum | `TRANSPORT`, `AUTH`, `SESSION`, `PROTOCOL`, `GATEWAY` |
| `message` | `string` | Human-readable description for logging/debugging |
| `recoverable` | `bool` | Whether the client should attempt to retry |

**Error code ranges:**
* `1xxx` — Transport errors (connection lost, timeout, stream reset)
* `2xxx` — Authentication errors (cert rejected, pairing failed, PodId denied)
* `3xxx` — Session errors (session not found, cache full)
* `4xxx` — Protocol errors (version mismatch, malformed message, unknown channel)
* `5xxx` — Gateway errors (forwarded from the agent gateway)

Retry policy: the client may retry recoverable errors with exponential backoff (initial 500ms, max 30s, jitter). Non-recoverable errors require user intervention.

### 2.11 Session Lifecycle & Graceful Shutdown

#### 2.11.1 Session Establishment
After version negotiation (§2.9), the client sends a `SessionInit` message. The agent responds with a `SessionAck` containing the assigned `session_id`. All subsequent messages are scoped to this session.

#### 2.11.2 Graceful Shutdown
Either side may initiate a graceful shutdown:
1. The initiator sends a `SessionClose` message on Channel A with a reason code.
2. The receiver acknowledges with `SessionCloseAck`.
3. Both sides drain in-flight messages (up to 5-second timeout).
4. The QUIC connection is closed.
5. The agent purges `.pod_cache/session_id/`.

#### 2.11.3 Ungraceful Disconnection
If the QUIC connection drops without a `SessionClose` (e.g., WiFi loss):
1. Both sides detect the connection loss via QUIC idle timeout (default: 30 seconds).
2. The agent preserves the session state and `.pod_cache` for a **reconnection window** (default: 5 minutes).
3. If the client reconnects within the window and presents the same PodId, the session resumes from the last acknowledged message sequence number.
4. After the reconnection window expires, the agent tears down the session and purges the cache.

**Application-layer sequencing:** QUIC transport-level acknowledgments do not survive connection death. When a new QUIC connection is established, it starts fresh with no memory of the previous connection's state. Therefore, the Rust core must implement its own lightweight application-layer sequence numbers (`seq_id`, `ack_id`) inside the protobuf wrapper for Channel A messages. Each side tracks the last `seq_id` acknowledged by the peer. On session resumption, the reconnecting side sends its last `ack_id`, and the peer replays any un-acknowledged messages from an in-memory buffer.

### 2.12 Logging & Observability

All Pod components (Rust core, SDK bindings, Flutter client) must implement structured logging using the `tracing` crate (Rust) or equivalent per-platform facilities.

**Requirements:**
* Use the standard `tracing` subscriber ecosystem (`tracing-subscriber` with `fmt` and `EnvFilter`).
* Log levels: `ERROR` for unrecoverable failures, `WARN` for degraded states, `INFO` for session lifecycle events, `DEBUG` for message-level tracing, `TRACE` for wire-level bytes.
* All log entries must include `session_id` and `pod_id` as structured fields when available.
* The SDK bindings (Python/Node.js) must surface Rust-side logs to the host language's logging framework (`logging` module in Python, `console`/`pino` in Node.js).
* Default log level for release builds: `INFO`. Configurable via `POD_LOG` environment variable (follows `RUST_LOG` syntax).

Good logging is critical for developer experience. Every connection failure, handshake error, and session event must be traceable without attaching a debugger.

### 2.13 Future Considerations

The following capabilities are explicitly deferred but the architecture must not preclude them:

* **Multi-client sessions:** Multiple clients connecting to a single agent simultaneously. The agent core must key all state by session ID, avoid global singletons, and design connection acceptance as a loop, not a one-shot.
* **Permissions & roles:** Fine-grained access control (read-only observers, full-control operators, admin). The pairing trust store should be designed to accommodate per-PodId metadata (e.g., a `role` field) even if only a single `operator` role is used initially.
* **TOON encoding:** A token-optimized encoding for semantic payloads, replacing JSON. Deferred until profiling demonstrates measurable token savings. The architecture treats the semantic payload as an opaque `bytes` field inside Protobuf, so swapping the encoding requires no wire-format changes.
* **A2U Proactivity (Push-to-Wake):** A mechanism for the agent to wake sleeping mobile clients via a stateless, metadata-free APNs/FCM push relay. When a long-running agent task completes after the mobile client has been suspended by the OS (iOS kills background sockets within ~30 seconds), the agent sends a lightweight push notification prompting the mobile OS to wake the app and re-establish the P2P QUIC connection in the background to drain the agent's outbox. The push payload carries no sensitive data — it is purely a wake signal. The actual message content is delivered over the re-established Pod connection.

---
**[EXECUTION DIRECTIVE]**
**To the AI Copilot:**
1. Acknowledge the strict boundary between the Pod Client, the Pod SDK, and the Agent Gateway.
2. We begin by implementing the core of the project, the encrypted transmission channels.
3. Initialize a Flutter + Rust (`flutter_rust_bridge`) workspace for the Client App.
4. Initialize a workspace for the SDK.
5. Define the `pod_protocol.proto` reflecting the Tri-Channel Multiplexer, including `Handshake`, `Error`, `SessionInit`, `SessionClose`, and channel-specific message types.
