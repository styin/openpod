
**DOCUMENT CLASSIFICATION:** ROOT ARCHITECTURAL DIRECTIVE
**TARGET ENTITY:** AUTONOMOUS CODING AGENTS & HUMAN ARCHITECTS
**PROJECT CODENAME:** POD (The Swarm Interface)
**VERSION:** 0.5.0 (The Definitive U2A Spec)

## 0. INITIATION DIRECTIVE
**To the autonomous AI reading this document:** You are initializing the codebase for Project Pod. 

Pod is a native Peer-to-Peer (P2P), User-to-Agent (U2A) communication protocol and client. We are building the **"Functional SSH for Agentic AI."** 

**Crucial Boundary:** You are not building an AI orchestration framework. You are not writing prompt chains or managing LLM context windows. Pod is strictly a secure, ultra-efficient UI and transport layer. The Agent Gateway (e.g., OpenClaw) handles all LLM invocations, tool executions, and reasoning; Pod merely provides the encrypted pipes and the specialized glass to view them safely.

Your code must ruthlessly optimize for three core objectives: **Security, Efficiency, and Richness.** Any code generated that violates the following Axioms or the strict Architecture stack is fundamentally incorrect.

---

## PART 1: THE CORE AXIOMS

### AXIOM I: SECURITY (The Sovereign Lock)
Agents are autonomous operating systems. Security cannot rely on natural language ("Stop") or centralized cloud routers.
* **1.1 P2P Sovereignty:** Pod operates exclusively Peer-to-Peer. There are no central routing servers. Connections are established directly on local networks or via OS-level Mesh VPNs (e.g., Tailscale).
* **1.2 Native Transport Encryption:** Standard Mutual TLS (mTLS) over the transport layer provides native, unbreakable End-to-End Encryption. Plaintext local network connections are strictly forbidden to prevent packet sniffing and identity spoofing.
* **1.3 Out-of-Band Hardware Interrupts:** The UI features a hard "Brake" button. This sends a POSIX-level interrupt payload over a dedicated, un-queued network datagram channel, physically bypassing chat traffic to freeze the Agent Gateway's execution loop instantly.
* **1.4 Cryptographic Action Gates:** If the Agent Gateway attempts a destructive action, it yields execution and requests permission. The Human UI generates a cryptographically signed approval. The Gateway mathematically verifies this signature before unblocking the OS thread.

### AXIOM II: EFFICIENCY (The Matryoshka Protocol)
Legacy chat APIs force massive JSON objects and REST bottlenecks. Pod must support 60fps token streaming and real-time OS telemetry without draining mobile batteries or exhausting LLM context windows.
* **2.1 Protobuf on the Wire:** All network frames are strictly compiled Protocol Buffers. This guarantees microsecond deserialization and zero string-parsing overhead for the transport layer.
* **2.2 TOON in the Core:** Inside the Protobuf envelope, the semantic payload handed to the Agent Gateway is strictly formatted in **TOON** (Token-Oriented Object Notation). We eliminate JSON brackets to achieve maximum LLM context efficiency.
	* Amend: If we notice compatibility issues, we may fallback to json
* **2.3 Decoupling Intent from Mass**: Text prompts and semantic pointers are weightless. They should be transmitted at an instant to the agent gateway for it to initiate planning as necessary with the LLM API, completely unblocked by media downloads.

### AXIOM III: RICHNESS (The Split Interface & Explicit Context)
A 1-dimensional chat UI is fatal for observing machine intelligence. Pod separates human intent from machine state. Human intent must be rich in terms of communication modalities, supporting multi-media, emojis, reactions, fostering both efficient HCI and enjoyable UX. Machine state must be rich in terms of transparency into the operations of the agent, its thinking, as well as its access boundaries.
* **3.1 Spatial Bifurcation:** The UI is strictly divided into two zones:
    *   *The Intent Stream (Main):* Human commands and polished Agent output natively rendered as interactive UI widgets, not raw Markdown.
    *   *The Telemetry Sidecar (Collapsible/Drawer):* A live dashboard streaming the Agent Gateway's remote state (Current Working Directory/`pwd`, CPU, raw `stdout`/`stderr` logs) in real-time.
* **3.2 OS-Native Context Only:** The client application does **not** persist, poll, or track local background shadow context. Context injection relies entirely on native OS-level invocations. To pass local context, the user utilizes standard OS functions (e.g., native long-press OS clipboard paste, native share-sheets). The Pod application acts strictly as a stateless passthrough for local intent.

---

## PART 2: THE UNAMBIGUOUS ARCHITECTURE

To eliminate engineering paralysis, the stack is hardcoded. Do not deviate or offer alternatives.

### 1. The Demarcation Line
* **The SDK (`pod-sdk`):** A lightweight adapter library imported into the Agent Gateway. *It does not invoke LLMs.* It exposes a WebTransport server, decrypts the incoming Pod connection, extracts the TOON payload, and hands it directly to the Gateway.
* **The Gateway:** Handles all tool execution and LLM communication. It explicitly pushes its state (e.g., `pwd`, logs) back into the SDK to be routed to the Pod Client.

### 2. The Network Stack
* **Transport:** **WebTransport (HTTP/3 over QUIC)**. This natively supports both *Reliable Streams* (for Tokens/Logs) and *Unreliable Datagrams* (for immediate Security Interrupts).
* **Discovery:** **mDNS (ZeroConf/Bonjour)**. The SDK broadcasts `_pod._udp.local`. The Client scans and connects.

### 3. The Tri-Channel Data Contract
The QUIC connection multiplexes three strictly typed channels over a single socket:
* **Channel A (Semantic):** *QUIC Reliable Stream.* High-speed TOON token deltas, UI intents, and zero-copy VFS OS pointers.
* **Channel B (Telemetry):** *QUIC Reliable Stream.* Live OS state (pwd, active processes, stdout) explicitly pushed by the Agent Gateway to be rendered in the Sidecar.
* **Channel C (Control):** *QUIC Unreliable Datagram.* High-priority, un-queued packets reserved exclusively for `SIGSTOP` interrupts and E2EE Cryptographic Action Signatures.
	* to be refined: how POSIX signals can be transmitted safely to only stop session-associated subprocesses without breaking gateway

### 4. The Client Application (The Glass)
We employ a "Shared Core" architecture to ensure identical protocol logic across iOS, Android, macOS, and Windows.
* **The Engine (`libpod_client_core`):** Written purely in **Rust**. This headless core handles 100% of the WebTransport networking, Protobuf serialization, mDNS discovery, and mTLS cryptography.
* **The UI:** Written in **Flutter** (Dart). Binds to the Rust core via `flutter_rust_bridge`. Flutter compiles to native ARM machine code, provides high fps UI rendering, and seamlessly hooks into native OS file-picker and clipboard intents. WebViews are strictly forbidden.

### 5. The Agent SDK (The Adapter)
To support both Python-based Gateways (e.g., OpenClaw) and TypeScript-based Gateways (e.g., NanoClaw) without duplicating complex cryptography and QUIC logic, the `pod-sdk` must utilize a Core + Binding architecture.
* **The Daemon Core (`libpod_agent_core`):** Written purely in **Rust**. Handles mDNS broadcasting, WebTransport multiplexing, mTLS, and `.pod_cache` file management. 
* **The Python Target:** Bound via `PyO3`. Exposes standard `asyncio` interfaces and decorators. Published to PyPI. 
* **The Node.js Target:** Bound via `NAPI-RS`. Exposes standard Promises and EventEmitters. Published to npm. 

### 6. Media & VFS (The Async Session Cache)
We reject complex streaming proxies in favor of robust, non-blocking UNIX-style file caching. Intent (Text) and Mass (Media) are decoupled but resolved via standard local file paths.
*   **Background Sync:** When the human attaches a media file, the Pod Client instantly sends the text prompt over Channel A, while *simultaneously* spawning an ad-hoc background WebTransport stream to push the raw file bytes to the SDK.
*   **The Session Cache:** The Pod SDK receives the file asynchronously and writes it to a stateful, local directory tied to the chat session (e.g., `.pod_cache/session_id/dataset.csv`).
*   **Non-Blocking Execution:** The Gateway receives the text prompt immediately, alongside the *local OS path* to the caching file. The Agent can begin its ReAct planning loop instantly. If it attempts to run a tool on the file before the download is complete, the SDK yields that tool's specific thread until the disk write finishes.
*   **Persistence & GC:** The SDK manages the cache. If the Agent wishes to keep the file permanently, it uses standard OS tools (`cp`, `mv`) to move the file from `.pod_cache/` into its permanent workspace. When the chat session is terminated by the user, the SDK automatically purges the `.pod_cache/session_id/` directory.

---
**[EXECUTION DIRECTIVE]**
**To the AI Copilot:** 
1. Acknowledge the strict boundary between the Pod Client, the Pod SDK, and the Agent Gateway.
2. We begin by implementing the core of the project, the encrypted transmission channels. 
3. Initialize a Flutter + Rust (`flutter_rust_bridge`) workspace for the Client App.
4. Initialize a workspace for the SDK.
5. Define the `pod_protocol.proto` reflecting the Tri-Channel Multiplexer.