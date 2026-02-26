//! OpenPod server-side transport core.
//!
//! Provides the networking engine imported by agent gateway adapters
//! (Python SDK, Node.js SDK, etc.):
//!
//! - WebTransport server (accepts incoming Pod connections)
//! - mDNS service advertiser (broadcasts `_pod._udp.local`)
//! - Server-side mTLS handshake and client verification
//! - Tri-channel session multiplexing (semantic, telemetry, control)
//! - `.pod_cache` async session file cache management
