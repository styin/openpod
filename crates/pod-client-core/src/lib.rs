//! OpenPod client-side transport core.
//!
//! Provides the headless networking engine consumed by any Pod client
//! application (Flutter app, native iOS, CLI, etc.):
//!
//! - WebTransport client (connection initiation over QUIC)
//! - mDNS service browser (discovers `_openpod._udp.local` agents)
//! - Client-side mTLS handshake
//! - Tri-channel session multiplexing (semantic, telemetry, control)
//! - Media upload via background WebTransport streams
