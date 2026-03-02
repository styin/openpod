//! Node identity primitives: Ed25519 keypair, PodId, X.509 certificates.
//!
//! Every OpenPod node generates a persistent Ed25519 keypair at first startup.
//! The PodId is derived from the public key via SHA-256 + base32 + Luhn check
//! digits (Manifesto §2.7.1).

pub mod certificate;
pub mod keypair;
pub mod pod_id;

pub use certificate::Certificate;
pub use keypair::Keypair;
pub use pod_id::PodId;
