//! # End-to-End Message Encryption — Layer 0
//!
//! This module implements the Signal-style end-to-end encryption protocol
//! for SofaMsg/SilentBell. It is **completely independent** of:
//!
//! - **Layer 1** (transport encryption via libp2p Noise) — hop-to-hop only
//! - **Layer 2** (at-rest vault encryption via AES-256-CBC) — on-device only
//!
//! Layer 0 protects message **content** between sender and recipient using
//! keys derived from their identity keypairs. Without this layer, a
//! compromised or malicious DHT relay node could read message payloads.
//!
//! ## Sub-modules
//!
//! - [`x3dh`] — Extended Triple Diffie-Hellman key agreement (session setup)
//! - [`ratchet`] — Double Ratchet algorithm (per-message forward secrecy)
//! - [`session`] — Session lifecycle management for multiple peers
//!
//! ## Security properties
//!
//! - **Confidentiality**: AES-256-GCM authenticated encryption per message
//! - **Forward secrecy**: Compromising long-term keys doesn't reveal past messages
//! - **Future secrecy (self-healing)**: DH ratchet re-establishes security
//!   even if a chain key is compromised
//! - **Integrity**: GCM auth tags prevent relay nodes from tampering with content
//!
//! ## Why AES-256-GCM here but AES-256-CBC in vault.rs?
//!
//! The vault (Layer 2) intentionally omits authentication tags so that
//! decryption with the wrong PIN produces silent garbage rather than an
//! error — this is the "duress PIN / plausible deniability" property.
//!
//! For in-transit messages (this layer), deniability is NOT a design goal.
//! We NEED integrity protection: if a relay node flips bits in a ciphertext,
//! the recipient must detect the tampering rather than silently accepting
//! corrupted plaintext. Hence: authenticated encryption (GCM).

pub mod x3dh;
pub mod ratchet;
pub mod session;

// Re-export key types for convenience
pub use x3dh::{
    PreKeyBundle, X3dhInitiatorOutput, X3dhResponderOutput,
    generate_signed_prekey, generate_one_time_prekey,
    initiate_x3dh, respond_x3dh,
    ed25519_signing_key_to_x25519,
    ed25519_verifying_key_to_x25519,
    SignedPreKey, OneTimePreKey,
};
pub use ratchet::{RatchetState, MessageHeader, EncryptedMessage};
pub use session::{Session, SessionManager};
