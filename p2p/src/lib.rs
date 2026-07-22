//! SilentBell P2P — libp2p networking layer for peer-to-peer messaging.
//!
//! This crate provides:
//! - A libp2p node with Kademlia DHT for peer discovery and message relay
//! - Queue ID derivation for message routing
//! - Message envelope format for DHT-stored payloads
//! - Noise-encrypted transport between peers
//! - High-level messaging integration with E2E encryption

pub mod node;
pub mod queue;
pub mod protocol;
pub mod doorbell;
pub mod messaging;

pub use node::{SofaNode, NodeConfig, NodeEvent};
pub use queue::QueueId;
pub use protocol::MessageEnvelope;
pub use doorbell::{
    DoorbellPing, DoorbellSender, DoorbellReceiver,
    DoorbellConfig, DoorbellEndpoint, DoorbellTransport,
    DoorbellError,
};
pub use messaging::{prepare_outgoing_message, process_incoming_message};
