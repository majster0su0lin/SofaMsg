#![allow(clippy::all)]

//! SilentBell P2P — libp2p networking layer for peer-to-peer messaging.
//!
//! This crate provides:
//! - A libp2p node with Kademlia DHT for peer discovery and message relay
//! - Queue ID derivation for message routing
//! - Message envelope format for DHT-stored payloads
//! - Noise-encrypted transport between peers
//! - High-level messaging integration with E2E encryption

pub mod doorbell;
pub mod messaging;
pub mod node;
pub mod protocol;
pub mod queue;

pub use doorbell::{
    DoorbellConfig, DoorbellEndpoint, DoorbellError, DoorbellPing, DoorbellReceiver,
    DoorbellSender, DoorbellTransport,
};
pub use messaging::{prepare_outgoing_message, process_incoming_message};
pub use node::{NodeConfig, NodeEvent, SofaNode};
pub use protocol::MessageEnvelope;
pub use queue::QueueId;
