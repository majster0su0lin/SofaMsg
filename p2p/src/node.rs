/// libp2p node — Kademlia DHT swarm for peer-to-peer messaging.
///
/// This module sets up a libp2p Swarm with:
/// - **TCP transport** with **Noise** encryption and **Yamux** multiplexing
/// - **Kademlia DHT** for storing/retrieving messages under Queue IDs
/// - **Identify** protocol for peer discovery and NAT detection
///
/// The node exposes async methods for:
/// - Starting and listening on a port
/// - Connecting to bootstrap peers
/// - Putting messages onto the DHT (sending)
/// - Getting messages from the DHT (receiving)
/// - Removing delivered messages from the DHT

use std::time::Duration;

use libp2p::{
    kad,
    noise,
    tcp,
    yamux,
    swarm::NetworkBehaviour,
    Multiaddr,
    PeerId,
    Swarm,
};
use tokio::sync::mpsc;

use crate::queue::QueueId;
use crate::protocol::{MessageEnvelope, QueuedMessages};

// ── Behaviour ────────────────────────────────────────────────

/// Combined network behaviour for the SofaMsg node.
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "SofaBehaviourEvent")]
struct SofaBehaviour {
    /// Kademlia DHT — stores message records and handles peer routing.
    kademlia: kad::Behaviour<kad::store::MemoryStore>,
    /// Identify — exchanges peer info (public key, protocols, addresses)
    /// automatically on every new connection.
    identify: libp2p::identify::Behaviour,
}

/// Events emitted by our combined behaviour.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum SofaBehaviourEvent {
    Kademlia(kad::Event),
    Identify(libp2p::identify::Event),
}

impl From<kad::Event> for SofaBehaviourEvent {
    fn from(e: kad::Event) -> Self {
        SofaBehaviourEvent::Kademlia(e)
    }
}

impl From<libp2p::identify::Event> for SofaBehaviourEvent {
    fn from(e: libp2p::identify::Event) -> Self {
        SofaBehaviourEvent::Identify(e)
    }
}

// ── Public types ─────────────────────────────────────────────

/// Configuration for creating a new SofaNode.
pub struct NodeConfig {
    /// TCP port to listen on. 0 = OS-assigned random port.
    pub listen_port: u16,
    /// Optional list of bootstrap peer addresses to connect to on start.
    pub bootstrap_peers: Vec<(PeerId, Multiaddr)>,
    /// Idle connection timeout.
    pub idle_timeout_secs: u64,
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            listen_port: 0,
            bootstrap_peers: Vec::new(),
            idle_timeout_secs: 60,
        }
    }
}

/// Events surfaced from the node's event loop to the application layer.
#[derive(Debug)]
pub enum NodeEvent {
    /// Successfully started listening on an address.
    Listening(Multiaddr),
    /// A message was successfully stored on the DHT.
    MessageStored { queue_id: String },
    /// Messages were retrieved from the DHT for our Queue ID.
    MessagesReceived { messages: Vec<MessageEnvelope> },
    /// A DHT query completed but found no records.
    NoMessages { queue_id: String },
    /// A peer was discovered via Identify.
    PeerDiscovered { peer_id: PeerId },
    /// An error occurred.
    Error(String),
}

// ── SofaNode ─────────────────────────────────────────────────

/// A running P2P node that participates in the SofaMsg DHT network.
pub struct SofaNode {
    /// Channel to send commands to the event loop.
    cmd_tx: mpsc::Sender<NodeCommand>,
    /// Channel to receive events from the event loop.
    event_rx: mpsc::Receiver<NodeEvent>,
    /// Our libp2p PeerId.
    pub peer_id: PeerId,
}

/// Commands sent from the application to the node's event loop.
enum NodeCommand {
    /// Store a message envelope on the DHT under the recipient's Queue ID.
    PutMessage {
        recipient_queue: QueueId,
        envelope: MessageEnvelope,
    },
    /// Query the DHT for messages under our Queue ID.
    GetMessages {
        our_queue: QueueId,
    },
    /// Connect to a specific peer by address.
    Dial {
        addr: Multiaddr,
    },
    /// Shut down the node.
    Shutdown,
}

impl SofaNode {
    /// Create and start a new P2P node.
    ///
    /// This spawns a background tokio task running the libp2p event loop.
    /// Use the returned `SofaNode` to send commands and receive events.
    pub async fn start(config: NodeConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        let (event_tx, event_rx) = mpsc::channel(64);

        // Build the swarm
        let swarm = libp2p::SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_behaviour(|key| {
                let peer_id = key.public().to_peer_id();

                // Kademlia with in-memory store
                let mut kad_config = kad::Config::new(
                    libp2p::StreamProtocol::new("/sofamsg/kad/1.0.0"),
                );
                kad_config.set_record_ttl(Some(Duration::from_secs(3600))); // 1 hour TTL
                kad_config.set_replication_factor(
                    std::num::NonZeroUsize::new(3).expect("3 > 0"),
                );

                let store = kad::store::MemoryStore::new(peer_id);
                let kademlia = kad::Behaviour::with_config(peer_id, store, kad_config);

                // Identify
                let identify = libp2p::identify::Behaviour::new(
                    libp2p::identify::Config::new(
                        "/sofamsg/id/1.0.0".to_string(),
                        key.public(),
                    )
                    .with_push_listen_addr_updates(true),
                );

                Ok(SofaBehaviour { kademlia, identify })
            })?
            .with_swarm_config(|cfg| {
                cfg.with_idle_connection_timeout(
                    Duration::from_secs(config.idle_timeout_secs),
                )
            })
            .build();

        let peer_id = *swarm.local_peer_id();
        let listen_port = config.listen_port;
        let bootstrap_peers = config.bootstrap_peers;

        // Spawn the event loop
        tokio::spawn(Self::event_loop(
            swarm,
            cmd_rx,
            event_tx,
            listen_port,
            bootstrap_peers,
        ));

        Ok(SofaNode {
            cmd_tx,
            event_rx,
            peer_id,
        })
    }

    /// Send a message to a peer by storing it on the DHT under their Queue ID.
    pub async fn send_message(
        &self,
        recipient_queue: QueueId,
        envelope: MessageEnvelope,
    ) -> Result<(), String> {
        self.cmd_tx
            .send(NodeCommand::PutMessage {
                recipient_queue,
                envelope,
            })
            .await
            .map_err(|e| format!("node event loop has shut down: {e}"))
    }

    /// Check for incoming messages by querying the DHT for our Queue ID.
    pub async fn check_messages(
        &self,
        our_queue: QueueId,
    ) -> Result<(), String> {
        self.cmd_tx
            .send(NodeCommand::GetMessages { our_queue })
            .await
            .map_err(|e| format!("node event loop has shut down: {e}"))
    }

    /// Connect to a peer by multiaddress.
    pub async fn dial(
        &self,
        addr: Multiaddr,
    ) -> Result<(), String> {
        self.cmd_tx
            .send(NodeCommand::Dial { addr })
            .await
            .map_err(|e| format!("node event loop has shut down: {e}"))
    }

    /// Receive the next event from the node.
    pub async fn next_event(&mut self) -> Option<NodeEvent> {
        self.event_rx.recv().await
    }

    /// Shut down the node.
    pub async fn shutdown(&self) {
        let _ = self.cmd_tx.send(NodeCommand::Shutdown).await;
    }

    // ── Internal event loop ──────────────────────────────────

    async fn event_loop(
        mut swarm: Swarm<SofaBehaviour>,
        mut cmd_rx: mpsc::Receiver<NodeCommand>,
        event_tx: mpsc::Sender<NodeEvent>,
        listen_port: u16,
        bootstrap_peers: Vec<(PeerId, Multiaddr)>,
    ) {
        // Start listening
        let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{listen_port}")
            .parse()
            .expect("valid multiaddr");

        if let Err(e) = swarm.listen_on(listen_addr) {
            let _ = event_tx.send(NodeEvent::Error(format!("Listen failed: {e}"))).await;
            return;
        }

        // Add bootstrap peers to Kademlia routing table
        for (peer_id, addr) in &bootstrap_peers {
            swarm.behaviour_mut().kademlia.add_address(peer_id, addr.clone());
        }

        // Bootstrap the DHT if we have peers
        if !bootstrap_peers.is_empty() {
            let _ = swarm.behaviour_mut().kademlia.bootstrap();
        }

        loop {
            tokio::select! {
                // Process swarm events
                event = swarm.next() => {
                    use libp2p::swarm::SwarmEvent::*;
                    match event {
                        Some(NewListenAddr { address, .. }) => {
                            let _ = event_tx.send(NodeEvent::Listening(address)).await;
                        }
                        Some(Behaviour(SofaBehaviourEvent::Kademlia(kad_event))) => {
                            Self::handle_kad_event(kad_event, &event_tx).await;
                        }
                        Some(Behaviour(SofaBehaviourEvent::Identify(
                            libp2p::identify::Event::Received { peer_id, info, .. },
                        ))) => {
                            // Add discovered peer's addresses to Kademlia
                            for addr in info.listen_addrs {
                                swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                            }
                            let _ = event_tx.send(NodeEvent::PeerDiscovered { peer_id }).await;
                        }
                        None => break, // Swarm closed
                        _ => {} // Ignore other events
                    }
                }

                // Process commands from the application
                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(NodeCommand::PutMessage { recipient_queue, envelope }) => {
                            Self::handle_put_message(
                                &mut swarm,
                                &event_tx,
                                recipient_queue,
                                envelope,
                            ).await;
                        }
                        Some(NodeCommand::GetMessages { our_queue }) => {
                            let key = our_queue.to_kad_key();
                            swarm.behaviour_mut().kademlia.get_record(key);
                        }
                        Some(NodeCommand::Dial { addr }) => {
                            if let Err(e) = swarm.dial(addr.clone()) {
                                let _ = event_tx.send(
                                    NodeEvent::Error(format!("Dial failed: {e}"))
                                ).await;
                            }
                        }
                        Some(NodeCommand::Shutdown) | None => break,
                    }
                }
            }
        }
    }

    async fn handle_put_message(
        swarm: &mut Swarm<SofaBehaviour>,
        event_tx: &mpsc::Sender<NodeEvent>,
        recipient_queue: QueueId,
        envelope: MessageEnvelope,
    ) {
        let key = recipient_queue.to_kad_key();
        let queue_id_str = recipient_queue.as_str().to_string();

        // Wrap in QueuedMessages
        let mut queued = QueuedMessages::new();
        queued.push(envelope);

        match queued.to_bytes() {
            Ok(value) => {
                let record = kad::Record {
                    key,
                    value,
                    publisher: None,
                    expires: None,
                };
                if let Err(e) = swarm.behaviour_mut().kademlia.put_record(
                    record,
                    kad::Quorum::One,
                ) {
                    let _ = event_tx.send(
                        NodeEvent::Error(format!("DHT put failed: {e}"))
                    ).await;
                } else {
                    let _ = event_tx.send(
                        NodeEvent::MessageStored { queue_id: queue_id_str }
                    ).await;
                }
            }
            Err(e) => {
                let _ = event_tx.send(
                    NodeEvent::Error(format!("Serialization failed: {e}"))
                ).await;
            }
        }
    }

    async fn handle_kad_event(
        event: kad::Event,
        event_tx: &mpsc::Sender<NodeEvent>,
    ) {
        match event {
            kad::Event::OutboundQueryProgressed {
                result: kad::QueryResult::GetRecord(Ok(
                    kad::GetRecordOk::FoundRecord(peer_record),
                )),
                ..
            } => {
                // Deserialize the retrieved record
                match QueuedMessages::from_bytes(&peer_record.record.value) {
                    Ok(queued) => {
                        let _ = event_tx.send(NodeEvent::MessagesReceived {
                            messages: queued.envelopes,
                        }).await;
                    }
                    Err(e) => {
                        let _ = event_tx.send(NodeEvent::Error(
                            format!("Failed to deserialize DHT record: {e}")
                        )).await;
                    }
                }
            }
            kad::Event::OutboundQueryProgressed {
                result: kad::QueryResult::GetRecord(Ok(
                    kad::GetRecordOk::FinishedWithNoAdditionalRecord { .. },
                )),
                ..
            } => {
                let _ = event_tx.send(NodeEvent::NoMessages {
                    queue_id: "unknown".to_string(),
                }).await;
            }
            kad::Event::OutboundQueryProgressed {
                result: kad::QueryResult::GetRecord(Err(e)),
                ..
            } => {
                let _ = event_tx.send(NodeEvent::NoMessages {
                    queue_id: format!("query error: {e:?}"),
                }).await;
            }
            _ => {} // Ignore other Kademlia events
        }
    }
}

// Needed for SwarmEvent pattern matching
use futures::StreamExt;
