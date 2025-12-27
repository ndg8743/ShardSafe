//! P2P Node implementation

use futures::StreamExt;
use libp2p::{
    identity, kad,
    noise,
    request_response::{self, ResponseChannel},
    swarm::SwarmEvent,
    yamux, Multiaddr, PeerId, Swarm,
};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::behaviour::{P2PBehaviour, P2PBehaviourEvent};
use super::protocol::{ChunkRequest, ChunkResponse};
use crate::crypto::ChunkId;
use crate::storage::ChunkStore;

#[derive(Error, Debug)]
pub enum NodeError {
    #[error("Transport error: {0}")]
    Transport(String),
    #[error("Dial error: {0}")]
    Dial(String),
    #[error("Chunk not found")]
    ChunkNotFound,
    #[error("Storage error: {0}")]
    Storage(String),
}

/// Node configuration
#[derive(Clone)]
pub struct NodeConfig {
    /// Port to listen on (0 for random)
    pub listen_port: u16,
    /// Bootstrap peers to connect to
    pub bootstrap_peers: Vec<(PeerId, Multiaddr)>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            listen_port: 0,
            bootstrap_peers: vec![],
        }
    }
}

/// Events emitted by the node
#[derive(Debug, Clone)]
pub enum NodeEvent {
    /// Node started listening
    Listening { address: Multiaddr },
    /// Connected to a peer
    PeerConnected { peer_id: PeerId },
    /// Disconnected from a peer
    PeerDisconnected { peer_id: PeerId },
    /// Chunk received from network
    ChunkReceived { chunk_id: ChunkId },
    /// Chunk stored by peer
    ChunkStored { chunk_id: ChunkId, peer_id: PeerId },
}

/// P2P Node
pub struct P2PNode {
    swarm: Swarm<P2PBehaviour>,
    chunk_store: Arc<ChunkStore>,
    event_tx: mpsc::Sender<NodeEvent>,
    local_peer_id: PeerId,
}

impl P2PNode {
    /// Create a new P2P node
    pub async fn new(
        chunk_store: Arc<ChunkStore>,
        config: NodeConfig,
    ) -> Result<(Self, mpsc::Receiver<NodeEvent>), NodeError> {
        // Generate identity
        let local_key = identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());
        let local_public_key = local_key.public();

        info!("Local peer ID: {}", local_peer_id);

        // Build swarm
        let swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| NodeError::Transport(e.to_string()))?
            .with_quic()
            .with_behaviour(|_| P2PBehaviour::new(local_peer_id, local_public_key))
            .map_err(|e| NodeError::Transport(e.to_string()))?
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(std::time::Duration::from_secs(60)))
            .build();

        let (event_tx, event_rx) = mpsc::channel(100);

        let mut node = Self {
            swarm,
            chunk_store,
            event_tx,
            local_peer_id,
        };

        // Start listening
        let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", config.listen_port)
            .parse()
            .unwrap();
        node.swarm
            .listen_on(listen_addr)
            .map_err(|e| NodeError::Transport(e.to_string()))?;

        // Connect to bootstrap peers
        for (peer_id, addr) in config.bootstrap_peers {
            node.swarm
                .dial(addr.clone())
                .map_err(|e| NodeError::Dial(e.to_string()))?;
            node.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
        }

        Ok((node, event_rx))
    }

    /// Get local peer ID
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// Get connected peer count
    pub fn peer_count(&self) -> usize {
        self.swarm.connected_peers().count()
    }

    /// Request a chunk from the network
    pub fn request_chunk(&mut self, peer_id: PeerId, chunk_id: ChunkId) {
        let request = ChunkRequest::Get { chunk_id };
        self.swarm
            .behaviour_mut()
            .chunk_transfer
            .send_request(&peer_id, request);
    }

    /// Store a chunk to a peer
    pub fn store_chunk(&mut self, peer_id: PeerId, data: Vec<u8>) {
        let request = ChunkRequest::Store { data };
        self.swarm
            .behaviour_mut()
            .chunk_transfer
            .send_request(&peer_id, request);
    }

    /// Announce chunk availability to DHT
    pub fn announce_chunk(&mut self, chunk_id: &ChunkId) {
        let key = kad::RecordKey::new(&chunk_id.as_bytes());
        self.swarm
            .behaviour_mut()
            .kademlia
            .start_providing(key)
            .ok();
    }

    /// Find providers for a chunk
    pub fn find_chunk_providers(&mut self, chunk_id: &ChunkId) {
        let key = kad::RecordKey::new(&chunk_id.as_bytes());
        self.swarm.behaviour_mut().kademlia.get_providers(key);
    }

    /// Run the node event loop
    pub async fn run(&mut self) {
        loop {
            if let Some(event) = self.swarm.next().await {
                self.handle_swarm_event(event).await;
            }
        }
    }

    /// Handle swarm events
    async fn handle_swarm_event(&mut self, event: SwarmEvent<P2PBehaviourEvent>) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Listening on {}", address);
                let _ = self.event_tx.send(NodeEvent::Listening { address }).await;
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                info!("Connected to {}", peer_id);
                let _ = self
                    .event_tx
                    .send(NodeEvent::PeerConnected { peer_id })
                    .await;
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                info!("Disconnected from {}", peer_id);
                let _ = self
                    .event_tx
                    .send(NodeEvent::PeerDisconnected { peer_id })
                    .await;
            }
            SwarmEvent::Behaviour(behaviour_event) => {
                self.handle_behaviour_event(behaviour_event).await;
            }
            _ => {}
        }
    }

    /// Handle behaviour events
    async fn handle_behaviour_event(&mut self, event: P2PBehaviourEvent) {
        match event {
            P2PBehaviourEvent::ChunkTransfer(chunk_event) => {
                self.handle_chunk_event(chunk_event).await;
            }
            P2PBehaviourEvent::Kademlia(kad_event) => {
                self.handle_kad_event(kad_event);
            }
            P2PBehaviourEvent::Identify(identify_event) => {
                if let libp2p::identify::Event::Received { peer_id, info, .. } = identify_event {
                    debug!("Identified peer {}: {:?}", peer_id, info.protocols);
                    // Add peer addresses to Kademlia
                    for addr in info.listen_addrs {
                        self.swarm
                            .behaviour_mut()
                            .kademlia
                            .add_address(&peer_id, addr);
                    }
                }
            }
            P2PBehaviourEvent::Ping(_) => {}
        }
    }

    /// Handle chunk transfer events
    async fn handle_chunk_event(
        &mut self,
        event: request_response::Event<ChunkRequest, ChunkResponse>,
    ) {
        match event {
            request_response::Event::Message { peer, message } => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    self.handle_chunk_request(request, channel);
                }
                request_response::Message::Response { response, .. } => {
                    self.handle_chunk_response(peer, response).await;
                }
            },
            request_response::Event::OutboundFailure { peer, error, .. } => {
                warn!("Outbound request to {} failed: {:?}", peer, error);
            }
            request_response::Event::InboundFailure { peer, error, .. } => {
                warn!("Inbound request from {} failed: {:?}", peer, error);
            }
            _ => {}
        }
    }

    /// Handle incoming chunk requests
    fn handle_chunk_request(
        &mut self,
        request: ChunkRequest,
        channel: ResponseChannel<ChunkResponse>,
    ) {
        let response = match request {
            ChunkRequest::Get { chunk_id } => {
                match self.chunk_store.get(&chunk_id) {
                    Ok(data) => ChunkResponse::Chunk { chunk_id, data },
                    Err(_) => ChunkResponse::Error {
                        message: "Chunk not found".to_string(),
                    },
                }
            }
            ChunkRequest::Store { data } => {
                let chunk_id = ChunkId::from_data(&data);
                match self.chunk_store.store(&chunk_id, &data) {
                    Ok(_) => {
                        // Announce to DHT that we have this chunk
                        self.announce_chunk(&chunk_id);
                        ChunkResponse::Stored { chunk_id }
                    }
                    Err(e) => ChunkResponse::Error {
                        message: e.to_string(),
                    },
                }
            }
            ChunkRequest::Has { chunk_id } => {
                let has = self.chunk_store.has(&chunk_id).unwrap_or(false);
                ChunkResponse::HasResult { chunk_id, has }
            }
        };

        let _ = self
            .swarm
            .behaviour_mut()
            .chunk_transfer
            .send_response(channel, response);
    }

    /// Handle chunk responses
    async fn handle_chunk_response(&mut self, peer: PeerId, response: ChunkResponse) {
        match response {
            ChunkResponse::Chunk { chunk_id, data } => {
                // Store received chunk locally
                if self.chunk_store.store(&chunk_id, &data).is_ok() {
                    let _ = self
                        .event_tx
                        .send(NodeEvent::ChunkReceived { chunk_id })
                        .await;
                }
            }
            ChunkResponse::Stored { chunk_id } => {
                let _ = self
                    .event_tx
                    .send(NodeEvent::ChunkStored {
                        chunk_id,
                        peer_id: peer,
                    })
                    .await;
            }
            ChunkResponse::HasResult { chunk_id, has } => {
                debug!("Peer {} has chunk {}: {}", peer, chunk_id, has);
            }
            ChunkResponse::Error { message } => {
                warn!("Chunk error from {}: {}", peer, message);
            }
        }
    }

    /// Handle Kademlia events
    fn handle_kad_event(&mut self, event: kad::Event) {
        match event {
            kad::Event::RoutingUpdated { peer, .. } => {
                debug!("Kademlia routing updated for {}", peer);
            }
            kad::Event::OutboundQueryProgressed { result, .. } => match result {
                kad::QueryResult::GetProviders(Ok(kad::GetProvidersOk::FoundProviders {
                    providers,
                    key,
                    ..
                })) => {
                    debug!("Found {} providers for {:?}", providers.len(), key);
                }
                kad::QueryResult::StartProviding(Ok(kad::AddProviderOk { key })) => {
                    debug!("Started providing {:?}", key);
                }
                _ => {}
            },
            _ => {}
        }
    }
}
