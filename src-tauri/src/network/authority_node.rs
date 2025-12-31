//! Authority-Enhanced P2P Node
//!
//! Wraps the base P2P node with authority tracking, traffic analysis,
//! and consensus-based validation.

use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info};
use libp2p::PeerId;

use super::node::{P2PNode, NodeConfig, NodeEvent, NodeError};
use super::protocol::{ChunkRequest, ChunkResponse};
use crate::authority::{AuthoritySystem, TrafficType, StateTransition};
use crate::consensus::{ConsensusSystem, ConsensusConfig, ChunkValidation};
use crate::crypto::ChunkId;
use crate::storage::ChunkStore;

/// Configuration for the authority-enhanced node
#[derive(Clone)]
pub struct AuthorityNodeConfig {
    /// Base node configuration
    pub node_config: NodeConfig,
    /// Consensus configuration
    pub consensus_config: ConsensusConfig,
    /// Whether to require consensus for chunk storage
    pub require_consensus_for_storage: bool,
    /// Minimum authority score to accept chunk from
    pub min_authority_for_chunk: f64,
    /// Enable automatic traffic recording
    pub auto_record_traffic: bool,
}

impl Default for AuthorityNodeConfig {
    fn default() -> Self {
        Self {
            node_config: NodeConfig::default(),
            consensus_config: ConsensusConfig::default(),
            require_consensus_for_storage: false, // Start permissive
            min_authority_for_chunk: 0.0,
            auto_record_traffic: true,
        }
    }
}

/// Events specific to the authority system
#[derive(Debug, Clone)]
pub enum AuthorityEvent {
    /// Authority scores updated
    AuthorityUpdated {
        top_authorities: Vec<(PeerId, f64)>,
    },
    /// Peer state changed
    PeerStateChanged {
        peer_id: PeerId,
        old_state: crate::authority::PeerState,
        new_state: crate::authority::PeerState,
    },
    /// Chunk validation completed
    ChunkValidated {
        chunk_id: ChunkId,
        accepted: bool,
        score: f64,
    },
    /// Network metrics updated
    MetricsUpdated {
        total_peers: usize,
        active_peers: usize,
        total_traffic: u64,
    },
}

/// Authority-enhanced P2P node
pub struct AuthorityNode {
    /// Base P2P node
    node: P2PNode,
    /// Authority system
    authority: Arc<AuthoritySystem>,
    /// Consensus system
    consensus: Arc<ConsensusSystem>,
    /// Configuration
    config: AuthorityNodeConfig,
    /// Authority event sender
    authority_event_tx: mpsc::Sender<AuthorityEvent>,
}

impl AuthorityNode {
    /// Create a new authority-enhanced node
    pub async fn new(
        chunk_store: Arc<ChunkStore>,
        config: AuthorityNodeConfig,
    ) -> Result<(Self, mpsc::Receiver<NodeEvent>, mpsc::Receiver<AuthorityEvent>), NodeError> {
        let (node, node_event_rx) = P2PNode::new(chunk_store, config.node_config.clone()).await?;

        let local_peer_id = node.local_peer_id();
        let authority = Arc::new(AuthoritySystem::new(local_peer_id));
        let consensus = Arc::new(ConsensusSystem::new(
            authority.clone(),
            config.consensus_config.clone(),
        ));

        let (authority_event_tx, authority_event_rx) = mpsc::channel(100);

        Ok((
            Self {
                node,
                authority,
                consensus,
                config,
                authority_event_tx,
            },
            node_event_rx,
            authority_event_rx,
        ))
    }

    /// Get local peer ID
    pub fn local_peer_id(&self) -> PeerId {
        self.node.local_peer_id()
    }

    /// Get connected peer count
    pub fn peer_count(&self) -> usize {
        self.node.peer_count()
    }

    /// Get the authority system
    pub fn authority(&self) -> &Arc<AuthoritySystem> {
        &self.authority
    }

    /// Get the consensus system
    pub fn consensus(&self) -> &Arc<ConsensusSystem> {
        &self.consensus
    }

    /// Record peer connected event
    pub async fn on_peer_connected(&self, peer_id: PeerId) {
        self.authority.peer_connected(peer_id).await;
        debug!("Authority: Peer {} connected", peer_id);
    }

    /// Record peer disconnected event
    pub async fn on_peer_disconnected(&self, peer_id: PeerId) {
        self.authority.peer_disconnected(peer_id).await;
        debug!("Authority: Peer {} disconnected", peer_id);
    }

    /// Record chunk transfer traffic
    pub async fn on_chunk_transferred(
        &self,
        from: PeerId,
        to: PeerId,
        bytes: u64,
        is_store: bool,
    ) {
        if self.config.auto_record_traffic {
            let traffic_type = if is_store {
                TrafficType::ChunkTransfer
            } else {
                TrafficType::ChunkRequest
            };
            self.authority.record_traffic(from, to, traffic_type, bytes).await;
        }
    }

    /// Record chunk validation result
    pub async fn on_chunk_validated(&self, peer_id: PeerId, chunk_id: &ChunkId, valid: bool) {
        let transition = if valid {
            StateTransition::ValidateSuccess
        } else {
            StateTransition::ValidateFail
        };
        self.authority.transition_peer_state(peer_id, transition).await;
    }

    /// Check if peer has sufficient authority to provide chunks
    pub async fn check_peer_authority(&self, peer_id: &PeerId) -> bool {
        if self.config.min_authority_for_chunk <= 0.0 {
            return true;
        }
        let score = self.authority.get_combined_score(peer_id).await;
        score >= self.config.min_authority_for_chunk
    }

    /// Get authority scores for all peers
    pub async fn get_authority_scores(&self) -> Vec<(PeerId, f64)> {
        let scores = self.authority.compute_authority_scores().await;
        let mut result: Vec<_> = scores.all().iter().map(|(p, s)| (*p, *s)).collect();
        result.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        result
    }

    /// Get network statistics
    pub async fn get_network_stats(&self) -> crate::authority::NetworkStats {
        self.authority.get_network_stats().await
    }

    /// Start chunk validation round
    pub async fn start_validation(&self, chunk_id: ChunkId) -> bool {
        self.consensus.start_validation(chunk_id).await
    }

    /// Submit validation vote
    pub async fn submit_validation_vote(
        &self,
        chunk_id: &ChunkId,
        voter: PeerId,
        valid: bool,
    ) -> Result<(), crate::consensus::ConsensusError> {
        let validation = if valid {
            ChunkValidation::valid(chunk_id.clone())
        } else {
            ChunkValidation::invalid(chunk_id.clone(), "Validation failed".to_string())
        };

        self.consensus.submit_vote(chunk_id, voter, validation).await
    }

    /// Check if chunk is validated
    pub async fn is_chunk_validated(&self, chunk_id: &ChunkId) -> Option<bool> {
        self.consensus.is_chunk_valid(chunk_id).await
    }

    /// Request a chunk with authority check
    pub async fn request_chunk_with_authority(
        &mut self,
        peer_id: PeerId,
        chunk_id: ChunkId,
    ) -> Result<(), AuthorityError> {
        // Check peer authority
        if !self.check_peer_authority(&peer_id).await {
            return Err(AuthorityError::InsufficientAuthority(peer_id));
        }

        // Record traffic
        self.authority
            .record_traffic(self.local_peer_id(), peer_id, TrafficType::ChunkRequest, 32)
            .await;

        // Send request
        self.node.request_chunk(peer_id, chunk_id);
        Ok(())
    }

    /// Get mutable access to the base node
    pub fn node_mut(&mut self) -> &mut P2PNode {
        &mut self.node
    }

    /// Get the base node
    pub fn node(&self) -> &P2PNode {
        &self.node
    }

    /// Run periodic maintenance tasks
    pub async fn run_maintenance(&self) {
        // Prune inactive peers
        self.authority.prune_inactive(3600).await; // 1 hour timeout

        // Update and broadcast authority scores
        let top = self.authority.get_authority_nodes(10).await;

        let _ = self
            .authority_event_tx
            .send(AuthorityEvent::AuthorityUpdated {
                top_authorities: top,
            })
            .await;

        // Get network stats
        let stats = self.authority.get_network_stats().await;
        let _ = self
            .authority_event_tx
            .send(AuthorityEvent::MetricsUpdated {
                total_peers: stats.total_peers,
                active_peers: stats.active_peers,
                total_traffic: stats.total_traffic_bytes,
            })
            .await;

        info!(
            "Maintenance: {} total peers, {} active, {} bytes traffic",
            stats.total_peers, stats.active_peers, stats.total_traffic_bytes
        );
    }
}

/// Errors specific to authority operations
#[derive(Debug)]
pub enum AuthorityError {
    InsufficientAuthority(PeerId),
    ValidationFailed(ChunkId),
    ConsensusError(crate::consensus::ConsensusError),
}

impl std::fmt::Display for AuthorityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthorityError::InsufficientAuthority(peer) => {
                write!(f, "Peer {} has insufficient authority", peer)
            }
            AuthorityError::ValidationFailed(chunk) => {
                write!(f, "Chunk {} failed validation", chunk)
            }
            AuthorityError::ConsensusError(e) => write!(f, "Consensus error: {}", e),
        }
    }
}

impl std::error::Error for AuthorityError {}

impl From<crate::consensus::ConsensusError> for AuthorityError {
    fn from(e: crate::consensus::ConsensusError) -> Self {
        AuthorityError::ConsensusError(e)
    }
}
