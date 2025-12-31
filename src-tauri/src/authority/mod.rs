//! Authority Discovery Module
//!
//! Implements Eigenvector Centrality-based authority discovery for finding
//! "server authoritative" nodes in the P2P network. The system:
//!
//! 1. Builds a directed graph from network traffic patterns
//! 2. Computes Eigenvector Centrality to identify high-authority nodes
//! 3. Tracks peer state transitions via a finite state machine
//! 4. Maintains reputation scores based on behavior history
//! 5. Provides network metrics and analytics

mod graph;
mod centrality;
mod state_machine;
mod reputation;
pub mod metrics;

pub use graph::{NetworkGraph, EdgeWeight, TrafficType};
pub use centrality::{AuthorityScores, CentralityConfig};
pub use state_machine::{PeerState, PeerStateMachine, StateTransition};
pub use reputation::{ReputationScore, ReputationSystem, ReputationConfig};

use libp2p::PeerId;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Authority discovery system combining graph analysis, state machines, and reputation
pub struct AuthoritySystem {
    /// Network topology graph
    graph: Arc<RwLock<NetworkGraph>>,
    /// Peer state machines
    state_machines: Arc<RwLock<HashMap<PeerId, PeerStateMachine>>>,
    /// Reputation system
    reputation: Arc<RwLock<ReputationSystem>>,
    /// Centrality configuration
    centrality_config: CentralityConfig,
    /// Local peer ID
    local_peer_id: PeerId,
}

impl AuthoritySystem {
    /// Create a new authority system
    pub fn new(local_peer_id: PeerId) -> Self {
        Self {
            graph: Arc::new(RwLock::new(NetworkGraph::new())),
            state_machines: Arc::new(RwLock::new(HashMap::new())),
            reputation: Arc::new(RwLock::new(ReputationSystem::new(ReputationConfig::default()))),
            centrality_config: CentralityConfig::default(),
            local_peer_id,
        }
    }

    /// Create with custom configuration
    pub fn with_config(
        local_peer_id: PeerId,
        centrality_config: CentralityConfig,
        reputation_config: ReputationConfig,
    ) -> Self {
        Self {
            graph: Arc::new(RwLock::new(NetworkGraph::new())),
            state_machines: Arc::new(RwLock::new(HashMap::new())),
            reputation: Arc::new(RwLock::new(ReputationSystem::new(reputation_config))),
            centrality_config,
            local_peer_id,
        }
    }

    /// Record a traffic event between peers
    pub async fn record_traffic(
        &self,
        from: PeerId,
        to: PeerId,
        traffic_type: TrafficType,
        bytes: u64,
    ) {
        let mut graph = self.graph.write().await;
        graph.record_traffic(from, to, traffic_type, bytes);
        debug!("Recorded traffic: {} -> {} ({:?}, {} bytes)", from, to, traffic_type, bytes);
    }

    /// Record a peer connection
    pub async fn peer_connected(&self, peer_id: PeerId) {
        // Add to graph
        {
            let mut graph = self.graph.write().await;
            graph.add_peer(peer_id);
        }

        // Initialize state machine if new
        {
            let mut state_machines = self.state_machines.write().await;
            state_machines.entry(peer_id).or_insert_with(|| {
                info!("New peer state machine for: {}", peer_id);
                PeerStateMachine::new(peer_id)
            });
        }

        // Update state to connected
        self.transition_peer_state(peer_id, StateTransition::Connect).await;
    }

    /// Record a peer disconnection
    pub async fn peer_disconnected(&self, peer_id: PeerId) {
        self.transition_peer_state(peer_id, StateTransition::Disconnect).await;
    }

    /// Transition a peer's state
    pub async fn transition_peer_state(&self, peer_id: PeerId, transition: StateTransition) {
        let mut state_machines = self.state_machines.write().await;
        if let Some(sm) = state_machines.get_mut(&peer_id) {
            let old_state = sm.current_state();
            sm.apply_transition(transition.clone());
            let new_state = sm.current_state();

            if old_state != new_state {
                debug!("Peer {} state: {:?} -> {:?}", peer_id, old_state, new_state);

                // Update reputation based on state transitions
                drop(state_machines);
                self.update_reputation_for_transition(peer_id, &transition).await;
            }
        }
    }

    /// Update reputation based on state transition
    async fn update_reputation_for_transition(&self, peer_id: PeerId, transition: &StateTransition) {
        let mut reputation = self.reputation.write().await;
        match transition {
            StateTransition::ServeChunk => reputation.record_positive(peer_id, 10),
            StateTransition::FailRequest => reputation.record_negative(peer_id, 5),
            StateTransition::Timeout => reputation.record_negative(peer_id, 3),
            StateTransition::ValidateSuccess => reputation.record_positive(peer_id, 15),
            StateTransition::ValidateFail => reputation.record_negative(peer_id, 20),
            _ => {}
        }
    }

    /// Compute authority scores using Eigenvector Centrality
    pub async fn compute_authority_scores(&self) -> AuthorityScores {
        let graph = self.graph.read().await;
        centrality::compute_eigenvector_centrality(&graph, &self.centrality_config)
    }

    /// Get the top N authority nodes
    pub async fn get_authority_nodes(&self, n: usize) -> Vec<(PeerId, f64)> {
        let scores = self.compute_authority_scores().await;
        scores.top_n(n)
    }

    /// Check if a peer is an authority node (top percentile)
    pub async fn is_authority(&self, peer_id: &PeerId, percentile: f64) -> bool {
        let scores = self.compute_authority_scores().await;
        scores.is_in_percentile(peer_id, percentile)
    }

    /// Get combined score (centrality + reputation)
    pub async fn get_combined_score(&self, peer_id: &PeerId) -> f64 {
        let authority_scores = self.compute_authority_scores().await;
        let reputation = self.reputation.read().await;

        let centrality = authority_scores.get(peer_id).unwrap_or(0.0);
        let rep_score = reputation.get_score(peer_id).normalized();

        // Weighted combination: 60% centrality, 40% reputation
        0.6 * centrality + 0.4 * rep_score
    }

    /// Get peer state
    pub async fn get_peer_state(&self, peer_id: &PeerId) -> Option<PeerState> {
        let state_machines = self.state_machines.read().await;
        state_machines.get(peer_id).map(|sm| sm.current_state())
    }

    /// Get all active (connected) peers
    pub async fn get_active_peers(&self) -> Vec<PeerId> {
        let state_machines = self.state_machines.read().await;
        state_machines
            .iter()
            .filter(|(_, sm)| sm.is_active())
            .map(|(peer_id, _)| *peer_id)
            .collect()
    }

    /// Get network statistics
    pub async fn get_network_stats(&self) -> NetworkStats {
        let graph = self.graph.read().await;
        let state_machines = self.state_machines.read().await;
        let reputation = self.reputation.read().await;

        let active_peers = state_machines.values().filter(|sm| sm.is_active()).count();
        let total_peers = state_machines.len();

        NetworkStats {
            total_peers,
            active_peers,
            total_edges: graph.edge_count(),
            total_traffic_bytes: graph.total_traffic(),
            avg_reputation: reputation.average_score(),
        }
    }

    /// Prune inactive peers from the system
    pub async fn prune_inactive(&self, max_inactive_secs: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut state_machines = self.state_machines.write().await;
        let mut to_remove = Vec::new();

        for (peer_id, sm) in state_machines.iter() {
            if let Some(last_active) = sm.last_active_timestamp() {
                if now - last_active > max_inactive_secs {
                    to_remove.push(*peer_id);
                }
            }
        }

        for peer_id in to_remove {
            state_machines.remove(&peer_id);
            debug!("Pruned inactive peer: {}", peer_id);
        }
    }
}

/// Network statistics
#[derive(Debug, Clone)]
pub struct NetworkStats {
    pub total_peers: usize,
    pub active_peers: usize,
    pub total_edges: usize,
    pub total_traffic_bytes: u64,
    pub avg_reputation: f64,
}
