//! Network Graph Module
//!
//! Builds a directed weighted graph from P2P traffic patterns.
//! Nodes represent peers, edges represent communication with weights
//! based on traffic volume and type.

use libp2p::PeerId;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::Direction;
use std::collections::HashMap;

/// Types of traffic between peers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrafficType {
    /// Chunk data transfer
    ChunkTransfer,
    /// Chunk request (query)
    ChunkRequest,
    /// DHT routing
    DhtRouting,
    /// Ping/keepalive
    Ping,
    /// Identify protocol
    Identify,
    /// Provider announcement
    ProviderAnnounce,
    /// Provider query
    ProviderQuery,
}

impl TrafficType {
    /// Weight multiplier for this traffic type (importance for authority)
    pub fn weight_multiplier(&self) -> f64 {
        match self {
            TrafficType::ChunkTransfer => 10.0,   // High importance - actual data
            TrafficType::ChunkRequest => 5.0,     // Medium - indicates need
            TrafficType::ProviderAnnounce => 8.0, // High - indicates storage
            TrafficType::ProviderQuery => 4.0,    // Medium - indicates interest
            TrafficType::DhtRouting => 3.0,       // Lower - routing
            TrafficType::Identify => 1.0,         // Low - handshake
            TrafficType::Ping => 0.5,             // Lowest - keepalive
        }
    }
}

/// Edge weight combining multiple factors
#[derive(Debug, Clone)]
pub struct EdgeWeight {
    /// Total bytes transferred on this edge
    pub bytes: u64,
    /// Number of interactions
    pub interaction_count: u64,
    /// Traffic breakdown by type
    pub traffic_by_type: HashMap<TrafficType, u64>,
    /// Last interaction timestamp
    pub last_interaction: u64,
    /// First interaction timestamp
    pub first_interaction: u64,
}

impl EdgeWeight {
    fn new() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            bytes: 0,
            interaction_count: 0,
            traffic_by_type: HashMap::new(),
            last_interaction: now,
            first_interaction: now,
        }
    }

    fn add_traffic(&mut self, traffic_type: TrafficType, bytes: u64) {
        self.bytes += bytes;
        self.interaction_count += 1;
        *self.traffic_by_type.entry(traffic_type).or_insert(0) += bytes;
        self.last_interaction = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    /// Compute the weighted score for this edge
    pub fn weighted_score(&self) -> f64 {
        let type_score: f64 = self.traffic_by_type
            .iter()
            .map(|(t, b)| t.weight_multiplier() * (*b as f64).ln_1p())
            .sum();

        let recency_factor = {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let age_secs = now.saturating_sub(self.last_interaction);
            // Decay factor: halves every hour
            0.5_f64.powf(age_secs as f64 / 3600.0)
        };

        let longevity_factor = {
            let duration = self.last_interaction.saturating_sub(self.first_interaction);
            // Bonus for long-standing connections (up to 2x at 24 hours)
            1.0 + (duration as f64 / 86400.0).min(1.0)
        };

        type_score * recency_factor * longevity_factor
    }
}

/// Directed weighted graph representing network topology
pub struct NetworkGraph {
    /// The petgraph graph
    graph: DiGraph<PeerId, EdgeWeight>,
    /// Map from PeerId to node index
    peer_indices: HashMap<PeerId, NodeIndex>,
    /// Total traffic recorded
    total_traffic: u64,
}

impl NetworkGraph {
    /// Create a new empty network graph
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            peer_indices: HashMap::new(),
            total_traffic: 0,
        }
    }

    /// Add a peer to the graph
    pub fn add_peer(&mut self, peer_id: PeerId) -> NodeIndex {
        if let Some(&idx) = self.peer_indices.get(&peer_id) {
            return idx;
        }
        let idx = self.graph.add_node(peer_id);
        self.peer_indices.insert(peer_id, idx);
        idx
    }

    /// Get or create node index for a peer
    fn get_or_create_peer(&mut self, peer_id: PeerId) -> NodeIndex {
        self.add_peer(peer_id)
    }

    /// Record traffic between two peers
    pub fn record_traffic(
        &mut self,
        from: PeerId,
        to: PeerId,
        traffic_type: TrafficType,
        bytes: u64,
    ) {
        let from_idx = self.get_or_create_peer(from);
        let to_idx = self.get_or_create_peer(to);

        // Find existing edge or create new one
        if let Some(edge_idx) = self.graph.find_edge(from_idx, to_idx) {
            let weight = self.graph.edge_weight_mut(edge_idx).unwrap();
            weight.add_traffic(traffic_type, bytes);
        } else {
            let mut weight = EdgeWeight::new();
            weight.add_traffic(traffic_type, bytes);
            self.graph.add_edge(from_idx, to_idx, weight);
        }

        self.total_traffic += bytes;
    }

    /// Get all peers in the graph
    pub fn peers(&self) -> impl Iterator<Item = &PeerId> {
        self.graph.node_weights()
    }

    /// Get peer count
    pub fn peer_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Get edge count
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// Get total traffic
    pub fn total_traffic(&self) -> u64 {
        self.total_traffic
    }

    /// Get the internal graph reference (for algorithms)
    pub fn inner(&self) -> &DiGraph<PeerId, EdgeWeight> {
        &self.graph
    }

    /// Get peer index
    pub fn peer_index(&self, peer_id: &PeerId) -> Option<NodeIndex> {
        self.peer_indices.get(peer_id).copied()
    }

    /// Get peer ID from index
    pub fn peer_id(&self, index: NodeIndex) -> Option<&PeerId> {
        self.graph.node_weight(index)
    }

    /// Get outbound traffic weight sum for a peer
    pub fn outbound_weight(&self, peer_id: &PeerId) -> f64 {
        let Some(idx) = self.peer_indices.get(peer_id) else {
            return 0.0;
        };

        self.graph
            .edges_directed(*idx, Direction::Outgoing)
            .map(|e| e.weight().weighted_score())
            .sum()
    }

    /// Get inbound traffic weight sum for a peer
    pub fn inbound_weight(&self, peer_id: &PeerId) -> f64 {
        let Some(idx) = self.peer_indices.get(peer_id) else {
            return 0.0;
        };

        self.graph
            .edges_directed(*idx, Direction::Incoming)
            .map(|e| e.weight().weighted_score())
            .sum()
    }

    /// Get the weighted adjacency matrix
    pub fn weighted_adjacency_matrix(&self) -> Vec<Vec<f64>> {
        let n = self.graph.node_count();
        let mut matrix = vec![vec![0.0; n]; n];

        for edge in self.graph.edge_references() {
            let from = edge.source().index();
            let to = edge.target().index();
            matrix[from][to] = edge.weight().weighted_score();
        }

        matrix
    }

    /// Get neighbors of a peer
    pub fn neighbors(&self, peer_id: &PeerId) -> Vec<PeerId> {
        let Some(idx) = self.peer_indices.get(peer_id) else {
            return vec![];
        };

        self.graph
            .neighbors(*idx)
            .filter_map(|n| self.graph.node_weight(n).copied())
            .collect()
    }

    /// Remove a peer and all its edges
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        if let Some(idx) = self.peer_indices.remove(peer_id) {
            self.graph.remove_node(idx);
            // Rebuild index map since indices may have changed
            self.rebuild_indices();
        }
    }

    fn rebuild_indices(&mut self) {
        self.peer_indices.clear();
        for idx in self.graph.node_indices() {
            if let Some(&peer_id) = self.graph.node_weight(idx) {
                self.peer_indices.insert(peer_id, idx);
            }
        }
    }
}

impl Default for NetworkGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_peer(n: u8) -> PeerId {
        let bytes = [n; 32];
        let key = libp2p::identity::ed25519::SecretKey::try_from_bytes(bytes.clone()).unwrap();
        let keypair = libp2p::identity::ed25519::Keypair::from(key);
        PeerId::from(libp2p::identity::PublicKey::from(keypair.public()))
    }

    #[test]
    fn test_graph_operations() {
        let mut graph = NetworkGraph::new();

        let peer1 = test_peer(1);
        let peer2 = test_peer(2);
        let peer3 = test_peer(3);

        // Add traffic
        graph.record_traffic(peer1, peer2, TrafficType::ChunkTransfer, 1000);
        graph.record_traffic(peer2, peer1, TrafficType::ChunkRequest, 100);
        graph.record_traffic(peer1, peer3, TrafficType::DhtRouting, 50);

        assert_eq!(graph.peer_count(), 3);
        assert_eq!(graph.edge_count(), 3);
        assert_eq!(graph.total_traffic(), 1150);

        // Check weights
        let outbound1 = graph.outbound_weight(&peer1);
        assert!(outbound1 > 0.0);

        let neighbors = graph.neighbors(&peer1);
        assert_eq!(neighbors.len(), 2);
    }
}
