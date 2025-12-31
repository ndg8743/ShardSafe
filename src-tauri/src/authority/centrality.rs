//! Eigenvector Centrality Module
//!
//! Computes Eigenvector Centrality for the network graph to identify
//! "authority" nodes - peers that are connected to other well-connected peers.
//!
//! The algorithm iteratively computes:
//!   x_{i}^{(k+1)} = (1/λ) * Σ_j A_{ij} * x_{j}^{(k)}
//!
//! Where:
//! - x_i is the centrality score of node i
//! - A_{ij} is the weighted adjacency matrix
//! - λ is the largest eigenvalue (used for normalization)

use libp2p::PeerId;
use std::collections::HashMap;

use super::graph::NetworkGraph;

/// Configuration for centrality computation
#[derive(Debug, Clone)]
pub struct CentralityConfig {
    /// Maximum iterations for power iteration
    pub max_iterations: usize,
    /// Convergence tolerance
    pub tolerance: f64,
    /// Damping factor (like PageRank, prevents sink nodes)
    pub damping: f64,
    /// Whether to use weighted edges
    pub use_weights: bool,
}

impl Default for CentralityConfig {
    fn default() -> Self {
        Self {
            max_iterations: 100,
            tolerance: 1e-6,
            damping: 0.85,
            use_weights: true,
        }
    }
}

/// Authority scores for all nodes
#[derive(Debug, Clone)]
pub struct AuthorityScores {
    scores: HashMap<PeerId, f64>,
    max_score: f64,
    iterations_used: usize,
}

impl AuthorityScores {
    /// Get the authority score for a peer
    pub fn get(&self, peer_id: &PeerId) -> Option<f64> {
        self.scores.get(peer_id).copied()
    }

    /// Get normalized score (0.0 to 1.0)
    pub fn get_normalized(&self, peer_id: &PeerId) -> Option<f64> {
        self.scores.get(peer_id).map(|&s| {
            if self.max_score > 0.0 {
                s / self.max_score
            } else {
                0.0
            }
        })
    }

    /// Get the top N authority nodes
    pub fn top_n(&self, n: usize) -> Vec<(PeerId, f64)> {
        let mut sorted: Vec<_> = self.scores.iter().map(|(p, s)| (*p, *s)).collect();
        sorted.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        sorted.truncate(n);
        sorted
    }

    /// Check if a peer is in the top percentile
    pub fn is_in_percentile(&self, peer_id: &PeerId, percentile: f64) -> bool {
        let Some(&score) = self.scores.get(peer_id) else {
            return false;
        };

        let threshold = self.percentile_threshold(percentile);
        score >= threshold
    }

    /// Get the score threshold for a given percentile
    fn percentile_threshold(&self, percentile: f64) -> f64 {
        let mut scores: Vec<f64> = self.scores.values().copied().collect();
        scores.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        if scores.is_empty() {
            return 0.0;
        }

        let idx = ((1.0 - percentile) * scores.len() as f64) as usize;
        let idx = idx.min(scores.len() - 1);
        scores[idx]
    }

    /// Get number of iterations used for convergence
    pub fn iterations(&self) -> usize {
        self.iterations_used
    }

    /// Get all scores
    pub fn all(&self) -> &HashMap<PeerId, f64> {
        &self.scores
    }

    /// Number of nodes scored
    pub fn len(&self) -> usize {
        self.scores.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.scores.is_empty()
    }
}

/// Compute Eigenvector Centrality using power iteration
pub fn compute_eigenvector_centrality(
    graph: &NetworkGraph,
    config: &CentralityConfig,
) -> AuthorityScores {
    let n = graph.peer_count();

    if n == 0 {
        return AuthorityScores {
            scores: HashMap::new(),
            max_score: 0.0,
            iterations_used: 0,
        };
    }

    // Build adjacency matrix and peer list
    let peers: Vec<PeerId> = graph.peers().copied().collect();
    let peer_to_idx: HashMap<PeerId, usize> = peers.iter().enumerate().map(|(i, p)| (*p, i)).collect();

    // Get weighted adjacency matrix
    let adj_matrix = if config.use_weights {
        graph.weighted_adjacency_matrix()
    } else {
        // Binary matrix
        let inner = graph.inner();
        let mut matrix = vec![vec![0.0; n]; n];
        for edge in inner.edge_references() {
            let from = edge.source().index();
            let to = edge.target().index();
            if from < n && to < n {
                matrix[from][to] = 1.0;
            }
        }
        matrix
    };

    // Normalize columns (make it column-stochastic with damping)
    let mut stochastic = normalize_matrix(&adj_matrix, n);

    // Apply damping factor (teleportation like PageRank)
    let teleport = (1.0 - config.damping) / n as f64;
    for row in stochastic.iter_mut() {
        for val in row.iter_mut() {
            *val = config.damping * (*val) + teleport;
        }
    }

    // Power iteration to find dominant eigenvector
    let mut x: Vec<f64> = vec![1.0 / n as f64; n];
    let mut iterations_used = 0;

    for iteration in 0..config.max_iterations {
        // x' = A * x
        let mut x_new = vec![0.0; n];
        for i in 0..n {
            for j in 0..n {
                x_new[i] += stochastic[j][i] * x[j]; // Note: transpose for eigenvector
            }
        }

        // Normalize
        let norm: f64 = x_new.iter().map(|v| v * v).sum::<f64>().sqrt();
        if norm > 0.0 {
            for v in x_new.iter_mut() {
                *v /= norm;
            }
        }

        // Check convergence
        let diff: f64 = x.iter().zip(x_new.iter()).map(|(a, b)| (a - b).abs()).sum();
        x = x_new;
        iterations_used = iteration + 1;

        if diff < config.tolerance {
            break;
        }
    }

    // Ensure all values are positive (take absolute value)
    let min_val = x.iter().copied().fold(f64::INFINITY, f64::min);
    if min_val < 0.0 {
        for v in x.iter_mut() {
            *v = v.abs();
        }
    }

    // Normalize to [0, 1]
    let max_val = x.iter().copied().fold(0.0, f64::max);
    if max_val > 0.0 {
        for v in x.iter_mut() {
            *v /= max_val;
        }
    }

    // Build result map
    let scores: HashMap<PeerId, f64> = peers.into_iter().zip(x.iter().copied()).collect();
    let max_score = x.iter().copied().fold(0.0, f64::max);

    AuthorityScores {
        scores,
        max_score,
        iterations_used,
    }
}

/// Normalize matrix columns to sum to 1 (with handling for dangling nodes)
fn normalize_matrix(matrix: &[Vec<f64>], n: usize) -> Vec<Vec<f64>> {
    let mut result = vec![vec![0.0; n]; n];

    // Calculate column sums
    let col_sums: Vec<f64> = (0..n)
        .map(|j| (0..n).map(|i| matrix[i][j]).sum())
        .collect();

    // Normalize
    for i in 0..n {
        for j in 0..n {
            if col_sums[j] > 0.0 {
                result[i][j] = matrix[i][j] / col_sums[j];
            } else {
                // Dangling node: distribute evenly
                result[i][j] = 1.0 / n as f64;
            }
        }
    }

    result
}

/// Compute HITS (Hyperlink-Induced Topic Search) authority and hub scores
/// Returns (authorities, hubs) tuples
pub fn compute_hits(
    graph: &NetworkGraph,
    config: &CentralityConfig,
) -> (AuthorityScores, AuthorityScores) {
    let n = graph.peer_count();

    if n == 0 {
        let empty = AuthorityScores {
            scores: HashMap::new(),
            max_score: 0.0,
            iterations_used: 0,
        };
        return (empty.clone(), empty);
    }

    let peers: Vec<PeerId> = graph.peers().copied().collect();
    let adj_matrix = graph.weighted_adjacency_matrix();

    // Initialize
    let mut auth: Vec<f64> = vec![1.0; n];
    let mut hub: Vec<f64> = vec![1.0; n];
    let mut iterations_used = 0;

    for iteration in 0..config.max_iterations {
        // Update authority scores: auth = A^T * hub
        let mut new_auth = vec![0.0; n];
        for i in 0..n {
            for j in 0..n {
                new_auth[i] += adj_matrix[j][i] * hub[j];
            }
        }

        // Update hub scores: hub = A * auth
        let mut new_hub = vec![0.0; n];
        for i in 0..n {
            for j in 0..n {
                new_hub[i] += adj_matrix[i][j] * new_auth[j];
            }
        }

        // Normalize
        let auth_norm: f64 = new_auth.iter().map(|v| v * v).sum::<f64>().sqrt();
        let hub_norm: f64 = new_hub.iter().map(|v| v * v).sum::<f64>().sqrt();

        if auth_norm > 0.0 {
            for v in new_auth.iter_mut() {
                *v /= auth_norm;
            }
        }
        if hub_norm > 0.0 {
            for v in new_hub.iter_mut() {
                *v /= hub_norm;
            }
        }

        // Check convergence
        let auth_diff: f64 = auth.iter().zip(new_auth.iter()).map(|(a, b)| (a - b).abs()).sum();
        let hub_diff: f64 = hub.iter().zip(new_hub.iter()).map(|(a, b)| (a - b).abs()).sum();

        auth = new_auth;
        hub = new_hub;
        iterations_used = iteration + 1;

        if auth_diff < config.tolerance && hub_diff < config.tolerance {
            break;
        }
    }

    // Build result maps
    let auth_scores: HashMap<PeerId, f64> = peers.iter().copied().zip(auth.iter().copied()).collect();
    let hub_scores: HashMap<PeerId, f64> = peers.iter().copied().zip(hub.iter().copied()).collect();

    let auth_max = auth.iter().copied().fold(0.0, f64::max);
    let hub_max = hub.iter().copied().fold(0.0, f64::max);

    (
        AuthorityScores {
            scores: auth_scores,
            max_score: auth_max,
            iterations_used,
        },
        AuthorityScores {
            scores: hub_scores,
            max_score: hub_max,
            iterations_used,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::graph::TrafficType;

    fn test_peer(n: u8) -> PeerId {
        let bytes = [n; 32];
        let key = libp2p::identity::ed25519::SecretKey::try_from_bytes(bytes.clone()).unwrap();
        let keypair = libp2p::identity::ed25519::Keypair::from(key);
        PeerId::from(libp2p::identity::PublicKey::from(keypair.public()))
    }

    #[test]
    fn test_eigenvector_centrality() {
        let mut graph = NetworkGraph::new();

        // Create a star topology: peer1 is the hub
        let center = test_peer(1);
        let p2 = test_peer(2);
        let p3 = test_peer(3);
        let p4 = test_peer(4);
        let p5 = test_peer(5);

        // Center connects to all others
        graph.record_traffic(center, p2, TrafficType::ChunkTransfer, 1000);
        graph.record_traffic(center, p3, TrafficType::ChunkTransfer, 1000);
        graph.record_traffic(center, p4, TrafficType::ChunkTransfer, 1000);
        graph.record_traffic(center, p5, TrafficType::ChunkTransfer, 1000);

        // Others connect back to center
        graph.record_traffic(p2, center, TrafficType::ChunkRequest, 100);
        graph.record_traffic(p3, center, TrafficType::ChunkRequest, 100);
        graph.record_traffic(p4, center, TrafficType::ChunkRequest, 100);
        graph.record_traffic(p5, center, TrafficType::ChunkRequest, 100);

        let config = CentralityConfig::default();
        let scores = compute_eigenvector_centrality(&graph, &config);

        // Center should have highest score
        let center_score = scores.get(&center).unwrap();
        let p2_score = scores.get(&p2).unwrap();

        assert!(center_score > p2_score, "Center should have higher authority");

        let top = scores.top_n(1);
        assert_eq!(top[0].0, center, "Center should be top authority");
    }
}
