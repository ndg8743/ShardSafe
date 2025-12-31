//! Network Metrics Module
//!
//! Provides analytics and metrics for the P2P network graph,
//! including clustering coefficient, density, diameter, and more.

use super::graph::NetworkGraph;
use libp2p::PeerId;
use petgraph::algo::{connected_components, has_path_connecting};
use petgraph::Direction;
use std::collections::HashMap;

/// Comprehensive network metrics
#[derive(Debug, Clone)]
pub struct NetworkMetrics {
    /// Number of nodes
    pub node_count: usize,
    /// Number of edges
    pub edge_count: usize,
    /// Graph density (edges / possible edges)
    pub density: f64,
    /// Number of connected components
    pub connected_components: usize,
    /// Average degree (edges per node)
    pub avg_degree: f64,
    /// Maximum degree
    pub max_degree: usize,
    /// Global clustering coefficient
    pub clustering_coefficient: f64,
    /// Reciprocity (fraction of mutual edges)
    pub reciprocity: f64,
    /// Total traffic bytes
    pub total_traffic: u64,
    /// Average traffic per edge
    pub avg_traffic_per_edge: f64,
}

/// Compute comprehensive network metrics
pub fn compute_network_metrics(graph: &NetworkGraph) -> NetworkMetrics {
    let n = graph.peer_count();
    let e = graph.edge_count();

    if n == 0 {
        return NetworkMetrics {
            node_count: 0,
            edge_count: 0,
            density: 0.0,
            connected_components: 0,
            avg_degree: 0.0,
            max_degree: 0,
            clustering_coefficient: 0.0,
            reciprocity: 0.0,
            total_traffic: 0,
            avg_traffic_per_edge: 0.0,
        };
    }

    // Density: e / (n * (n-1)) for directed graph
    let possible_edges = n * (n.saturating_sub(1));
    let density = if possible_edges > 0 {
        e as f64 / possible_edges as f64
    } else {
        0.0
    };

    // Connected components (treating as undirected)
    let inner = graph.inner();
    let components = connected_components(inner);

    // Degrees
    let degrees: Vec<usize> = (0..inner.node_count())
        .map(|i| {
            let idx = petgraph::graph::NodeIndex::new(i);
            inner.edges_directed(idx, Direction::Outgoing).count()
                + inner.edges_directed(idx, Direction::Incoming).count()
        })
        .collect();

    let avg_degree = if n > 0 {
        degrees.iter().sum::<usize>() as f64 / n as f64
    } else {
        0.0
    };

    let max_degree = degrees.into_iter().max().unwrap_or(0);

    // Clustering coefficient (local average)
    let clustering = compute_clustering_coefficient(graph);

    // Reciprocity
    let reciprocity = compute_reciprocity(graph);

    // Traffic stats
    let total_traffic = graph.total_traffic();
    let avg_traffic = if e > 0 {
        total_traffic as f64 / e as f64
    } else {
        0.0
    };

    NetworkMetrics {
        node_count: n,
        edge_count: e,
        density,
        connected_components: components,
        avg_degree,
        max_degree,
        clustering_coefficient: clustering,
        reciprocity,
        total_traffic,
        avg_traffic_per_edge: avg_traffic,
    }
}

/// Compute global clustering coefficient
fn compute_clustering_coefficient(graph: &NetworkGraph) -> f64 {
    let inner = graph.inner();
    let n = inner.node_count();

    if n < 3 {
        return 0.0;
    }

    let mut total_coefficient = 0.0;
    let mut nodes_with_neighbors = 0;

    for node_idx in inner.node_indices() {
        // Get neighbors (both directions for directed graph)
        let neighbors: Vec<_> = inner
            .neighbors_undirected(node_idx)
            .collect();

        let k = neighbors.len();
        if k < 2 {
            continue;
        }

        // Count edges between neighbors
        let mut triangles = 0;
        for i in 0..neighbors.len() {
            for j in (i + 1)..neighbors.len() {
                // Check if neighbors[i] and neighbors[j] are connected
                if inner.find_edge(neighbors[i], neighbors[j]).is_some()
                    || inner.find_edge(neighbors[j], neighbors[i]).is_some()
                {
                    triangles += 1;
                }
            }
        }

        // Local clustering coefficient
        let possible_triangles = k * (k - 1) / 2;
        if possible_triangles > 0 {
            total_coefficient += triangles as f64 / possible_triangles as f64;
            nodes_with_neighbors += 1;
        }
    }

    if nodes_with_neighbors > 0 {
        total_coefficient / nodes_with_neighbors as f64
    } else {
        0.0
    }
}

/// Compute reciprocity (fraction of edges that are mutual)
fn compute_reciprocity(graph: &NetworkGraph) -> f64 {
    let inner = graph.inner();
    let mut mutual = 0;
    let mut total = 0;

    for edge in inner.edge_references() {
        total += 1;
        let source = edge.source();
        let target = edge.target();

        // Check if reverse edge exists
        if inner.find_edge(target, source).is_some() {
            mutual += 1;
        }
    }

    if total > 0 {
        mutual as f64 / total as f64
    } else {
        0.0
    }
}

/// Per-node metrics
#[derive(Debug, Clone)]
pub struct NodeMetrics {
    pub peer_id: PeerId,
    pub in_degree: usize,
    pub out_degree: usize,
    pub total_degree: usize,
    pub in_weight: f64,
    pub out_weight: f64,
    pub local_clustering: f64,
    pub betweenness_estimate: f64,
}

/// Compute metrics for a specific node
pub fn compute_node_metrics(graph: &NetworkGraph, peer_id: &PeerId) -> Option<NodeMetrics> {
    let idx = graph.peer_index(peer_id)?;
    let inner = graph.inner();

    let in_degree = inner.edges_directed(idx, Direction::Incoming).count();
    let out_degree = inner.edges_directed(idx, Direction::Outgoing).count();

    let in_weight = graph.inbound_weight(peer_id);
    let out_weight = graph.outbound_weight(peer_id);

    // Local clustering
    let neighbors: Vec<_> = inner.neighbors_undirected(idx).collect();
    let local_clustering = if neighbors.len() >= 2 {
        let mut triangles = 0;
        for i in 0..neighbors.len() {
            for j in (i + 1)..neighbors.len() {
                if inner.find_edge(neighbors[i], neighbors[j]).is_some()
                    || inner.find_edge(neighbors[j], neighbors[i]).is_some()
                {
                    triangles += 1;
                }
            }
        }
        let possible = neighbors.len() * (neighbors.len() - 1) / 2;
        if possible > 0 {
            triangles as f64 / possible as f64
        } else {
            0.0
        }
    } else {
        0.0
    };

    // Betweenness estimate (simplified: fraction of pairs this node could bridge)
    let betweenness = estimate_betweenness(graph, idx);

    Some(NodeMetrics {
        peer_id: *peer_id,
        in_degree,
        out_degree,
        total_degree: in_degree + out_degree,
        in_weight,
        out_weight,
        local_clustering,
        betweenness_estimate: betweenness,
    })
}

/// Estimate betweenness centrality (simplified algorithm)
fn estimate_betweenness(graph: &NetworkGraph, node_idx: petgraph::graph::NodeIndex) -> f64 {
    let inner = graph.inner();
    let n = inner.node_count();

    if n < 3 {
        return 0.0;
    }

    let mut paths_through = 0;
    let mut total_pairs = 0;

    // Sample pairs to check (for performance)
    let sample_size = n.min(50);

    for i in inner.node_indices().take(sample_size) {
        if i == node_idx {
            continue;
        }

        for j in inner.node_indices().skip(i.index() + 1).take(sample_size) {
            if j == node_idx {
                continue;
            }

            total_pairs += 1;

            // Check if path through our node exists
            let has_path_through = has_path_connecting(inner, i, node_idx, None)
                && has_path_connecting(inner, node_idx, j, None);

            // Check if direct path exists (without our node)
            let has_direct = has_path_connecting(inner, i, j, None);

            // If path through our node exists but no direct (or shorter), increment
            if has_path_through && !has_direct {
                paths_through += 1;
            }
        }
    }

    if total_pairs > 0 {
        paths_through as f64 / total_pairs as f64
    } else {
        0.0
    }
}

/// Degree distribution of the network
#[derive(Debug, Clone)]
pub struct DegreeDistribution {
    pub histogram: HashMap<usize, usize>,
    pub min_degree: usize,
    pub max_degree: usize,
    pub median_degree: usize,
    pub mode_degree: usize,
}

/// Compute degree distribution
pub fn compute_degree_distribution(graph: &NetworkGraph) -> DegreeDistribution {
    let inner = graph.inner();
    let mut degrees: Vec<usize> = Vec::new();
    let mut histogram: HashMap<usize, usize> = HashMap::new();

    for node_idx in inner.node_indices() {
        let degree = inner.edges_directed(node_idx, Direction::Outgoing).count()
            + inner.edges_directed(node_idx, Direction::Incoming).count();
        degrees.push(degree);
        *histogram.entry(degree).or_insert(0) += 1;
    }

    if degrees.is_empty() {
        return DegreeDistribution {
            histogram: HashMap::new(),
            min_degree: 0,
            max_degree: 0,
            median_degree: 0,
            mode_degree: 0,
        };
    }

    degrees.sort();

    let min_degree = *degrees.first().unwrap();
    let max_degree = *degrees.last().unwrap();
    let median_degree = degrees[degrees.len() / 2];
    let mode_degree = histogram
        .iter()
        .max_by_key(|(_, count)| *count)
        .map(|(degree, _)| *degree)
        .unwrap_or(0);

    DegreeDistribution {
        histogram,
        min_degree,
        max_degree,
        median_degree,
        mode_degree,
    }
}

/// Traffic analysis results
#[derive(Debug, Clone)]
pub struct TrafficAnalysis {
    pub total_bytes: u64,
    pub avg_bytes_per_edge: f64,
    pub max_edge_bytes: u64,
    pub top_talkers: Vec<(PeerId, u64)>,
    pub busiest_edges: Vec<(PeerId, PeerId, u64)>,
}

/// Analyze traffic patterns
pub fn analyze_traffic(graph: &NetworkGraph, top_n: usize) -> TrafficAnalysis {
    let inner = graph.inner();

    let mut node_traffic: HashMap<PeerId, u64> = HashMap::new();
    let mut edge_traffic: Vec<(PeerId, PeerId, u64)> = Vec::new();
    let mut total_bytes = 0u64;
    let mut max_edge_bytes = 0u64;

    for edge in inner.edge_references() {
        let from = *inner.node_weight(edge.source()).unwrap();
        let to = *inner.node_weight(edge.target()).unwrap();
        let bytes = edge.weight().bytes;

        total_bytes += bytes;
        max_edge_bytes = max_edge_bytes.max(bytes);

        *node_traffic.entry(from).or_insert(0) += bytes;
        edge_traffic.push((from, to, bytes));
    }

    let edge_count = graph.edge_count();
    let avg_bytes = if edge_count > 0 {
        total_bytes as f64 / edge_count as f64
    } else {
        0.0
    };

    // Top talkers
    let mut top_talkers: Vec<_> = node_traffic.into_iter().collect();
    top_talkers.sort_by(|a, b| b.1.cmp(&a.1));
    top_talkers.truncate(top_n);

    // Busiest edges
    edge_traffic.sort_by(|a, b| b.2.cmp(&a.2));
    edge_traffic.truncate(top_n);

    TrafficAnalysis {
        total_bytes,
        avg_bytes_per_edge: avg_bytes,
        max_edge_bytes,
        top_talkers,
        busiest_edges: edge_traffic,
    }
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
    fn test_network_metrics() {
        let mut graph = NetworkGraph::new();

        // Create a small network
        let p1 = test_peer(1);
        let p2 = test_peer(2);
        let p3 = test_peer(3);

        graph.record_traffic(p1, p2, TrafficType::ChunkTransfer, 1000);
        graph.record_traffic(p2, p1, TrafficType::ChunkRequest, 100);
        graph.record_traffic(p2, p3, TrafficType::ChunkTransfer, 500);
        graph.record_traffic(p3, p1, TrafficType::DhtRouting, 50);

        let metrics = compute_network_metrics(&graph);

        assert_eq!(metrics.node_count, 3);
        assert_eq!(metrics.edge_count, 4);
        assert!(metrics.density > 0.0);
        assert!(metrics.reciprocity > 0.0);
    }

    #[test]
    fn test_degree_distribution() {
        let mut graph = NetworkGraph::new();

        for i in 1..=5 {
            for j in 1..=5 {
                if i != j {
                    graph.record_traffic(
                        test_peer(i),
                        test_peer(j),
                        TrafficType::Ping,
                        10,
                    );
                }
            }
        }

        let dist = compute_degree_distribution(&graph);

        assert!(dist.max_degree > 0);
        assert!(!dist.histogram.is_empty());
    }
}
