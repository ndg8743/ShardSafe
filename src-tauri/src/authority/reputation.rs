//! Reputation System Module
//!
//! Maintains reputation scores for peers based on their behavior history.
//! Combines positive and negative events with time decay to produce
//! a normalized trust score.

use libp2p::PeerId;
use std::collections::HashMap;

/// Configuration for the reputation system
#[derive(Debug, Clone)]
pub struct ReputationConfig {
    /// Initial reputation for new peers
    pub initial_score: i64,
    /// Maximum positive reputation
    pub max_score: i64,
    /// Minimum (most negative) reputation
    pub min_score: i64,
    /// Half-life for reputation decay in seconds
    pub decay_half_life: u64,
    /// Threshold below which peer is considered untrusted
    pub untrusted_threshold: i64,
    /// Threshold above which peer is considered highly trusted
    pub trusted_threshold: i64,
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self {
            initial_score: 50,
            max_score: 1000,
            min_score: -500,
            decay_half_life: 86400, // 24 hours
            untrusted_threshold: 0,
            trusted_threshold: 200,
        }
    }
}

/// Individual reputation event
#[derive(Debug, Clone)]
struct ReputationEvent {
    delta: i64,
    timestamp: u64,
    reason: String,
}

/// Reputation data for a single peer
#[derive(Debug, Clone)]
pub struct PeerReputation {
    /// Raw score (sum of all events)
    raw_score: i64,
    /// List of events
    events: Vec<ReputationEvent>,
    /// First seen timestamp
    first_seen: u64,
    /// Total positive points earned
    total_positive: u64,
    /// Total negative points earned
    total_negative: u64,
    /// Number of interactions
    interaction_count: u64,
}

impl PeerReputation {
    fn new(initial_score: i64) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            raw_score: initial_score,
            events: Vec::new(),
            first_seen: now,
            total_positive: 0,
            total_negative: 0,
            interaction_count: 0,
        }
    }

    fn add_event(&mut self, delta: i64, reason: String, config: &ReputationConfig) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.events.push(ReputationEvent {
            delta,
            timestamp: now,
            reason,
        });

        if delta > 0 {
            self.total_positive += delta as u64;
        } else {
            self.total_negative += (-delta) as u64;
        }

        self.raw_score = (self.raw_score + delta).clamp(config.min_score, config.max_score);
        self.interaction_count += 1;
    }

    /// Calculate time-decayed score
    fn decayed_score(&self, half_life: u64) -> f64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut score = 0.0;

        for event in &self.events {
            let age = now.saturating_sub(event.timestamp);
            let decay = 0.5_f64.powf(age as f64 / half_life as f64);
            score += event.delta as f64 * decay;
        }

        score
    }

    /// Get the account age in seconds
    fn age(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now.saturating_sub(self.first_seen)
    }
}

/// Reputation score result with multiple views
#[derive(Debug, Clone)]
pub struct ReputationScore {
    /// Raw score without decay
    pub raw: i64,
    /// Score with time decay applied
    pub decayed: f64,
    /// Normalized score (0.0 to 1.0)
    pub normalized: f64,
    /// Peer age in seconds
    pub age_secs: u64,
    /// Total interactions
    pub interactions: u64,
    /// Positive/negative ratio
    pub positive_ratio: f64,
}

impl ReputationScore {
    /// Get normalized score
    pub fn normalized(&self) -> f64 {
        self.normalized
    }

    /// Check if peer is trusted
    pub fn is_trusted(&self, threshold: f64) -> bool {
        self.normalized >= threshold
    }
}

/// Reputation system for tracking peer trust
pub struct ReputationSystem {
    config: ReputationConfig,
    peers: HashMap<PeerId, PeerReputation>,
}

impl ReputationSystem {
    /// Create a new reputation system
    pub fn new(config: ReputationConfig) -> Self {
        Self {
            config,
            peers: HashMap::new(),
        }
    }

    /// Get or create reputation for a peer
    fn get_or_create(&mut self, peer_id: PeerId) -> &mut PeerReputation {
        self.peers
            .entry(peer_id)
            .or_insert_with(|| PeerReputation::new(self.config.initial_score))
    }

    /// Record a positive reputation event
    pub fn record_positive(&mut self, peer_id: PeerId, points: i64) {
        self.record_event(peer_id, points.abs(), format!("+{} points", points.abs()));
    }

    /// Record a negative reputation event
    pub fn record_negative(&mut self, peer_id: PeerId, points: i64) {
        self.record_event(peer_id, -points.abs(), format!("-{} points", points.abs()));
    }

    /// Record a reputation event with reason
    pub fn record_event(&mut self, peer_id: PeerId, delta: i64, reason: String) {
        let config = self.config.clone();
        let rep = self.get_or_create(peer_id);
        rep.add_event(delta, reason, &config);
    }

    /// Record chunk served successfully
    pub fn record_chunk_served(&mut self, peer_id: PeerId, bytes: u64) {
        let points = (bytes / 1024).max(1) as i64; // 1 point per KB, minimum 1
        self.record_event(peer_id, points.min(50), "Chunk served".to_string());
    }

    /// Record chunk validation success
    pub fn record_validation_success(&mut self, peer_id: PeerId) {
        self.record_event(peer_id, 20, "Validation success".to_string());
    }

    /// Record chunk validation failure
    pub fn record_validation_failure(&mut self, peer_id: PeerId) {
        self.record_event(peer_id, -50, "Validation failure".to_string());
    }

    /// Record request timeout
    pub fn record_timeout(&mut self, peer_id: PeerId) {
        self.record_event(peer_id, -10, "Request timeout".to_string());
    }

    /// Record connection failure
    pub fn record_connection_failure(&mut self, peer_id: PeerId) {
        self.record_event(peer_id, -5, "Connection failure".to_string());
    }

    /// Get reputation score for a peer
    pub fn get_score(&self, peer_id: &PeerId) -> ReputationScore {
        let Some(rep) = self.peers.get(peer_id) else {
            return ReputationScore {
                raw: self.config.initial_score,
                decayed: self.config.initial_score as f64,
                normalized: 0.5,
                age_secs: 0,
                interactions: 0,
                positive_ratio: 0.5,
            };
        };

        let decayed = rep.decayed_score(self.config.decay_half_life);
        let range = (self.config.max_score - self.config.min_score) as f64;
        let normalized = (decayed - self.config.min_score as f64) / range;

        let positive_ratio = if rep.total_positive + rep.total_negative > 0 {
            rep.total_positive as f64 / (rep.total_positive + rep.total_negative) as f64
        } else {
            0.5
        };

        ReputationScore {
            raw: rep.raw_score,
            decayed,
            normalized: normalized.clamp(0.0, 1.0),
            age_secs: rep.age(),
            interactions: rep.interaction_count,
            positive_ratio,
        }
    }

    /// Check if peer is trusted
    pub fn is_trusted(&self, peer_id: &PeerId) -> bool {
        let score = self.get_score(peer_id);
        score.raw >= self.config.trusted_threshold
    }

    /// Check if peer is untrusted
    pub fn is_untrusted(&self, peer_id: &PeerId) -> bool {
        let score = self.get_score(peer_id);
        score.raw < self.config.untrusted_threshold
    }

    /// Get all peers sorted by reputation
    pub fn ranked_peers(&self) -> Vec<(PeerId, ReputationScore)> {
        let mut result: Vec<_> = self.peers
            .keys()
            .map(|p| (*p, self.get_score(p)))
            .collect();

        result.sort_by(|a, b| {
            b.1.decayed
                .partial_cmp(&a.1.decayed)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        result
    }

    /// Get trusted peers (above threshold)
    pub fn trusted_peers(&self) -> Vec<PeerId> {
        self.peers
            .keys()
            .filter(|p| self.is_trusted(p))
            .copied()
            .collect()
    }

    /// Get untrusted peers (below threshold)
    pub fn untrusted_peers(&self) -> Vec<PeerId> {
        self.peers
            .keys()
            .filter(|p| self.is_untrusted(p))
            .copied()
            .collect()
    }

    /// Calculate average reputation score
    pub fn average_score(&self) -> f64 {
        if self.peers.is_empty() {
            return 0.5;
        }

        let sum: f64 = self.peers
            .keys()
            .map(|p| self.get_score(p).normalized)
            .sum();

        sum / self.peers.len() as f64
    }

    /// Prune old events to save memory
    pub fn prune_old_events(&mut self, max_age_secs: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let cutoff = now.saturating_sub(max_age_secs);

        for rep in self.peers.values_mut() {
            rep.events.retain(|e| e.timestamp >= cutoff);
        }
    }

    /// Remove peer from reputation system
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.peers.remove(peer_id);
    }

    /// Get number of tracked peers
    pub fn peer_count(&self) -> usize {
        self.peers.len()
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
    fn test_reputation_tracking() {
        let config = ReputationConfig::default();
        let mut system = ReputationSystem::new(config);

        let peer = test_peer(1);

        // Initial score
        let score = system.get_score(&peer);
        assert_eq!(score.raw, 50); // Default initial

        // Add positive event
        system.record_positive(peer, 20);
        let score = system.get_score(&peer);
        assert_eq!(score.raw, 70);

        // Add negative event
        system.record_negative(peer, 30);
        let score = system.get_score(&peer);
        assert_eq!(score.raw, 40);
    }

    #[test]
    fn test_trust_thresholds() {
        let config = ReputationConfig {
            initial_score: 50,
            trusted_threshold: 100,
            untrusted_threshold: 0,
            ..Default::default()
        };
        let mut system = ReputationSystem::new(config);

        let peer = test_peer(2);

        // Start neutral
        assert!(!system.is_trusted(&peer));
        assert!(!system.is_untrusted(&peer));

        // Become trusted
        system.record_positive(peer, 60);
        assert!(system.is_trusted(&peer));

        // Become untrusted
        system.record_negative(peer, 200);
        assert!(system.is_untrusted(&peer));
    }

    #[test]
    fn test_ranking() {
        let config = ReputationConfig::default();
        let mut system = ReputationSystem::new(config);

        let peer1 = test_peer(1);
        let peer2 = test_peer(2);
        let peer3 = test_peer(3);

        system.record_positive(peer1, 100);
        system.record_positive(peer2, 50);
        system.record_positive(peer3, 200);

        let ranked = system.ranked_peers();
        assert_eq!(ranked[0].0, peer3); // Highest score
        assert_eq!(ranked[1].0, peer1);
        assert_eq!(ranked[2].0, peer2); // Lowest score
    }
}
