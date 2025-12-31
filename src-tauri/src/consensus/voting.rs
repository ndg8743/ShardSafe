//! Voting Module
//!
//! Implements weighted voting rounds for chunk validation consensus.

use super::validation::ChunkValidation;
use super::ConsensusError;
use crate::crypto::ChunkId;
use libp2p::PeerId;
use std::collections::HashMap;

/// Configuration for consensus voting
#[derive(Debug, Clone)]
pub struct ConsensusConfig {
    /// Minimum number of votes to finalize
    pub min_votes: usize,
    /// Minimum total authority weight to finalize
    pub min_total_weight: f64,
    /// Threshold for acceptance (weighted score above this = accepted)
    pub acceptance_threshold: f64,
    /// Threshold for rejection (weighted score below this = rejected)
    pub rejection_threshold: f64,
    /// Minimum authority score to participate in voting
    pub min_authority_to_vote: f64,
    /// Maximum time for a voting round (seconds)
    pub round_timeout_secs: u64,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            min_votes: 3,
            min_total_weight: 1.0,
            acceptance_threshold: 0.6,
            rejection_threshold: 0.4,
            min_authority_to_vote: 0.1,
            round_timeout_secs: 300, // 5 minutes
        }
    }
}

/// A vote in a consensus round
#[derive(Debug, Clone)]
pub struct ConsensusVote {
    /// The peer submitting the vote
    pub voter: PeerId,
    /// The validation result
    pub validation: ChunkValidation,
    /// Authority weight of the voter
    pub authority_weight: f64,
    /// Timestamp of the vote
    pub timestamp: u64,
}

impl ConsensusVote {
    /// Get the effective weight of this vote
    pub fn effective_weight(&self) -> f64 {
        let method_weight = self.validation.result.is_valid as u8 as f64;
        let confidence = self.validation.confidence;
        let method_reliability = self.validation.method.reliability_weight();

        self.authority_weight * confidence * method_reliability * method_weight
    }

    /// Get the negative weight (for invalid votes)
    pub fn negative_weight(&self) -> f64 {
        if self.validation.result.is_valid {
            0.0
        } else {
            let confidence = self.validation.confidence;
            let method_reliability = self.validation.method.reliability_weight();
            self.authority_weight * confidence * method_reliability
        }
    }
}

/// A voting round for a specific chunk
#[derive(Debug)]
pub struct VotingRound {
    chunk_id: ChunkId,
    votes: HashMap<PeerId, ConsensusVote>,
    started_at: u64,
    config: ConsensusConfig,
}

impl VotingRound {
    /// Create a new voting round
    pub fn new(chunk_id: ChunkId, config: ConsensusConfig) -> Self {
        Self {
            chunk_id,
            votes: HashMap::new(),
            started_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            config,
        }
    }

    /// Add a vote to the round
    pub fn add_vote(&mut self, vote: ConsensusVote) -> Result<(), ConsensusError> {
        // Check if already voted
        if self.votes.contains_key(&vote.voter) {
            return Err(ConsensusError::AlreadyVoted(vote.voter));
        }

        // Check if round expired
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if now.saturating_sub(self.started_at) > self.config.round_timeout_secs {
            return Err(ConsensusError::RoundExpired(self.chunk_id.clone()));
        }

        self.votes.insert(vote.voter, vote);
        Ok(())
    }

    /// Get vote count
    pub fn vote_count(&self) -> usize {
        self.votes.len()
    }

    /// Get total authority weight
    pub fn total_weight(&self) -> f64 {
        self.votes.values().map(|v| v.authority_weight).sum()
    }

    /// Get when the round started
    pub fn started_at(&self) -> u64 {
        self.started_at
    }

    /// Check if the round can be finalized
    pub fn can_finalize(&self, config: &ConsensusConfig) -> bool {
        // Need minimum votes
        if self.votes.len() < config.min_votes {
            return false;
        }

        // Need minimum weight
        if self.total_weight() < config.min_total_weight {
            return false;
        }

        // Check timeout
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Can finalize if criteria met OR if timed out
        true || now.saturating_sub(self.started_at) > config.round_timeout_secs
    }

    /// Calculate the weighted validation score
    fn calculate_weighted_score(&self) -> f64 {
        let positive_weight: f64 = self.votes
            .values()
            .map(|v| v.effective_weight())
            .sum();

        let negative_weight: f64 = self.votes
            .values()
            .map(|v| v.negative_weight())
            .sum();

        let total = positive_weight + negative_weight;
        if total == 0.0 {
            0.5 // Neutral if no weights
        } else {
            positive_weight / total
        }
    }

    /// Finalize the voting round
    pub fn finalize(&self, config: &ConsensusConfig) -> ConsensusResult {
        let weighted_score = self.calculate_weighted_score();
        let vote_count = self.votes.len();
        let total_weight = self.total_weight();

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Collect voter list
        let voters: Vec<PeerId> = self.votes.keys().copied().collect();

        if weighted_score >= config.acceptance_threshold {
            ConsensusResult::Accepted {
                chunk_id: self.chunk_id.clone(),
                weighted_score,
                vote_count,
                total_weight,
                voters,
                timestamp,
            }
        } else if weighted_score <= config.rejection_threshold {
            ConsensusResult::Rejected {
                chunk_id: self.chunk_id.clone(),
                weighted_score,
                vote_count,
                total_weight,
                voters,
                timestamp,
            }
        } else {
            ConsensusResult::Inconclusive {
                chunk_id: self.chunk_id.clone(),
                weighted_score,
                vote_count,
                total_weight,
                voters,
                timestamp,
            }
        }
    }

    /// Get votes for analysis
    pub fn votes(&self) -> &HashMap<PeerId, ConsensusVote> {
        &self.votes
    }
}

/// Result of a completed consensus round
#[derive(Debug, Clone)]
pub enum ConsensusResult {
    /// Chunk was accepted as valid
    Accepted {
        chunk_id: ChunkId,
        weighted_score: f64,
        vote_count: usize,
        total_weight: f64,
        voters: Vec<PeerId>,
        timestamp: u64,
    },
    /// Chunk was rejected as invalid
    Rejected {
        chunk_id: ChunkId,
        weighted_score: f64,
        vote_count: usize,
        total_weight: f64,
        voters: Vec<PeerId>,
        timestamp: u64,
    },
    /// Voting was inconclusive
    Inconclusive {
        chunk_id: ChunkId,
        weighted_score: f64,
        vote_count: usize,
        total_weight: f64,
        voters: Vec<PeerId>,
        timestamp: u64,
    },
}

impl ConsensusResult {
    /// Check if the result is accepted
    pub fn is_accepted(&self) -> bool {
        matches!(self, ConsensusResult::Accepted { .. })
    }

    /// Check if the result is rejected
    pub fn is_rejected(&self) -> bool {
        matches!(self, ConsensusResult::Rejected { .. })
    }

    /// Get the weighted score
    pub fn weighted_score(&self) -> f64 {
        match self {
            ConsensusResult::Accepted { weighted_score, .. } => *weighted_score,
            ConsensusResult::Rejected { weighted_score, .. } => *weighted_score,
            ConsensusResult::Inconclusive { weighted_score, .. } => *weighted_score,
        }
    }

    /// Get the chunk ID
    pub fn chunk_id(&self) -> &ChunkId {
        match self {
            ConsensusResult::Accepted { chunk_id, .. } => chunk_id,
            ConsensusResult::Rejected { chunk_id, .. } => chunk_id,
            ConsensusResult::Inconclusive { chunk_id, .. } => chunk_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::validation::ChunkValidation;

    fn test_peer(n: u8) -> PeerId {
        let bytes = [n; 32];
        let key = libp2p::identity::ed25519::SecretKey::try_from_bytes(bytes.clone()).unwrap();
        let keypair = libp2p::identity::ed25519::Keypair::from(key);
        PeerId::from(libp2p::identity::PublicKey::from(keypair.public()))
    }

    fn test_chunk_id() -> ChunkId {
        ChunkId::from_data(&[1, 2, 3, 4])
    }

    #[test]
    fn test_voting_round() {
        let chunk_id = test_chunk_id();
        let config = ConsensusConfig::default();
        let mut round = VotingRound::new(chunk_id.clone(), config.clone());

        // Add votes
        for i in 0..3 {
            let peer = test_peer(i);
            let vote = ConsensusVote {
                voter: peer,
                validation: ChunkValidation::valid(chunk_id.clone()),
                authority_weight: 0.5,
                timestamp: 0,
            };
            round.add_vote(vote).unwrap();
        }

        assert_eq!(round.vote_count(), 3);
        assert!(round.can_finalize(&config));

        let result = round.finalize(&config);
        assert!(result.is_accepted());
    }

    #[test]
    fn test_rejection() {
        let chunk_id = test_chunk_id();
        let config = ConsensusConfig::default();
        let mut round = VotingRound::new(chunk_id.clone(), config.clone());

        // Add invalid votes
        for i in 0..3 {
            let peer = test_peer(i);
            let vote = ConsensusVote {
                voter: peer,
                validation: ChunkValidation::invalid(chunk_id.clone(), "Bad".to_string()),
                authority_weight: 0.5,
                timestamp: 0,
            };
            round.add_vote(vote).unwrap();
        }

        let result = round.finalize(&config);
        assert!(result.is_rejected());
    }

    #[test]
    fn test_duplicate_vote() {
        let chunk_id = test_chunk_id();
        let config = ConsensusConfig::default();
        let mut round = VotingRound::new(chunk_id.clone(), config);

        let peer = test_peer(1);
        let vote1 = ConsensusVote {
            voter: peer,
            validation: ChunkValidation::valid(chunk_id.clone()),
            authority_weight: 0.5,
            timestamp: 0,
        };
        let vote2 = ConsensusVote {
            voter: peer,
            validation: ChunkValidation::valid(chunk_id.clone()),
            authority_weight: 0.5,
            timestamp: 0,
        };

        assert!(round.add_vote(vote1).is_ok());
        assert!(matches!(round.add_vote(vote2), Err(ConsensusError::AlreadyVoted(_))));
    }
}
