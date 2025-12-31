//! Consensus Module
//!
//! Implements authority-weighted consensus for distributed chunk validation.
//! Uses Eigenvector Centrality scores to weight votes from peers.

mod validation;
mod voting;

pub use validation::{ValidationResult, ChunkValidation, ValidationStatus};
pub use voting::{ConsensusVote, VotingRound, ConsensusResult, ConsensusConfig};

use crate::authority::AuthoritySystem;
use crate::crypto::ChunkId;
use libp2p::PeerId;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Authority-weighted consensus system
pub struct ConsensusSystem {
    authority: Arc<AuthoritySystem>,
    config: ConsensusConfig,
    active_rounds: Arc<RwLock<HashMap<ChunkId, VotingRound>>>,
    completed_validations: Arc<RwLock<HashMap<ChunkId, ConsensusResult>>>,
}

impl ConsensusSystem {
    /// Create a new consensus system
    pub fn new(authority: Arc<AuthoritySystem>, config: ConsensusConfig) -> Self {
        Self {
            authority,
            config,
            active_rounds: Arc::new(RwLock::new(HashMap::new())),
            completed_validations: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Start a validation round for a chunk
    pub async fn start_validation(&self, chunk_id: ChunkId) -> bool {
        let mut rounds = self.active_rounds.write().await;

        if rounds.contains_key(&chunk_id) {
            debug!("Validation already in progress for chunk {}", chunk_id);
            return false;
        }

        let round = VotingRound::new(chunk_id.clone(), self.config.clone());
        rounds.insert(chunk_id.clone(), round);
        info!("Started validation round for chunk {}", chunk_id);
        true
    }

    /// Submit a vote for a chunk validation
    pub async fn submit_vote(
        &self,
        chunk_id: &ChunkId,
        voter: PeerId,
        validation: ChunkValidation,
    ) -> Result<(), ConsensusError> {
        // Get authority score for the voter
        let authority_score = self.authority.get_combined_score(&voter).await;

        // Check minimum authority threshold
        if authority_score < self.config.min_authority_to_vote {
            return Err(ConsensusError::InsufficientAuthority {
                peer: voter,
                score: authority_score,
                required: self.config.min_authority_to_vote,
            });
        }

        let vote = ConsensusVote {
            voter,
            validation,
            authority_weight: authority_score,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let mut rounds = self.active_rounds.write().await;
        let round = rounds
            .get_mut(chunk_id)
            .ok_or(ConsensusError::NoActiveRound(chunk_id.clone()))?;

        round.add_vote(vote)?;

        // Check if round can be finalized
        if round.can_finalize(&self.config) {
            let result = round.finalize(&self.config);
            let chunk_id = chunk_id.clone();

            drop(rounds);

            self.finalize_round(chunk_id, result).await;
        }

        Ok(())
    }

    /// Finalize a validation round
    async fn finalize_round(&self, chunk_id: ChunkId, result: ConsensusResult) {
        // Move from active to completed
        {
            let mut rounds = self.active_rounds.write().await;
            rounds.remove(&chunk_id);
        }

        {
            let mut completed = self.completed_validations.write().await;
            completed.insert(chunk_id.clone(), result.clone());
        }

        match &result {
            ConsensusResult::Accepted { weighted_score, .. } => {
                info!("Chunk {} ACCEPTED with score {:.3}", chunk_id, weighted_score);
            }
            ConsensusResult::Rejected { weighted_score, .. } => {
                warn!("Chunk {} REJECTED with score {:.3}", chunk_id, weighted_score);
            }
            ConsensusResult::Inconclusive { .. } => {
                warn!("Chunk {} validation INCONCLUSIVE", chunk_id);
            }
        }
    }

    /// Get validation result for a chunk
    pub async fn get_validation_result(&self, chunk_id: &ChunkId) -> Option<ConsensusResult> {
        let completed = self.completed_validations.read().await;
        completed.get(chunk_id).cloned()
    }

    /// Check if chunk is validated and accepted
    pub async fn is_chunk_valid(&self, chunk_id: &ChunkId) -> Option<bool> {
        let completed = self.completed_validations.read().await;
        completed.get(chunk_id).map(|r| matches!(r, ConsensusResult::Accepted { .. }))
    }

    /// Get active round status
    pub async fn get_round_status(&self, chunk_id: &ChunkId) -> Option<RoundStatus> {
        let rounds = self.active_rounds.read().await;
        rounds.get(chunk_id).map(|r| RoundStatus {
            chunk_id: chunk_id.clone(),
            vote_count: r.vote_count(),
            total_weight: r.total_weight(),
            started_at: r.started_at(),
            can_finalize: r.can_finalize(&self.config),
        })
    }

    /// Cancel a validation round
    pub async fn cancel_round(&self, chunk_id: &ChunkId) -> bool {
        let mut rounds = self.active_rounds.write().await;
        rounds.remove(chunk_id).is_some()
    }

    /// Prune old completed validations
    pub async fn prune_old_validations(&self, max_age_secs: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut completed = self.completed_validations.write().await;
        completed.retain(|_, result| {
            let timestamp = match result {
                ConsensusResult::Accepted { timestamp, .. } => *timestamp,
                ConsensusResult::Rejected { timestamp, .. } => *timestamp,
                ConsensusResult::Inconclusive { timestamp, .. } => *timestamp,
            };
            now.saturating_sub(timestamp) < max_age_secs
        });
    }

    /// Get statistics about the consensus system
    pub async fn stats(&self) -> ConsensusStats {
        let rounds = self.active_rounds.read().await;
        let completed = self.completed_validations.read().await;

        let accepted = completed
            .values()
            .filter(|r| matches!(r, ConsensusResult::Accepted { .. }))
            .count();
        let rejected = completed
            .values()
            .filter(|r| matches!(r, ConsensusResult::Rejected { .. }))
            .count();
        let inconclusive = completed
            .values()
            .filter(|r| matches!(r, ConsensusResult::Inconclusive { .. }))
            .count();

        ConsensusStats {
            active_rounds: rounds.len(),
            completed_validations: completed.len(),
            accepted,
            rejected,
            inconclusive,
        }
    }
}

/// Status of an active voting round
#[derive(Debug, Clone)]
pub struct RoundStatus {
    pub chunk_id: ChunkId,
    pub vote_count: usize,
    pub total_weight: f64,
    pub started_at: u64,
    pub can_finalize: bool,
}

/// Statistics about the consensus system
#[derive(Debug, Clone)]
pub struct ConsensusStats {
    pub active_rounds: usize,
    pub completed_validations: usize,
    pub accepted: usize,
    pub rejected: usize,
    pub inconclusive: usize,
}

/// Errors that can occur during consensus
#[derive(Debug, Clone)]
pub enum ConsensusError {
    NoActiveRound(ChunkId),
    InsufficientAuthority {
        peer: PeerId,
        score: f64,
        required: f64,
    },
    AlreadyVoted(PeerId),
    RoundExpired(ChunkId),
}

impl std::fmt::Display for ConsensusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConsensusError::NoActiveRound(id) => write!(f, "No active round for chunk {}", id),
            ConsensusError::InsufficientAuthority { peer, score, required } => {
                write!(f, "Peer {} has insufficient authority ({:.3} < {:.3})", peer, score, required)
            }
            ConsensusError::AlreadyVoted(peer) => write!(f, "Peer {} has already voted", peer),
            ConsensusError::RoundExpired(id) => write!(f, "Voting round for chunk {} has expired", id),
        }
    }
}

impl std::error::Error for ConsensusError {}
