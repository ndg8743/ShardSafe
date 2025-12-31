//! Peer State Machine Module
//!
//! Tracks peer behavior through a finite state machine, enabling
//! behavioral analysis and trust decisions based on state history.
//!
//! State transitions are triggered by network events and drive
//! reputation updates.

use libp2p::PeerId;
use std::collections::VecDeque;

/// Possible states for a peer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerState {
    /// Peer just discovered, no interaction yet
    Unknown,
    /// Connection established, identifying
    Connecting,
    /// Fully connected and responsive
    Connected,
    /// Actively serving chunks
    Serving,
    /// Actively requesting chunks
    Requesting,
    /// Temporary connection issues
    Degraded,
    /// Multiple failures, potentially malicious
    Suspect,
    /// Confirmed bad behavior
    Banned,
    /// Disconnected normally
    Disconnected,
    /// Idle but available
    Idle,
}

impl PeerState {
    /// Check if the peer is in an active/usable state
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            PeerState::Connected | PeerState::Serving | PeerState::Requesting | PeerState::Idle
        )
    }

    /// Check if the peer should be avoided
    pub fn is_problematic(&self) -> bool {
        matches!(self, PeerState::Suspect | PeerState::Banned)
    }

    /// Get the trust factor for this state (0.0 to 1.0)
    pub fn trust_factor(&self) -> f64 {
        match self {
            PeerState::Serving => 1.0,
            PeerState::Connected => 0.9,
            PeerState::Requesting => 0.85,
            PeerState::Idle => 0.8,
            PeerState::Connecting => 0.5,
            PeerState::Unknown => 0.3,
            PeerState::Degraded => 0.2,
            PeerState::Disconnected => 0.1,
            PeerState::Suspect => 0.05,
            PeerState::Banned => 0.0,
        }
    }
}

/// State transitions triggered by events
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateTransition {
    /// Connection initiated
    Connect,
    /// Connection fully established
    Connected,
    /// Peer disconnected
    Disconnect,
    /// Peer served a chunk successfully
    ServeChunk,
    /// Peer requested a chunk
    RequestChunk,
    /// Request failed or was denied
    FailRequest,
    /// Request timed out
    Timeout,
    /// Chunk validation succeeded
    ValidateSuccess,
    /// Chunk validation failed (data corruption/manipulation)
    ValidateFail,
    /// Peer became idle (no activity)
    GoIdle,
    /// Peer recovered from degraded state
    Recover,
    /// Admin action to ban
    Ban,
    /// Admin action to unban
    Unban,
}

/// Record of a state transition
#[derive(Debug, Clone)]
pub struct TransitionRecord {
    pub from: PeerState,
    pub to: PeerState,
    pub trigger: StateTransition,
    pub timestamp: u64,
}

/// State machine for tracking peer behavior
pub struct PeerStateMachine {
    peer_id: PeerId,
    current_state: PeerState,
    history: VecDeque<TransitionRecord>,
    max_history: usize,
    consecutive_failures: u32,
    last_activity: u64,
    created_at: u64,
}

impl PeerStateMachine {
    /// Create a new state machine for a peer
    pub fn new(peer_id: PeerId) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            peer_id,
            current_state: PeerState::Unknown,
            history: VecDeque::with_capacity(100),
            max_history: 100,
            consecutive_failures: 0,
            last_activity: now,
            created_at: now,
        }
    }

    /// Get the current state
    pub fn current_state(&self) -> PeerState {
        self.current_state
    }

    /// Get the peer ID
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Check if peer is in an active state
    pub fn is_active(&self) -> bool {
        self.current_state.is_active()
    }

    /// Get last activity timestamp
    pub fn last_active_timestamp(&self) -> Option<u64> {
        Some(self.last_activity)
    }

    /// Apply a state transition
    pub fn apply_transition(&mut self, transition: StateTransition) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let old_state = self.current_state;
        let new_state = self.compute_next_state(&transition);

        // Update consecutive failure counter
        match &transition {
            StateTransition::FailRequest | StateTransition::Timeout | StateTransition::ValidateFail => {
                self.consecutive_failures += 1;
            }
            StateTransition::ServeChunk | StateTransition::ValidateSuccess | StateTransition::Connected => {
                self.consecutive_failures = 0;
            }
            _ => {}
        }

        // Check if we should escalate to suspect
        if self.consecutive_failures >= 3 && !matches!(new_state, PeerState::Suspect | PeerState::Banned) {
            self.current_state = PeerState::Suspect;
        } else {
            self.current_state = new_state;
        }

        // Record transition
        let record = TransitionRecord {
            from: old_state,
            to: self.current_state,
            trigger: transition,
            timestamp: now,
        };

        self.history.push_back(record);
        if self.history.len() > self.max_history {
            self.history.pop_front();
        }

        self.last_activity = now;
    }

    /// Compute the next state based on current state and transition
    fn compute_next_state(&self, transition: &StateTransition) -> PeerState {
        use PeerState::*;
        use StateTransition::*;

        match (&self.current_state, transition) {
            // From Unknown
            (Unknown, Connect) => Connecting,
            (Unknown, _) => Unknown,

            // From Connecting
            (Connecting, Connected) => PeerState::Connected,
            (Connecting, Disconnect) => Disconnected,
            (Connecting, Timeout) => Degraded,
            (Connecting, _) => Connecting,

            // From Connected
            (PeerState::Connected, ServeChunk) => Serving,
            (PeerState::Connected, RequestChunk) => Requesting,
            (PeerState::Connected, Disconnect) => Disconnected,
            (PeerState::Connected, Timeout) => Degraded,
            (PeerState::Connected, GoIdle) => Idle,
            (PeerState::Connected, _) => PeerState::Connected,

            // From Serving
            (Serving, ServeChunk) => Serving,
            (Serving, RequestChunk) => Requesting,
            (Serving, FailRequest) => Degraded,
            (Serving, ValidateFail) => Suspect,
            (Serving, Disconnect) => Disconnected,
            (Serving, GoIdle) => Idle,
            (Serving, _) => Serving,

            // From Requesting
            (Requesting, ServeChunk) => Serving,
            (Requesting, RequestChunk) => Requesting,
            (Requesting, ValidateSuccess) => PeerState::Connected,
            (Requesting, ValidateFail) => Suspect,
            (Requesting, Timeout) => Degraded,
            (Requesting, Disconnect) => Disconnected,
            (Requesting, _) => Requesting,

            // From Degraded
            (Degraded, Recover) => PeerState::Connected,
            (Degraded, StateTransition::Connected) => PeerState::Connected,
            (Degraded, ServeChunk) => Serving,
            (Degraded, FailRequest) => Suspect,
            (Degraded, Timeout) => Suspect,
            (Degraded, ValidateFail) => Banned,
            (Degraded, Disconnect) => Disconnected,
            (Degraded, _) => Degraded,

            // From Suspect
            (Suspect, ValidateSuccess) => Degraded, // Needs to prove itself
            (Suspect, ServeChunk) => Degraded,
            (Suspect, ValidateFail) => Banned,
            (Suspect, FailRequest) => Banned,
            (Suspect, Disconnect) => Disconnected,
            (Suspect, Unban) => Degraded,
            (Suspect, _) => Suspect,

            // From Banned
            (Banned, Unban) => Degraded,
            (Banned, _) => Banned,

            // From Disconnected
            (Disconnected, Connect) => Connecting,
            (Disconnected, _) => Disconnected,

            // From Idle
            (Idle, RequestChunk) => Requesting,
            (Idle, ServeChunk) => Serving,
            (Idle, Disconnect) => Disconnected,
            (Idle, Timeout) => Degraded,
            (Idle, _) => Idle,
        }
    }

    /// Get transition history
    pub fn history(&self) -> &VecDeque<TransitionRecord> {
        &self.history
    }

    /// Get time in current state
    pub fn time_in_state(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if let Some(last) = self.history.back() {
            now.saturating_sub(last.timestamp)
        } else {
            now.saturating_sub(self.created_at)
        }
    }

    /// Get stability score (how stable the peer's state has been)
    pub fn stability_score(&self) -> f64 {
        if self.history.is_empty() {
            return 0.5; // Neutral for new peers
        }

        // Count state changes in the last hour
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let one_hour_ago = now.saturating_sub(3600);

        let recent_changes = self.history
            .iter()
            .filter(|r| r.timestamp >= one_hour_ago)
            .count();

        // Score decreases with more state changes
        // 0 changes = 1.0, 10+ changes = 0.1
        let score = 1.0 - (recent_changes as f64 * 0.09).min(0.9);
        score
    }

    /// Get failure ratio in history
    pub fn failure_ratio(&self) -> f64 {
        if self.history.is_empty() {
            return 0.0;
        }

        let failures = self.history
            .iter()
            .filter(|r| matches!(
                r.trigger,
                StateTransition::FailRequest | StateTransition::Timeout | StateTransition::ValidateFail
            ))
            .count();

        failures as f64 / self.history.len() as f64
    }

    /// Get success ratio in history
    pub fn success_ratio(&self) -> f64 {
        if self.history.is_empty() {
            return 0.5;
        }

        let successes = self.history
            .iter()
            .filter(|r| matches!(
                r.trigger,
                StateTransition::ServeChunk | StateTransition::ValidateSuccess
            ))
            .count();

        successes as f64 / self.history.len() as f64
    }

    /// Get overall behavior score (combines multiple factors)
    pub fn behavior_score(&self) -> f64 {
        let state_factor = self.current_state.trust_factor();
        let stability = self.stability_score();
        let success = self.success_ratio();
        let failure_penalty = 1.0 - self.failure_ratio();

        // Weighted combination
        0.3 * state_factor + 0.2 * stability + 0.3 * success + 0.2 * failure_penalty
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
    fn test_state_transitions() {
        let peer = test_peer(1);
        let mut sm = PeerStateMachine::new(peer);

        assert_eq!(sm.current_state(), PeerState::Unknown);

        sm.apply_transition(StateTransition::Connect);
        assert_eq!(sm.current_state(), PeerState::Connecting);

        sm.apply_transition(StateTransition::Connected);
        assert_eq!(sm.current_state(), PeerState::Connected);

        sm.apply_transition(StateTransition::ServeChunk);
        assert_eq!(sm.current_state(), PeerState::Serving);

        assert!(sm.is_active());
    }

    #[test]
    fn test_failure_escalation() {
        let peer = test_peer(2);
        let mut sm = PeerStateMachine::new(peer);

        sm.apply_transition(StateTransition::Connect);
        sm.apply_transition(StateTransition::Connected);

        // Three consecutive failures should escalate to Suspect
        sm.apply_transition(StateTransition::FailRequest);
        sm.apply_transition(StateTransition::FailRequest);
        sm.apply_transition(StateTransition::FailRequest);

        assert_eq!(sm.current_state(), PeerState::Suspect);
    }

    #[test]
    fn test_behavior_score() {
        let peer = test_peer(3);
        let mut sm = PeerStateMachine::new(peer);

        sm.apply_transition(StateTransition::Connect);
        sm.apply_transition(StateTransition::Connected);
        sm.apply_transition(StateTransition::ServeChunk);
        sm.apply_transition(StateTransition::ValidateSuccess);

        let score = sm.behavior_score();
        assert!(score > 0.5, "Good peer should have high score");
    }
}
