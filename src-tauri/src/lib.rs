//! ShardSafe - Zero-Trust P2P Distributed Storage System
//!
//! A decentralized file storage system where:
//! - Files are encrypted client-side before leaving your machine
//! - Encrypted files are split into shards and distributed across peers
//! - No single node (including storage nodes) can read your data
//! - Files can be reconstructed from a subset of shards (erasure coding)
//! - Authority nodes are discovered via Eigenvector Centrality
//! - Consensus is achieved through weighted voting based on authority scores

pub mod authority;
pub mod consensus;
pub mod crypto;
pub mod files;
pub mod network;
pub mod schema;
pub mod storage;

// Re-export commonly used types
pub use crypto::{ChunkId, ChunkKey, MasterKey};
pub use files::{ErasureConfig, FileManifest};
pub use network::{
    NodeConfig, NodeEvent, P2PNode,
    AuthorityNode, AuthorityNodeConfig, AuthorityEvent, AuthorityError,
};
pub use storage::ChunkStore;

// Re-export authority system types
pub use authority::{
    AuthoritySystem, AuthorityScores, CentralityConfig,
    NetworkGraph, TrafficType, EdgeWeight,
    PeerState, PeerStateMachine, StateTransition,
    ReputationScore, ReputationSystem, ReputationConfig,
    NetworkStats,
};

// Re-export consensus types
pub use consensus::{
    ConsensusSystem, ConsensusConfig, ConsensusResult,
    ChunkValidation, ValidationResult, ValidationStatus,
    ConsensusVote, VotingRound,
};

// Re-export schema types (Concordia-inspired)
pub use schema::{
    // Type system
    SchemaType, Field, FieldType, Message, MessageSchema,
    // Rule engine (hot-reloadable)
    RuleEngine, Rule, RuleSet, RuleContext,
    // Expression VM
    ExprVM, Opcode, Value, ExprError,
    // Validation framework
    Validator, ValidationRule, SchemaValidationResult,
    // Codec
    Codec, CodecError, EncodeContext, DecodeContext,
};
