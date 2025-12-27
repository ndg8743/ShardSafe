//! ShardSafe - Zero-Trust P2P Distributed Storage System
//!
//! A decentralized file storage system where:
//! - Files are encrypted client-side before leaving your machine
//! - Encrypted files are split into shards and distributed across peers
//! - No single node (including storage nodes) can read your data
//! - Files can be reconstructed from a subset of shards (erasure coding)

pub mod crypto;
pub mod files;
pub mod network;
pub mod storage;

// Re-export commonly used types
pub use crypto::{ChunkId, ChunkKey, MasterKey};
pub use files::{ErasureConfig, FileManifest};
pub use network::{NodeConfig, NodeEvent, P2PNode};
pub use storage::ChunkStore;
