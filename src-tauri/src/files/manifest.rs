//! File manifest - encrypted metadata about stored files
//!
//! The manifest tracks:
//! - Original filename and size
//! - Chunk IDs and their peer locations
//! - Encryption salt
//! - Erasure coding config

use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::crypto::hashing::ChunkId;
use crate::files::erasure::ErasureConfig;

/// Metadata for a single stored file
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileManifest {
    /// Unique file identifier (random)
    pub file_id: [u8; 32],

    /// Original filename (encrypted in storage)
    pub filename: String,

    /// Original file size in bytes
    pub original_size: u64,

    /// Salt used for key derivation
    pub salt: [u8; 16],

    /// Size of each chunk
    pub chunk_size: usize,

    /// Erasure coding configuration
    pub erasure_config: ErasureConfig,

    /// List of chunks in order
    pub chunks: Vec<ChunkInfo>,

    /// Creation timestamp
    pub created_at: u64,

    /// BLAKE3 hash of original file (for verification)
    pub content_hash: [u8; 32],
}

/// Information about a single chunk
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChunkInfo {
    /// Chunk index within the file
    pub index: u64,

    /// Content-addressed ID (hash of encrypted chunk)
    pub chunk_id: ChunkId,

    /// Size of this chunk after encryption
    pub encrypted_size: usize,

    /// Shard indices from erasure coding (for this chunk)
    pub shard_locations: Vec<ShardLocation>,
}

/// Location of a shard in the network
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShardLocation {
    /// Shard index (0..total_shards)
    pub shard_index: usize,

    /// Content-addressed ID of this shard
    pub shard_id: ChunkId,

    /// Peer IDs known to store this shard
    pub peer_ids: Vec<String>,
}

impl FileManifest {
    /// Create a new file manifest
    pub fn new(
        filename: String,
        original_size: u64,
        salt: [u8; 16],
        chunk_size: usize,
        erasure_config: ErasureConfig,
        content_hash: [u8; 32],
    ) -> Self {
        let mut file_id = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut file_id);

        Self {
            file_id,
            filename,
            original_size,
            salt,
            chunk_size,
            erasure_config,
            chunks: Vec::new(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            content_hash,
        }
    }

    /// Serialize manifest to bytes (will be encrypted before storage)
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Deserialize manifest from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

    /// Add a chunk to the manifest
    pub fn add_chunk(&mut self, chunk_info: ChunkInfo) {
        self.chunks.push(chunk_info);
    }

    /// Get total number of chunks
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::MasterKey;

    #[test]
    fn test_manifest_serialization() {
        let salt = MasterKey::generate_salt();
        let manifest = FileManifest::new(
            "test.txt".to_string(),
            1024,
            salt,
            1024 * 1024,
            ErasureConfig::default(),
            [0u8; 32],
        );

        let bytes = manifest.to_bytes().unwrap();
        let decoded = FileManifest::from_bytes(&bytes).unwrap();

        assert_eq!(manifest.filename, decoded.filename);
        assert_eq!(manifest.original_size, decoded.original_size);
    }
}
