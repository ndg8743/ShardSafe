//! Content-addressed hashing using BLAKE3
//!
//! Every chunk is identified by its cryptographic hash.
//! This enables:
//! - Deduplication (same content = same hash)
//! - Integrity verification
//! - Tamper detection

use serde::{Deserialize, Serialize};
use std::fmt;

/// A content-addressed chunk identifier
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChunkId(pub [u8; 32]);

impl ChunkId {
    /// Compute the ChunkId for given data
    pub fn from_data(data: &[u8]) -> Self {
        let hash = blake3::hash(data);
        Self(*hash.as_bytes())
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex string
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| hex::FromHexError::InvalidStringLength)?;
        Ok(Self(arr))
    }
}

impl fmt::Display for ChunkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Debug for ChunkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChunkId({}...)", &self.to_hex()[..8])
    }
}

/// Verify that data matches its claimed ChunkId
pub fn verify_chunk(chunk_id: &ChunkId, data: &[u8]) -> bool {
    ChunkId::from_data(data) == *chunk_id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_same_content_same_hash() {
        let data = b"test data";
        let id1 = ChunkId::from_data(data);
        let id2 = ChunkId::from_data(data);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_different_content_different_hash() {
        let id1 = ChunkId::from_data(b"data1");
        let id2 = ChunkId::from_data(b"data2");
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_hex_roundtrip() {
        let id = ChunkId::from_data(b"test");
        let hex = id.to_hex();
        let parsed = ChunkId::from_hex(&hex).unwrap();
        assert_eq!(id, parsed);
    }
}
