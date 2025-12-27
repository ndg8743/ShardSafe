//! Local chunk storage using sled embedded database

use sled::{Db, Tree};
use std::path::Path;
use thiserror::Error;
use tracing::info;

use crate::crypto::hashing::ChunkId;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Database(#[from] sled::Error),
    #[error("Chunk not found: {0}")]
    NotFound(ChunkId),
    #[error("Storage full")]
    StorageFull,
    #[error("Chunk ID mismatch")]
    ChunkIdMismatch,
}

/// Local storage for chunks
pub struct ChunkStore {
    #[allow(dead_code)]
    db: Db,
    chunks: Tree,
    metadata: Tree,
    max_size_bytes: u64,
}

impl ChunkStore {
    /// Open or create chunk store at given path
    pub fn open(path: impl AsRef<Path>, max_size_gb: u64) -> Result<Self, StorageError> {
        let db = sled::open(path)?;
        let chunks = db.open_tree("chunks")?;
        let metadata = db.open_tree("metadata")?;

        Ok(Self {
            db,
            chunks,
            metadata,
            max_size_bytes: max_size_gb * 1024 * 1024 * 1024,
        })
    }

    /// Store a chunk
    pub fn store(&self, chunk_id: &ChunkId, data: &[u8]) -> Result<(), StorageError> {
        // Check storage limits
        let current_size = self.total_size()?;
        if current_size + data.len() as u64 > self.max_size_bytes {
            return Err(StorageError::StorageFull);
        }

        // Verify chunk ID matches data
        let computed_id = ChunkId::from_data(data);
        if computed_id != *chunk_id {
            info!("Chunk ID mismatch - rejecting");
            return Err(StorageError::ChunkIdMismatch);
        }

        // Store chunk
        self.chunks.insert(chunk_id.as_bytes(), data)?;

        // Update metadata
        let key = format!("stored_at:{}", chunk_id);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.metadata
            .insert(key.as_bytes(), &timestamp.to_le_bytes())?;

        Ok(())
    }

    /// Retrieve a chunk
    pub fn get(&self, chunk_id: &ChunkId) -> Result<Vec<u8>, StorageError> {
        self.chunks
            .get(chunk_id.as_bytes())?
            .map(|v| v.to_vec())
            .ok_or_else(|| StorageError::NotFound(*chunk_id))
    }

    /// Check if we have a chunk
    pub fn has(&self, chunk_id: &ChunkId) -> Result<bool, StorageError> {
        Ok(self.chunks.contains_key(chunk_id.as_bytes())?)
    }

    /// Delete a chunk
    pub fn delete(&self, chunk_id: &ChunkId) -> Result<(), StorageError> {
        self.chunks.remove(chunk_id.as_bytes())?;
        let key = format!("stored_at:{}", chunk_id);
        self.metadata.remove(key.as_bytes())?;
        Ok(())
    }

    /// List all stored chunk IDs
    pub fn list_chunks(&self) -> Result<Vec<ChunkId>, StorageError> {
        let mut chunks = Vec::new();
        for item in self.chunks.iter() {
            let (key, _) = item?;
            if key.len() == 32 {
                let bytes: [u8; 32] = key.as_ref().try_into().unwrap();
                chunks.push(ChunkId::from_bytes(bytes));
            }
        }
        Ok(chunks)
    }

    /// Get total storage used
    pub fn total_size(&self) -> Result<u64, StorageError> {
        let mut total = 0u64;
        for item in self.chunks.iter() {
            let (_, value) = item?;
            total += value.len() as u64;
        }
        Ok(total)
    }

    /// Get number of stored chunks
    pub fn chunk_count(&self) -> Result<usize, StorageError> {
        Ok(self.chunks.len())
    }

    /// Flush changes to disk
    pub fn flush(&self) -> Result<(), StorageError> {
        self.chunks.flush()?;
        self.metadata.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_store_and_retrieve() {
        let dir = tempdir().unwrap();
        let store = ChunkStore::open(dir.path(), 1).unwrap();

        let data = b"test chunk data";
        let chunk_id = ChunkId::from_data(data);

        store.store(&chunk_id, data).unwrap();

        let retrieved = store.get(&chunk_id).unwrap();
        assert_eq!(data.as_slice(), retrieved.as_slice());
    }

    #[test]
    fn test_chunk_id_mismatch() {
        let dir = tempdir().unwrap();
        let store = ChunkStore::open(dir.path(), 1).unwrap();

        let data = b"test chunk data";
        let wrong_id = ChunkId::from_data(b"wrong");

        let result = store.store(&wrong_id, data);
        assert!(matches!(result, Err(StorageError::ChunkIdMismatch)));
    }

    #[test]
    fn test_list_chunks() {
        let dir = tempdir().unwrap();
        let store = ChunkStore::open(dir.path(), 1).unwrap();

        let data1 = b"chunk 1";
        let data2 = b"chunk 2";
        let id1 = ChunkId::from_data(data1);
        let id2 = ChunkId::from_data(data2);

        store.store(&id1, data1).unwrap();
        store.store(&id2, data2).unwrap();

        let chunks = store.list_chunks().unwrap();
        assert_eq!(chunks.len(), 2);
    }
}
