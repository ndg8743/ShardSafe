//! Storage module for local chunk persistence
//!
//! Uses sled embedded database for fast, reliable storage.

pub mod chunks;

pub use chunks::{ChunkStore, StorageError};
