//! File processing module
//!
//! Handles chunking, erasure coding, and file manifests.

pub mod chunker;
pub mod erasure;
pub mod manifest;

pub use chunker::{chunk_data, reassemble_chunks, Chunk, DEFAULT_CHUNK_SIZE};
pub use erasure::{decode, encode, ErasureConfig, ErasureError};
pub use manifest::{ChunkInfo, FileManifest, ShardLocation};
