//! Cryptography module for zero-trust encryption
//!
//! Provides key derivation, authenticated encryption, and content addressing.

pub mod encryption;
pub mod hashing;
pub mod keys;

pub use encryption::{decrypt, encrypt, EncryptionError};
pub use hashing::{verify_chunk, ChunkId};
pub use keys::{ChunkKey, MasterKey};
