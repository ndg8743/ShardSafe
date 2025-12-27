//! Key derivation and management using Argon2id
//!
//! Security: Keys are derived from user passphrase using Argon2id,
//! which is resistant to GPU/ASIC attacks and side-channel attacks.

use argon2::{Argon2, Algorithm, Params, Version};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::ZeroizeOnDrop;

/// Master key derived from user passphrase
/// Automatically zeroed when dropped
#[derive(ZeroizeOnDrop)]
pub struct MasterKey {
    key: [u8; 32],
}

impl MasterKey {
    /// Derive a master key from a passphrase
    ///
    /// Uses Argon2id with memory-hard parameters to resist brute force
    pub fn derive_from_passphrase(
        passphrase: &str,
        salt: &[u8; 16],
    ) -> Result<Self, argon2::Error> {
        // Argon2id parameters (OWASP recommendations)
        // Memory: 64 MiB, Iterations: 3, Parallelism: 4
        let params = Params::new(
            64 * 1024, // 64 MiB memory
            3,         // 3 iterations
            4,         // 4 parallel lanes
            Some(32),  // 32-byte output
        )?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key = [0u8; 32];
        argon2.hash_password_into(passphrase.as_bytes(), salt, &mut key)?;

        Ok(Self { key })
    }

    /// Generate a new random salt for key derivation
    pub fn generate_salt() -> [u8; 16] {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        salt
    }

    /// Derive a chunk-specific key from master key
    ///
    /// Each chunk gets a unique key derived from:
    /// master_key || file_id || chunk_index
    pub fn derive_chunk_key(&self, file_id: &[u8; 32], chunk_index: u64) -> ChunkKey {
        let mut hasher = blake3::Hasher::new_derive_key("p2p-storage chunk key v1");
        hasher.update(&self.key);
        hasher.update(file_id);
        hasher.update(&chunk_index.to_le_bytes());

        let mut chunk_key = [0u8; 32];
        hasher.finalize_xof().fill(&mut chunk_key);

        ChunkKey { key: chunk_key }
    }

    /// Get raw key bytes (use carefully)
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

/// Per-chunk encryption key
#[derive(ZeroizeOnDrop)]
pub struct ChunkKey {
    key: [u8; 32],
}

impl ChunkKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation_deterministic() {
        let salt = [0u8; 16];
        let key1 = MasterKey::derive_from_passphrase("test", &salt).unwrap();
        let key2 = MasterKey::derive_from_passphrase("test", &salt).unwrap();
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_chunk_keys_unique() {
        let salt = MasterKey::generate_salt();
        let master = MasterKey::derive_from_passphrase("test", &salt).unwrap();
        let file_id = [0u8; 32];

        let key0 = master.derive_chunk_key(&file_id, 0);
        let key1 = master.derive_chunk_key(&file_id, 1);

        assert_ne!(key0.as_bytes(), key1.as_bytes());
    }
}
