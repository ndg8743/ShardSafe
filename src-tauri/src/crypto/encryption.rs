//! Authenticated encryption using ChaCha20-Poly1305
//!
//! Why ChaCha20 over AES?
//! - Faster on systems without AES-NI (mobile, older hardware)
//! - No timing side-channel vulnerabilities
//! - Simpler implementation, less room for errors

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use thiserror::Error;

use super::keys::ChunkKey;

#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed - data may be corrupted or key incorrect")]
    DecryptionFailed,
    #[error("Invalid ciphertext format")]
    InvalidFormat,
}

/// Encrypt data with ChaCha20-Poly1305
///
/// Output format: nonce (12 bytes) || ciphertext || tag (16 bytes)
pub fn encrypt(key: &ChunkKey, plaintext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    let cipher = ChaCha20Poly1305::new(key.as_bytes().into());

    // Generate random nonce
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

    // Encrypt with authentication
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| EncryptionError::EncryptionFailed)?;

    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt data with ChaCha20-Poly1305
pub fn decrypt(key: &ChunkKey, ciphertext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    if ciphertext.len() < 12 + 16 {
        return Err(EncryptionError::InvalidFormat);
    }

    let cipher = ChaCha20Poly1305::new(key.as_bytes().into());

    // Extract nonce and ciphertext
    let nonce = Nonce::from_slice(&ciphertext[..12]);
    let encrypted = &ciphertext[12..];

    // Decrypt and verify
    cipher
        .decrypt(nonce, encrypted)
        .map_err(|_| EncryptionError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::MasterKey;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let salt = MasterKey::generate_salt();
        let master = MasterKey::derive_from_passphrase("test", &salt).unwrap();
        let chunk_key = master.derive_chunk_key(&[0u8; 32], 0);

        let plaintext = b"Hello, World!";
        let ciphertext = encrypt(&chunk_key, plaintext).unwrap();
        let decrypted = decrypt(&chunk_key, &ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_wrong_key_fails() {
        let salt = MasterKey::generate_salt();
        let master = MasterKey::derive_from_passphrase("test", &salt).unwrap();
        let key1 = master.derive_chunk_key(&[0u8; 32], 0);
        let key2 = master.derive_chunk_key(&[0u8; 32], 1);

        let ciphertext = encrypt(&key1, b"secret").unwrap();
        let result = decrypt(&key2, &ciphertext);

        assert!(result.is_err());
    }
}
