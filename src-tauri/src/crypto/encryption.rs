//! Authenticated encryption using XChaCha20-Poly1305
//!
//! Why XChaCha20 over regular ChaCha20?
//! - 24-byte nonce (vs 12) - safe for random nonce generation
//! - No birthday bound issues until ~2^96 messages
//!
//! Why ChaCha20 over AES?
//! - Faster on systems without AES-NI (mobile, older hardware)
//! - No timing side-channel vulnerabilities
//! - Simpler implementation, less room for errors

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
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

/// Encrypt data with XChaCha20-Poly1305
///
/// Output format: nonce (24 bytes) || ciphertext || tag (16 bytes)
pub fn encrypt(key: &ChunkKey, plaintext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());

    // Generate random 24-byte nonce (safe for random generation)
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

    // Encrypt with authentication
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| EncryptionError::EncryptionFailed)?;

    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(24 + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt data with XChaCha20-Poly1305
pub fn decrypt(key: &ChunkKey, ciphertext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    // 24 bytes nonce + 16 bytes tag minimum
    if ciphertext.len() < 24 + 16 {
        return Err(EncryptionError::InvalidFormat);
    }

    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());

    // Extract 24-byte nonce and ciphertext
    let nonce = XNonce::from_slice(&ciphertext[..24]);
    let encrypted = &ciphertext[24..];

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
