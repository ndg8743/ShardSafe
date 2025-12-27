//! File chunking with configurable chunk size
//!
//! Splits files into fixed-size chunks for distribution.
//! Padding is applied to obscure exact file sizes.

use thiserror::Error;

/// Default chunk size: 1 MiB
pub const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;

#[derive(Error, Debug)]
pub enum ChunkError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid padding")]
    InvalidPadding,
}

/// A single chunk of file data
#[derive(Clone)]
pub struct Chunk {
    /// Index of this chunk (0-based)
    pub index: u64,
    /// Raw chunk data (may be padded)
    pub data: Vec<u8>,
    /// Whether this chunk contains padding
    pub is_padded: bool,
}

/// Split data into fixed-size chunks
///
/// The last chunk is padded to the full chunk size to obscure file length.
/// Padding format: data || 0x80 || 0x00...0x00 || length (8 bytes big-endian)
pub fn chunk_data(data: &[u8], chunk_size: usize) -> Vec<Chunk> {
    let mut chunks = Vec::new();
    let mut offset = 0;
    let mut index = 0;

    while offset < data.len() {
        let end = std::cmp::min(offset + chunk_size, data.len());
        let chunk_data = &data[offset..end];

        let (final_data, is_padded) = if end == data.len() {
            // Last chunk - apply padding
            (pad_chunk(chunk_data, chunk_size), true)
        } else {
            (chunk_data.to_vec(), false)
        };

        chunks.push(Chunk {
            index,
            data: final_data,
            is_padded,
        });

        offset = end;
        index += 1;
    }

    // Handle empty file case
    if chunks.is_empty() {
        chunks.push(Chunk {
            index: 0,
            data: pad_chunk(&[], chunk_size),
            is_padded: true,
        });
    }

    chunks
}

/// Apply PKCS#7-style padding with length suffix
fn pad_chunk(data: &[u8], chunk_size: usize) -> Vec<u8> {
    let mut padded = Vec::with_capacity(chunk_size);
    padded.extend_from_slice(data);

    // Add padding byte
    padded.push(0x80);

    // Fill with zeros until we have room for length
    while padded.len() < chunk_size - 8 {
        padded.push(0x00);
    }

    // Ensure we have exactly chunk_size - 8 bytes before adding length
    padded.resize(chunk_size - 8, 0x00);

    // Append original data length (to detect padding removal)
    padded.extend_from_slice(&(data.len() as u64).to_be_bytes());

    padded
}

/// Remove padding from a chunk
pub fn unpad_chunk(data: &[u8]) -> Result<Vec<u8>, ChunkError> {
    if data.len() < 9 {
        return Ok(data.to_vec()); // Not padded
    }

    // Read original length from end
    let len_bytes: [u8; 8] = data[data.len() - 8..]
        .try_into()
        .map_err(|_| ChunkError::InvalidPadding)?;
    let original_len = u64::from_be_bytes(len_bytes) as usize;

    if original_len > data.len() - 9 {
        return Err(ChunkError::InvalidPadding);
    }

    Ok(data[..original_len].to_vec())
}

/// Reassemble chunks into original file data
pub fn reassemble_chunks(chunks: &mut [Chunk]) -> Result<Vec<u8>, ChunkError> {
    // Sort by index
    chunks.sort_by_key(|c| c.index);

    let mut result = Vec::new();

    for (i, chunk) in chunks.iter().enumerate() {
        let data = if chunk.is_padded || i == chunks.len() - 1 {
            unpad_chunk(&chunk.data)?
        } else {
            chunk.data.clone()
        };
        result.extend_from_slice(&data);
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_and_reassemble() {
        let data = vec![0u8; 2_500_000]; // 2.5 MB
        let chunks = chunk_data(&data, DEFAULT_CHUNK_SIZE);

        assert_eq!(chunks.len(), 3); // 1MB + 1MB + 0.5MB padded

        let mut chunks_clone: Vec<Chunk> = chunks.into_iter().collect();
        let reassembled = reassemble_chunks(&mut chunks_clone).unwrap();

        assert_eq!(data, reassembled);
    }

    #[test]
    fn test_small_file() {
        let data = b"Hello, World!".to_vec();
        let chunks = chunk_data(&data, DEFAULT_CHUNK_SIZE);

        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].is_padded);
        assert_eq!(chunks[0].data.len(), DEFAULT_CHUNK_SIZE);

        let mut chunks_clone = chunks;
        let reassembled = reassemble_chunks(&mut chunks_clone).unwrap();
        assert_eq!(data, reassembled);
    }

    #[test]
    fn test_empty_file() {
        let chunks = chunk_data(&[], DEFAULT_CHUNK_SIZE);
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].is_padded);

        let mut chunks_clone = chunks;
        let reassembled = reassemble_chunks(&mut chunks_clone).unwrap();
        assert!(reassembled.is_empty());
    }
}
