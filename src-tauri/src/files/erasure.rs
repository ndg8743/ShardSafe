//! Simple erasure coding for fault tolerance
//!
//! This is a simplified implementation that splits data into shards
//! with basic replication. For production, replace with proper Reed-Solomon.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ErasureError {
    #[error("Not enough shards to reconstruct (have {have}, need {need})")]
    NotEnoughShards { have: usize, need: usize },
    #[error("Invalid shard size")]
    InvalidShardSize,
}

/// Erasure coding configuration
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub struct ErasureConfig {
    /// Number of data shards (k)
    pub data_shards: usize,
    /// Number of parity shards (replicas for now)
    pub parity_shards: usize,
}

impl Default for ErasureConfig {
    fn default() -> Self {
        // 3 data + 2 parity = 5 total shards
        Self {
            data_shards: 3,
            parity_shards: 2,
        }
    }
}

impl ErasureConfig {
    /// Total number of shards (k + m)
    pub fn total_shards(&self) -> usize {
        self.data_shards + self.parity_shards
    }
}

/// Encode data into shards
///
/// Splits data into data_shards pieces.
/// Parity shards are copies of data shards for redundancy.
pub fn encode(data: &[u8], config: ErasureConfig) -> Result<Vec<Vec<u8>>, ErasureError> {
    if data.is_empty() {
        return Ok(vec![vec![]; config.total_shards()]);
    }

    let shard_size = (data.len() + config.data_shards - 1) / config.data_shards;

    // Pad data
    let mut padded = data.to_vec();
    padded.resize(shard_size * config.data_shards, 0);

    // Split into data shards
    let mut shards: Vec<Vec<u8>> = padded
        .chunks(shard_size)
        .map(|c| c.to_vec())
        .collect();

    // Add parity shards (simple replication for now)
    for i in 0..config.parity_shards {
        let source_idx = i % config.data_shards;
        shards.push(shards[source_idx].clone());
    }

    Ok(shards)
}

/// Decode shards back to original data
///
/// `shards` is a vec of (shard_index, shard_data) tuples.
pub fn decode(
    shards: Vec<(usize, Vec<u8>)>,
    config: ErasureConfig,
    original_len: usize,
) -> Result<Vec<u8>, ErasureError> {
    if shards.is_empty() || original_len == 0 {
        return Ok(vec![]);
    }

    if shards.len() < config.data_shards {
        return Err(ErasureError::NotEnoughShards {
            have: shards.len(),
            need: config.data_shards,
        });
    }

    // Collect data shards (or parity equivalents)
    let mut data_shards: Vec<Option<Vec<u8>>> = vec![None; config.data_shards];

    for (idx, data) in shards {
        if idx < config.data_shards {
            data_shards[idx] = Some(data);
        } else {
            // Parity shards are copies of data shards
            let source_idx = (idx - config.data_shards) % config.data_shards;
            if data_shards[source_idx].is_none() {
                data_shards[source_idx] = Some(data);
            }
        }
    }

    // Check we have all data shards
    if data_shards.iter().any(|s| s.is_none()) {
        return Err(ErasureError::NotEnoughShards {
            have: data_shards.iter().filter(|s| s.is_some()).count(),
            need: config.data_shards,
        });
    }

    // Concatenate shards
    let mut result = Vec::with_capacity(original_len);
    for shard in data_shards.into_iter().flatten() {
        result.extend_from_slice(&shard);
    }
    result.truncate(original_len);

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_no_loss() {
        let data = b"Hello, World! This is test data for erasure coding.";
        let config = ErasureConfig::default();

        let shards = encode(data, config).unwrap();
        assert_eq!(shards.len(), config.total_shards());

        let indexed: Vec<(usize, Vec<u8>)> = shards.into_iter().enumerate().collect();
        let decoded = decode(indexed, config, data.len()).unwrap();

        assert_eq!(data.as_slice(), decoded.as_slice());
    }

    #[test]
    fn test_decode_with_losses() {
        let data = b"Test data for reconstruction";
        let config = ErasureConfig::default();

        let shards = encode(data, config).unwrap();

        // Lose shard 1, but parity shard 3 (index 3) is a copy of shard 0
        // and parity shard 4 (index 4) is a copy of shard 1
        let surviving: Vec<(usize, Vec<u8>)> = shards
            .into_iter()
            .enumerate()
            .filter(|(i, _)| *i != 1) // lose shard 1
            .collect();

        let decoded = decode(surviving, config, data.len()).unwrap();
        assert_eq!(data.as_slice(), decoded.as_slice());
    }
}
