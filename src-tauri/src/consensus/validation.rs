//! Chunk Validation Module
//!
//! Defines validation results and statuses for chunks.

use crate::crypto::ChunkId;
use serde::{Deserialize, Serialize};

/// Result of validating a chunk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// The chunk that was validated
    pub chunk_id: ChunkId,
    /// Whether the chunk passed validation
    pub is_valid: bool,
    /// Hash verification result
    pub hash_verified: bool,
    /// Size verification result
    pub size_verified: bool,
    /// Optional error message
    pub error: Option<String>,
    /// Timestamp of validation
    pub timestamp: u64,
}

impl ValidationResult {
    /// Create a successful validation result
    pub fn success(chunk_id: ChunkId) -> Self {
        Self {
            chunk_id,
            is_valid: true,
            hash_verified: true,
            size_verified: true,
            error: None,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// Create a failed validation result
    pub fn failure(chunk_id: ChunkId, error: String) -> Self {
        Self {
            chunk_id,
            is_valid: false,
            hash_verified: false,
            size_verified: false,
            error: Some(error),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// Create a hash mismatch result
    pub fn hash_mismatch(chunk_id: ChunkId) -> Self {
        Self {
            chunk_id,
            is_valid: false,
            hash_verified: false,
            size_verified: true,
            error: Some("Hash mismatch".to_string()),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
}

/// Status of chunk validation in the network
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationStatus {
    /// Not yet validated
    Pending,
    /// Validation in progress
    InProgress,
    /// Successfully validated
    Validated,
    /// Validation failed
    Invalid,
    /// Validation inconclusive (not enough votes)
    Inconclusive,
}

/// A chunk validation report submitted by a peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkValidation {
    /// The validation result
    pub result: ValidationResult,
    /// Confidence score (0.0 to 1.0)
    pub confidence: f64,
    /// Method used to validate
    pub method: ValidationMethod,
    /// Additional metadata
    pub metadata: Option<ValidationMetadata>,
}

impl ChunkValidation {
    /// Create a new validation with high confidence
    pub fn valid(chunk_id: ChunkId) -> Self {
        Self {
            result: ValidationResult::success(chunk_id),
            confidence: 1.0,
            method: ValidationMethod::FullHash,
            metadata: None,
        }
    }

    /// Create an invalid validation
    pub fn invalid(chunk_id: ChunkId, reason: String) -> Self {
        Self {
            result: ValidationResult::failure(chunk_id, reason),
            confidence: 1.0,
            method: ValidationMethod::FullHash,
            metadata: None,
        }
    }

    /// Check if this validation indicates validity
    pub fn is_valid(&self) -> bool {
        self.result.is_valid
    }
}

/// Method used to validate a chunk
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationMethod {
    /// Full hash verification (BLAKE3)
    FullHash,
    /// Probabilistic sampling
    Sampling,
    /// Proof of retrievability check
    ProofOfRetrievability,
    /// Size-only check
    SizeOnly,
    /// Trusted source (no verification)
    TrustedSource,
}

impl ValidationMethod {
    /// Get the reliability weight for this method
    pub fn reliability_weight(&self) -> f64 {
        match self {
            ValidationMethod::FullHash => 1.0,
            ValidationMethod::ProofOfRetrievability => 0.95,
            ValidationMethod::Sampling => 0.7,
            ValidationMethod::SizeOnly => 0.3,
            ValidationMethod::TrustedSource => 0.5,
        }
    }
}

/// Additional validation metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationMetadata {
    /// Time taken to validate (ms)
    pub validation_time_ms: u64,
    /// Number of bytes verified
    pub bytes_verified: u64,
    /// Sample rate (for sampling method)
    pub sample_rate: Option<f64>,
    /// Any additional notes
    pub notes: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_chunk_id() -> ChunkId {
        ChunkId::from_data(&[1, 2, 3, 4])
    }

    #[test]
    fn test_validation_result() {
        let chunk_id = test_chunk_id();

        let success = ValidationResult::success(chunk_id.clone());
        assert!(success.is_valid);
        assert!(success.hash_verified);

        let failure = ValidationResult::failure(chunk_id.clone(), "Test error".to_string());
        assert!(!failure.is_valid);
        assert!(failure.error.is_some());

        let hash_mismatch = ValidationResult::hash_mismatch(chunk_id);
        assert!(!hash_mismatch.is_valid);
        assert!(!hash_mismatch.hash_verified);
    }

    #[test]
    fn test_chunk_validation() {
        let chunk_id = test_chunk_id();

        let valid = ChunkValidation::valid(chunk_id.clone());
        assert!(valid.is_valid());
        assert_eq!(valid.confidence, 1.0);

        let invalid = ChunkValidation::invalid(chunk_id, "Bad data".to_string());
        assert!(!invalid.is_valid());
    }
}
