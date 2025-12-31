//! Zero-Copy Codec - Concordia-Inspired Callback-Based IO
//!
//! This module provides a zero-copy serialization framework inspired by
//! Concordia's callback-based IO pattern. Key features:
//!
//! - Zero-copy where possible (borrowed slices)
//! - Bit-level field support for compact wire formats
//! - Configurable endianness
//! - Type-safe encode/decode traits

use std::fmt;
use thiserror::Error;

use crate::crypto::hashing::ChunkId;

// ============================================================================
// Endianness
// ============================================================================

/// Byte order for multi-byte values
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Endian {
    /// Big-endian (network byte order)
    Big,
    /// Little-endian
    #[default]
    Little,
    /// Native endianness of the platform
    Native,
}

impl Endian {
    /// Check if this is effectively little-endian on the current platform
    #[inline]
    pub fn is_little(self) -> bool {
        match self {
            Endian::Big => false,
            Endian::Little => true,
            Endian::Native => cfg!(target_endian = "little"),
        }
    }

    /// Check if this is effectively big-endian on the current platform
    #[inline]
    pub fn is_big(self) -> bool {
        !self.is_little()
    }
}

// ============================================================================
// Codec Errors
// ============================================================================

/// Errors that can occur during encoding/decoding
#[derive(Error, Debug, Clone, PartialEq)]
pub enum CodecError {
    /// Buffer does not have enough space for encoding
    #[error("buffer overflow: need {needed} bytes, have {available}")]
    BufferOverflow { needed: usize, available: usize },

    /// Not enough data in buffer to decode
    #[error("buffer underflow: need {needed} bytes, have {available}")]
    BufferUnderflow { needed: usize, available: usize },

    /// Data does not represent a valid value
    #[error("invalid data: {0}")]
    InvalidData(String),

    /// Validation constraint failed
    #[error("validation failed: {0}")]
    ValidationFailed(String),
}

/// Result type for codec operations
pub type CodecResult<T> = Result<T, CodecError>;

// ============================================================================
// Encode Context
// ============================================================================

/// Context for encoding operations
///
/// Provides a mutable buffer and cursor for zero-copy serialization.
/// Supports bit-level operations for compact wire formats.
pub struct EncodeContext<'a> {
    /// Mutable buffer to write into
    buffer: &'a mut [u8],
    /// Current byte position in buffer
    cursor: usize,
    /// Current bit offset within current byte (0-7)
    bit_offset: u8,
    /// Byte order for multi-byte values
    endianness: Endian,
}

impl<'a> EncodeContext<'a> {
    /// Create a new encode context with the given buffer
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self {
            buffer,
            cursor: 0,
            bit_offset: 0,
            endianness: Endian::Little,
        }
    }

    /// Create a new encode context with specified endianness
    pub fn with_endian(buffer: &'a mut [u8], endianness: Endian) -> Self {
        Self {
            buffer,
            cursor: 0,
            bit_offset: 0,
            endianness,
        }
    }

    /// Get current cursor position (bytes written)
    #[inline]
    pub fn position(&self) -> usize {
        self.cursor
    }

    /// Get current bit offset
    #[inline]
    pub fn bit_offset(&self) -> u8 {
        self.bit_offset
    }

    /// Get remaining capacity in bytes
    #[inline]
    pub fn remaining(&self) -> usize {
        self.buffer.len().saturating_sub(self.cursor)
    }

    /// Get the endianness setting
    #[inline]
    pub fn endianness(&self) -> Endian {
        self.endianness
    }

    /// Set the endianness
    pub fn set_endianness(&mut self, endian: Endian) {
        self.endianness = endian;
    }

    /// Align to byte boundary, advancing if currently mid-byte
    pub fn align_to_byte(&mut self) {
        if self.bit_offset > 0 {
            self.cursor += 1;
            self.bit_offset = 0;
        }
    }

    /// Write raw bytes to the buffer
    pub fn write_bytes(&mut self, data: &[u8]) -> CodecResult<usize> {
        // Align to byte boundary first
        self.align_to_byte();

        let len = data.len();
        if self.remaining() < len {
            return Err(CodecError::BufferOverflow {
                needed: len,
                available: self.remaining(),
            });
        }

        self.buffer[self.cursor..self.cursor + len].copy_from_slice(data);
        self.cursor += len;
        Ok(len)
    }

    /// Write a single byte
    #[inline]
    pub fn write_byte(&mut self, byte: u8) -> CodecResult<usize> {
        self.align_to_byte();

        if self.remaining() < 1 {
            return Err(CodecError::BufferOverflow {
                needed: 1,
                available: 0,
            });
        }

        self.buffer[self.cursor] = byte;
        self.cursor += 1;
        Ok(1)
    }

    /// Write bits to the buffer (for bitfield support)
    ///
    /// Writes `bit_count` bits from the low bits of `value`.
    pub fn write_bits(&mut self, value: u64, bit_count: u8) -> CodecResult<usize> {
        if bit_count == 0 || bit_count > 64 {
            return Err(CodecError::InvalidData(format!(
                "bit_count must be 1-64, got {}",
                bit_count
            )));
        }

        let mut bits_remaining = bit_count;
        let mut val = value;
        let mut bytes_written = 0;

        while bits_remaining > 0 {
            // Ensure we have space
            if self.cursor >= self.buffer.len() {
                return Err(CodecError::BufferOverflow {
                    needed: 1,
                    available: 0,
                });
            }

            // How many bits can we write to the current byte?
            let bits_in_byte = (8 - self.bit_offset).min(bits_remaining);

            // Extract the bits we want to write
            let mask = (1u64 << bits_in_byte) - 1;
            let bits_to_write = (val & mask) as u8;

            // Write to the buffer
            if self.bit_offset == 0 {
                self.buffer[self.cursor] = 0;
            }
            self.buffer[self.cursor] |= bits_to_write << self.bit_offset;

            // Advance
            val >>= bits_in_byte;
            bits_remaining -= bits_in_byte;
            self.bit_offset += bits_in_byte;

            if self.bit_offset >= 8 {
                self.bit_offset = 0;
                self.cursor += 1;
                bytes_written += 1;
            }
        }

        // Count partial byte
        if self.bit_offset > 0 {
            bytes_written += 1;
        }

        Ok(bytes_written)
    }

    /// Get a reference to the written portion of the buffer
    pub fn written(&self) -> &[u8] {
        let end = if self.bit_offset > 0 {
            self.cursor + 1
        } else {
            self.cursor
        };
        &self.buffer[..end]
    }
}

impl fmt::Debug for EncodeContext<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncodeContext")
            .field("cursor", &self.cursor)
            .field("bit_offset", &self.bit_offset)
            .field("endianness", &self.endianness)
            .field("remaining", &self.remaining())
            .finish()
    }
}

// ============================================================================
// Decode Context
// ============================================================================

/// Context for decoding operations
///
/// Provides an immutable buffer and cursor for zero-copy deserialization.
/// Supports bit-level operations for compact wire formats.
pub struct DecodeContext<'a> {
    /// Immutable buffer to read from
    buffer: &'a [u8],
    /// Current byte position in buffer
    cursor: usize,
    /// Current bit offset within current byte (0-7)
    bit_offset: u8,
    /// Byte order for multi-byte values
    endianness: Endian,
}

impl<'a> DecodeContext<'a> {
    /// Create a new decode context with the given buffer
    pub fn new(buffer: &'a [u8]) -> Self {
        Self {
            buffer,
            cursor: 0,
            bit_offset: 0,
            endianness: Endian::Little,
        }
    }

    /// Create a new decode context with specified endianness
    pub fn with_endian(buffer: &'a [u8], endianness: Endian) -> Self {
        Self {
            buffer,
            cursor: 0,
            bit_offset: 0,
            endianness,
        }
    }

    /// Get current cursor position (bytes read)
    #[inline]
    pub fn position(&self) -> usize {
        self.cursor
    }

    /// Get current bit offset
    #[inline]
    pub fn bit_offset(&self) -> u8 {
        self.bit_offset
    }

    /// Get remaining bytes to read
    #[inline]
    pub fn remaining(&self) -> usize {
        self.buffer.len().saturating_sub(self.cursor)
    }

    /// Get the endianness setting
    #[inline]
    pub fn endianness(&self) -> Endian {
        self.endianness
    }

    /// Set the endianness
    pub fn set_endianness(&mut self, endian: Endian) {
        self.endianness = endian;
    }

    /// Align to byte boundary, advancing if currently mid-byte
    pub fn align_to_byte(&mut self) {
        if self.bit_offset > 0 {
            self.cursor += 1;
            self.bit_offset = 0;
        }
    }

    /// Read raw bytes from the buffer (zero-copy slice)
    pub fn read_bytes(&mut self, len: usize) -> CodecResult<&'a [u8]> {
        self.align_to_byte();

        if self.remaining() < len {
            return Err(CodecError::BufferUnderflow {
                needed: len,
                available: self.remaining(),
            });
        }

        let slice = &self.buffer[self.cursor..self.cursor + len];
        self.cursor += len;
        Ok(slice)
    }

    /// Read a single byte
    #[inline]
    pub fn read_byte(&mut self) -> CodecResult<u8> {
        self.align_to_byte();

        if self.remaining() < 1 {
            return Err(CodecError::BufferUnderflow {
                needed: 1,
                available: 0,
            });
        }

        let byte = self.buffer[self.cursor];
        self.cursor += 1;
        Ok(byte)
    }

    /// Read bits from the buffer (for bitfield support)
    ///
    /// Returns `bit_count` bits as a u64.
    pub fn read_bits(&mut self, bit_count: u8) -> CodecResult<u64> {
        if bit_count == 0 || bit_count > 64 {
            return Err(CodecError::InvalidData(format!(
                "bit_count must be 1-64, got {}",
                bit_count
            )));
        }

        let mut result: u64 = 0;
        let mut bits_remaining = bit_count;
        let mut result_offset: u8 = 0;

        while bits_remaining > 0 {
            if self.cursor >= self.buffer.len() {
                return Err(CodecError::BufferUnderflow {
                    needed: 1,
                    available: 0,
                });
            }

            // How many bits can we read from the current byte?
            let bits_in_byte = (8 - self.bit_offset).min(bits_remaining);

            // Extract bits from buffer
            let mask = ((1u16 << bits_in_byte) - 1) as u8;
            let bits_read = (self.buffer[self.cursor] >> self.bit_offset) & mask;

            // Add to result
            result |= (bits_read as u64) << result_offset;

            // Advance
            bits_remaining -= bits_in_byte;
            result_offset += bits_in_byte;
            self.bit_offset += bits_in_byte;

            if self.bit_offset >= 8 {
                self.bit_offset = 0;
                self.cursor += 1;
            }
        }

        Ok(result)
    }

    /// Peek at the next byte without consuming it
    pub fn peek_byte(&self) -> CodecResult<u8> {
        let pos = if self.bit_offset > 0 {
            self.cursor + 1
        } else {
            self.cursor
        };

        if pos >= self.buffer.len() {
            return Err(CodecError::BufferUnderflow {
                needed: 1,
                available: 0,
            });
        }

        Ok(self.buffer[pos])
    }

    /// Get a reference to the remaining buffer
    pub fn remaining_buffer(&self) -> &'a [u8] {
        let start = if self.bit_offset > 0 {
            self.cursor + 1
        } else {
            self.cursor
        };
        &self.buffer[start..]
    }
}

impl fmt::Debug for DecodeContext<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecodeContext")
            .field("cursor", &self.cursor)
            .field("bit_offset", &self.bit_offset)
            .field("endianness", &self.endianness)
            .field("remaining", &self.remaining())
            .finish()
    }
}

// ============================================================================
// Codec Trait
// ============================================================================

/// Trait for types that can be encoded to and decoded from binary
///
/// Inspired by Concordia's callback-based IO, this trait enables
/// zero-copy serialization where possible.
pub trait Codec: Sized {
    /// Encode this value into the context buffer
    ///
    /// Returns the number of bytes written on success.
    fn encode(&self, ctx: &mut EncodeContext) -> CodecResult<usize>;

    /// Decode a value from the context buffer
    fn decode(ctx: &mut DecodeContext) -> CodecResult<Self>;

    /// Get the encoded size of this value (if known statically)
    fn encoded_size(&self) -> Option<usize> {
        None
    }
}

// ============================================================================
// Primitive Type Implementations
// ============================================================================

/// Helper macro for implementing Codec on integer types
macro_rules! impl_codec_int {
    ($ty:ty, $size:expr) => {
        impl Codec for $ty {
            fn encode(&self, ctx: &mut EncodeContext) -> CodecResult<usize> {
                let bytes = if ctx.endianness().is_little() {
                    self.to_le_bytes()
                } else {
                    self.to_be_bytes()
                };
                ctx.write_bytes(&bytes)
            }

            fn decode(ctx: &mut DecodeContext) -> CodecResult<Self> {
                let bytes = ctx.read_bytes($size)?;
                let arr: [u8; $size] = bytes.try_into().unwrap();
                Ok(if ctx.endianness().is_little() {
                    Self::from_le_bytes(arr)
                } else {
                    Self::from_be_bytes(arr)
                })
            }

            fn encoded_size(&self) -> Option<usize> {
                Some($size)
            }
        }
    };
}

impl_codec_int!(u8, 1);
impl_codec_int!(u16, 2);
impl_codec_int!(u32, 4);
impl_codec_int!(u64, 8);
impl_codec_int!(i8, 1);
impl_codec_int!(i16, 2);
impl_codec_int!(i32, 4);
impl_codec_int!(i64, 8);

// Floating point types
impl Codec for f32 {
    fn encode(&self, ctx: &mut EncodeContext) -> CodecResult<usize> {
        let bytes = if ctx.endianness().is_little() {
            self.to_le_bytes()
        } else {
            self.to_be_bytes()
        };
        ctx.write_bytes(&bytes)
    }

    fn decode(ctx: &mut DecodeContext) -> CodecResult<Self> {
        let bytes = ctx.read_bytes(4)?;
        let arr: [u8; 4] = bytes.try_into().unwrap();
        Ok(if ctx.endianness().is_little() {
            f32::from_le_bytes(arr)
        } else {
            f32::from_be_bytes(arr)
        })
    }

    fn encoded_size(&self) -> Option<usize> {
        Some(4)
    }
}

impl Codec for f64 {
    fn encode(&self, ctx: &mut EncodeContext) -> CodecResult<usize> {
        let bytes = if ctx.endianness().is_little() {
            self.to_le_bytes()
        } else {
            self.to_be_bytes()
        };
        ctx.write_bytes(&bytes)
    }

    fn decode(ctx: &mut DecodeContext) -> CodecResult<Self> {
        let bytes = ctx.read_bytes(8)?;
        let arr: [u8; 8] = bytes.try_into().unwrap();
        Ok(if ctx.endianness().is_little() {
            f64::from_le_bytes(arr)
        } else {
            f64::from_be_bytes(arr)
        })
    }

    fn encoded_size(&self) -> Option<usize> {
        Some(8)
    }
}

// Boolean
impl Codec for bool {
    fn encode(&self, ctx: &mut EncodeContext) -> CodecResult<usize> {
        ctx.write_byte(if *self { 1 } else { 0 })
    }

    fn decode(ctx: &mut DecodeContext) -> CodecResult<Self> {
        let byte = ctx.read_byte()?;
        match byte {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(CodecError::InvalidData(format!(
                "invalid boolean value: {}",
                byte
            ))),
        }
    }

    fn encoded_size(&self) -> Option<usize> {
        Some(1)
    }
}

// ============================================================================
// Variable-Length Types
// ============================================================================

/// Vec<u8> with u32 length prefix
impl Codec for Vec<u8> {
    fn encode(&self, ctx: &mut EncodeContext) -> CodecResult<usize> {
        let len = self.len();
        if len > u32::MAX as usize {
            return Err(CodecError::InvalidData(format!(
                "byte vector too large: {} bytes",
                len
            )));
        }

        let mut written = (len as u32).encode(ctx)?;
        written += ctx.write_bytes(self)?;
        Ok(written)
    }

    fn decode(ctx: &mut DecodeContext) -> CodecResult<Self> {
        let len = u32::decode(ctx)? as usize;
        let bytes = ctx.read_bytes(len)?;
        Ok(bytes.to_vec())
    }

    fn encoded_size(&self) -> Option<usize> {
        Some(4 + self.len())
    }
}

/// String with u32 length prefix (UTF-8)
impl Codec for String {
    fn encode(&self, ctx: &mut EncodeContext) -> CodecResult<usize> {
        let bytes = self.as_bytes();
        let len = bytes.len();
        if len > u32::MAX as usize {
            return Err(CodecError::InvalidData(format!(
                "string too large: {} bytes",
                len
            )));
        }

        let mut written = (len as u32).encode(ctx)?;
        written += ctx.write_bytes(bytes)?;
        Ok(written)
    }

    fn decode(ctx: &mut DecodeContext) -> CodecResult<Self> {
        let len = u32::decode(ctx)? as usize;
        let bytes = ctx.read_bytes(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|e| {
            CodecError::InvalidData(format!("invalid UTF-8 string: {}", e))
        })
    }

    fn encoded_size(&self) -> Option<usize> {
        Some(4 + self.len())
    }
}

// ============================================================================
// ChunkId (32-byte fixed)
// ============================================================================

impl Codec for ChunkId {
    fn encode(&self, ctx: &mut EncodeContext) -> CodecResult<usize> {
        ctx.write_bytes(self.as_bytes())
    }

    fn decode(ctx: &mut DecodeContext) -> CodecResult<Self> {
        let bytes = ctx.read_bytes(32)?;
        let arr: [u8; 32] = bytes.try_into().unwrap();
        Ok(ChunkId::from_bytes(arr))
    }

    fn encoded_size(&self) -> Option<usize> {
        Some(32)
    }
}

// ============================================================================
// Helper Macros
// ============================================================================

/// Encode multiple values sequentially
#[macro_export]
macro_rules! encode_all {
    ($ctx:expr, $($value:expr),+ $(,)?) => {{
        let mut total = 0usize;
        $(
            total += $crate::schema::codec::Codec::encode(&$value, $ctx)?;
        )+
        Ok::<usize, $crate::schema::codec::CodecError>(total)
    }};
}

/// Decode multiple values sequentially
#[macro_export]
macro_rules! decode_all {
    ($ctx:expr, $($ty:ty),+ $(,)?) => {{
        (
            $(
                <$ty as $crate::schema::codec::Codec>::decode($ctx)?,
            )+
        )
    }};
}

// ============================================================================
// Fixed-Size Array Support
// ============================================================================

/// Implement Codec for fixed-size byte arrays
macro_rules! impl_codec_byte_array {
    ($size:expr) => {
        impl Codec for [u8; $size] {
            fn encode(&self, ctx: &mut EncodeContext) -> CodecResult<usize> {
                ctx.write_bytes(self)
            }

            fn decode(ctx: &mut DecodeContext) -> CodecResult<Self> {
                let bytes = ctx.read_bytes($size)?;
                Ok(bytes.try_into().unwrap())
            }

            fn encoded_size(&self) -> Option<usize> {
                Some($size)
            }
        }
    };
}

// Common fixed-size arrays
impl_codec_byte_array!(16);
impl_codec_byte_array!(32);
impl_codec_byte_array!(64);
impl_codec_byte_array!(128);
impl_codec_byte_array!(256);

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Primitive roundtrip tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_u8_roundtrip() {
        let mut buf = [0u8; 16];
        let value: u8 = 0xAB;

        let mut enc = EncodeContext::new(&mut buf);
        value.encode(&mut enc).unwrap();
        assert_eq!(enc.position(), 1);

        let mut dec = DecodeContext::new(&buf);
        let decoded = u8::decode(&mut dec).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_u16_roundtrip_le() {
        let mut buf = [0u8; 16];
        let value: u16 = 0x1234;

        let mut enc = EncodeContext::new(&mut buf);
        value.encode(&mut enc).unwrap();
        assert_eq!(enc.position(), 2);
        assert_eq!(&buf[..2], &[0x34, 0x12]); // Little-endian

        let mut dec = DecodeContext::new(&buf);
        let decoded = u16::decode(&mut dec).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_u16_roundtrip_be() {
        let mut buf = [0u8; 16];
        let value: u16 = 0x1234;

        let mut enc = EncodeContext::with_endian(&mut buf, Endian::Big);
        value.encode(&mut enc).unwrap();
        assert_eq!(&buf[..2], &[0x12, 0x34]); // Big-endian

        let mut dec = DecodeContext::with_endian(&buf, Endian::Big);
        let decoded = u16::decode(&mut dec).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_u32_roundtrip() {
        let mut buf = [0u8; 16];
        let value: u32 = 0xDEADBEEF;

        let mut enc = EncodeContext::new(&mut buf);
        value.encode(&mut enc).unwrap();

        let mut dec = DecodeContext::new(&buf);
        let decoded = u32::decode(&mut dec).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_u64_roundtrip() {
        let mut buf = [0u8; 16];
        let value: u64 = 0x123456789ABCDEF0;

        let mut enc = EncodeContext::new(&mut buf);
        value.encode(&mut enc).unwrap();

        let mut dec = DecodeContext::new(&buf);
        let decoded = u64::decode(&mut dec).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_i8_roundtrip() {
        let mut buf = [0u8; 16];
        let value: i8 = -42;

        let mut enc = EncodeContext::new(&mut buf);
        value.encode(&mut enc).unwrap();

        let mut dec = DecodeContext::new(&buf);
        let decoded = i8::decode(&mut dec).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_i16_roundtrip() {
        let mut buf = [0u8; 16];
        let value: i16 = -1234;

        let mut enc = EncodeContext::new(&mut buf);
        value.encode(&mut enc).unwrap();

        let mut dec = DecodeContext::new(&buf);
        let decoded = i16::decode(&mut dec).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_i32_roundtrip() {
        let mut buf = [0u8; 16];
        let value: i32 = -123456789;

        let mut enc = EncodeContext::new(&mut buf);
        value.encode(&mut enc).unwrap();

        let mut dec = DecodeContext::new(&buf);
        let decoded = i32::decode(&mut dec).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_i64_roundtrip() {
        let mut buf = [0u8; 16];
        let value: i64 = -1234567890123456789;

        let mut enc = EncodeContext::new(&mut buf);
        value.encode(&mut enc).unwrap();

        let mut dec = DecodeContext::new(&buf);
        let decoded = i64::decode(&mut dec).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_f32_roundtrip() {
        let mut buf = [0u8; 16];
        let value: f32 = 3.14159;

        let mut enc = EncodeContext::new(&mut buf);
        value.encode(&mut enc).unwrap();

        let mut dec = DecodeContext::new(&buf);
        let decoded = f32::decode(&mut dec).unwrap();
        assert!((value - decoded).abs() < f32::EPSILON);
    }

    #[test]
    fn test_f64_roundtrip() {
        let mut buf = [0u8; 16];
        let value: f64 = 3.141592653589793;

        let mut enc = EncodeContext::new(&mut buf);
        value.encode(&mut enc).unwrap();

        let mut dec = DecodeContext::new(&buf);
        let decoded = f64::decode(&mut dec).unwrap();
        assert!((value - decoded).abs() < f64::EPSILON);
    }

    #[test]
    fn test_bool_roundtrip() {
        let mut buf = [0u8; 16];

        for value in [true, false] {
            let mut enc = EncodeContext::new(&mut buf);
            value.encode(&mut enc).unwrap();

            let mut dec = DecodeContext::new(&buf);
            let decoded = bool::decode(&mut dec).unwrap();
            assert_eq!(value, decoded);
        }
    }

    #[test]
    fn test_bool_invalid() {
        let buf = [2u8]; // Invalid boolean value
        let mut dec = DecodeContext::new(&buf);
        let result = bool::decode(&mut dec);
        assert!(matches!(result, Err(CodecError::InvalidData(_))));
    }

    // -------------------------------------------------------------------------
    // Variable-length type tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_vec_u8_roundtrip() {
        let mut buf = [0u8; 256];
        let value: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8];

        let mut enc = EncodeContext::new(&mut buf);
        let written = value.encode(&mut enc).unwrap();
        assert_eq!(written, 4 + 8); // 4-byte length + data

        let mut dec = DecodeContext::new(&buf);
        let decoded = Vec::<u8>::decode(&mut dec).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_vec_u8_empty() {
        let mut buf = [0u8; 16];
        let value: Vec<u8> = vec![];

        let mut enc = EncodeContext::new(&mut buf);
        value.encode(&mut enc).unwrap();

        let mut dec = DecodeContext::new(&buf);
        let decoded = Vec::<u8>::decode(&mut dec).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_string_roundtrip() {
        let mut buf = [0u8; 256];
        let value = String::from("Hello, ShardSafe!");

        let mut enc = EncodeContext::new(&mut buf);
        let written = value.encode(&mut enc).unwrap();
        assert_eq!(written, 4 + value.len());

        let mut dec = DecodeContext::new(&buf);
        let decoded = String::decode(&mut dec).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_string_unicode() {
        let mut buf = [0u8; 256];
        let value = String::from("Hello, world!");

        let mut enc = EncodeContext::new(&mut buf);
        value.encode(&mut enc).unwrap();

        let mut dec = DecodeContext::new(&buf);
        let decoded = String::decode(&mut dec).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    fn test_string_empty() {
        let mut buf = [0u8; 16];
        let value = String::new();

        let mut enc = EncodeContext::new(&mut buf);
        value.encode(&mut enc).unwrap();

        let mut dec = DecodeContext::new(&buf);
        let decoded = String::decode(&mut dec).unwrap();
        assert!(decoded.is_empty());
    }

    // -------------------------------------------------------------------------
    // ChunkId tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_chunk_id_roundtrip() {
        let mut buf = [0u8; 64];
        let data = b"test chunk data for hashing";
        let chunk_id = ChunkId::from_data(data);

        let mut enc = EncodeContext::new(&mut buf);
        let written = chunk_id.encode(&mut enc).unwrap();
        assert_eq!(written, 32);

        let mut dec = DecodeContext::new(&buf);
        let decoded = ChunkId::decode(&mut dec).unwrap();
        assert_eq!(chunk_id, decoded);
    }

    #[test]
    fn test_chunk_id_encoded_size() {
        let chunk_id = ChunkId::from_data(b"test");
        assert_eq!(chunk_id.encoded_size(), Some(32));
    }

    // -------------------------------------------------------------------------
    // Fixed-size array tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_byte_array_32_roundtrip() {
        let mut buf = [0u8; 64];
        let value: [u8; 32] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];

        let mut enc = EncodeContext::new(&mut buf);
        value.encode(&mut enc).unwrap();

        let mut dec = DecodeContext::new(&buf);
        let decoded = <[u8; 32]>::decode(&mut dec).unwrap();
        assert_eq!(value, decoded);
    }

    // -------------------------------------------------------------------------
    // Bit-level operations tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_write_bits_single_byte() {
        let mut buf = [0u8; 16];
        let mut enc = EncodeContext::new(&mut buf);

        // Write 4 bits (value 0b1010 = 10)
        enc.write_bits(0b1010, 4).unwrap();
        assert_eq!(enc.bit_offset(), 4);

        // Write another 4 bits (value 0b0101 = 5)
        enc.write_bits(0b0101, 4).unwrap();
        assert_eq!(enc.bit_offset(), 0);
        assert_eq!(enc.position(), 1);

        // Result should be 0b0101_1010 = 0x5A
        assert_eq!(buf[0], 0x5A);
    }

    #[test]
    fn test_read_bits_single_byte() {
        let buf = [0x5A]; // 0b0101_1010
        let mut dec = DecodeContext::new(&buf);

        // Read 4 bits
        let low = dec.read_bits(4).unwrap();
        assert_eq!(low, 0b1010);

        // Read 4 more bits
        let high = dec.read_bits(4).unwrap();
        assert_eq!(high, 0b0101);
    }

    #[test]
    fn test_bits_cross_byte() {
        let mut buf = [0u8; 16];
        let mut enc = EncodeContext::new(&mut buf);

        // Write 12 bits spanning 2 bytes
        enc.write_bits(0xABC, 12).unwrap();

        let mut dec = DecodeContext::new(&buf);
        let value = dec.read_bits(12).unwrap();
        assert_eq!(value, 0xABC);
    }

    // -------------------------------------------------------------------------
    // Error handling tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_buffer_overflow() {
        let mut buf = [0u8; 2];
        let value: u32 = 0x12345678;

        let mut enc = EncodeContext::new(&mut buf);
        let result = value.encode(&mut enc);
        assert!(matches!(result, Err(CodecError::BufferOverflow { .. })));
    }

    #[test]
    fn test_buffer_underflow() {
        let buf = [0u8; 2];
        let mut dec = DecodeContext::new(&buf);
        let result = u32::decode(&mut dec);
        assert!(matches!(result, Err(CodecError::BufferUnderflow { .. })));
    }

    // -------------------------------------------------------------------------
    // Multiple value encoding tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_multiple_values() {
        let mut buf = [0u8; 256];

        let v1: u8 = 0x01;
        let v2: u32 = 0xDEADBEEF;
        let v3 = String::from("test");
        let v4: bool = true;

        let mut enc = EncodeContext::new(&mut buf);
        v1.encode(&mut enc).unwrap();
        v2.encode(&mut enc).unwrap();
        v3.encode(&mut enc).unwrap();
        v4.encode(&mut enc).unwrap();

        let mut dec = DecodeContext::new(&buf);
        assert_eq!(u8::decode(&mut dec).unwrap(), v1);
        assert_eq!(u32::decode(&mut dec).unwrap(), v2);
        assert_eq!(String::decode(&mut dec).unwrap(), v3);
        assert_eq!(bool::decode(&mut dec).unwrap(), v4);
    }

    // -------------------------------------------------------------------------
    // Endianness tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_endian_detection() {
        assert!(Endian::Little.is_little());
        assert!(!Endian::Little.is_big());
        assert!(Endian::Big.is_big());
        assert!(!Endian::Big.is_little());
    }

    #[test]
    fn test_mixed_endian_encoding() {
        let mut buf = [0u8; 16];
        let value: u32 = 0x12345678;

        // Encode as big-endian
        let mut enc = EncodeContext::with_endian(&mut buf, Endian::Big);
        value.encode(&mut enc).unwrap();

        // Bytes should be in big-endian order
        assert_eq!(&buf[..4], &[0x12, 0x34, 0x56, 0x78]);

        // Decode with big-endian
        let mut dec = DecodeContext::with_endian(&buf, Endian::Big);
        let decoded = u32::decode(&mut dec).unwrap();
        assert_eq!(value, decoded);

        // Decoding with little-endian gives different result
        let mut dec_le = DecodeContext::new(&buf);
        let decoded_wrong = u32::decode(&mut dec_le).unwrap();
        assert_ne!(value, decoded_wrong);
    }

    // -------------------------------------------------------------------------
    // Context utility tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_context_written() {
        let mut buf = [0u8; 16];
        let mut enc = EncodeContext::new(&mut buf);

        42u32.encode(&mut enc).unwrap();
        let written = enc.written();
        assert_eq!(written.len(), 4);
    }

    #[test]
    fn test_context_remaining_buffer() {
        let buf = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut dec = DecodeContext::new(&buf);

        u32::decode(&mut dec).unwrap();
        let remaining = dec.remaining_buffer();
        assert_eq!(remaining, &[5, 6, 7, 8]);
    }

    #[test]
    fn test_peek_byte() {
        let buf = [0xAB, 0xCD];
        let dec = DecodeContext::new(&buf);

        assert_eq!(dec.peek_byte().unwrap(), 0xAB);
        assert_eq!(dec.position(), 0); // Position unchanged
    }

    #[test]
    fn test_align_to_byte() {
        let mut buf = [0u8; 16];
        let mut enc = EncodeContext::new(&mut buf);

        enc.write_bits(0b101, 3).unwrap();
        assert_eq!(enc.bit_offset(), 3);
        assert_eq!(enc.position(), 0);

        enc.align_to_byte();
        assert_eq!(enc.bit_offset(), 0);
        assert_eq!(enc.position(), 1);
    }
}
