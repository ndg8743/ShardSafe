//! Schema Types - Message and Field Definitions
//!
//! Defines the type system for network messages, inspired by Concordia's
//! packet and struct definitions.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Primitive types supported in schemas
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PrimitiveType {
    Bool,
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
}

impl PrimitiveType {
    /// Size in bytes
    pub fn size(&self) -> usize {
        match self {
            PrimitiveType::Bool | PrimitiveType::U8 | PrimitiveType::I8 => 1,
            PrimitiveType::U16 | PrimitiveType::I16 => 2,
            PrimitiveType::U32 | PrimitiveType::I32 | PrimitiveType::F32 => 4,
            PrimitiveType::U64 | PrimitiveType::I64 | PrimitiveType::F64 => 8,
        }
    }

    /// Size in bits
    pub fn bit_size(&self) -> usize {
        self.size() * 8
    }
}

/// Field type in a schema
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FieldType {
    /// Primitive type
    Primitive(PrimitiveType),
    /// Fixed-size byte array
    Bytes(usize),
    /// Variable-length byte array with length prefix type
    VarBytes(PrimitiveType),
    /// Null-terminated string
    StringNull,
    /// Length-prefixed string
    StringPrefix(PrimitiveType),
    /// Fixed-size array of primitives
    Array(PrimitiveType, usize),
    /// Variable-length array with length prefix
    VarArray(PrimitiveType, PrimitiveType),
    /// Nested struct reference
    Struct(String),
    /// Bitfield (base type, bit count)
    Bitfield(PrimitiveType, u8),
    /// Enum with named values
    Enum(String),
    /// Peer ID (32-byte public key hash)
    PeerId,
    /// Chunk ID (32-byte BLAKE3 hash)
    ChunkId,
    /// Optional field (present if flag is set)
    Optional(Box<FieldType>),
}

impl FieldType {
    /// Check if type has fixed size
    pub fn is_fixed_size(&self) -> bool {
        match self {
            FieldType::Primitive(_) => true,
            FieldType::Bytes(_) => true,
            FieldType::Array(_, _) => true,
            FieldType::Bitfield(_, _) => true,
            FieldType::PeerId => true,
            FieldType::ChunkId => true,
            _ => false,
        }
    }

    /// Get fixed size if applicable
    pub fn fixed_size(&self) -> Option<usize> {
        match self {
            FieldType::Primitive(p) => Some(p.size()),
            FieldType::Bytes(n) => Some(*n),
            FieldType::Array(p, n) => Some(p.size() * n),
            FieldType::PeerId => Some(32),
            FieldType::ChunkId => Some(32),
            _ => None,
        }
    }
}

/// Validation decorator on a field (inspired by Concordia's @const, @range, etc.)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FieldDecorator {
    /// Constant value that must match
    Const(u64),
    /// Range constraint (min, max inclusive)
    Range(i64, i64),
    /// Hash verification (field contains hash of another field)
    Hash(String),
    /// CRC check over preceding fields
    Crc(u8), // CRC width
    /// Expression that must evaluate to true
    Expr(String),
    /// Optional - field may be absent
    Optional,
    /// Default value if not present
    Default(u64),
    /// Scale factor (value = raw * scale)
    Scale(f64),
    /// Offset (value = raw + offset)
    Offset(f64),
    /// Documentation comment
    Doc(String),
}

/// A field in a message or struct
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Field {
    /// Field name
    pub name: String,
    /// Field type
    pub field_type: FieldType,
    /// Validation decorators
    pub decorators: Vec<FieldDecorator>,
    /// Field ID for callback (like Concordia's key_id)
    pub field_id: u16,
}

impl Field {
    /// Create a new primitive field
    pub fn primitive(name: &str, ptype: PrimitiveType) -> Self {
        Self {
            name: name.to_string(),
            field_type: FieldType::Primitive(ptype),
            decorators: Vec::new(),
            field_id: 0,
        }
    }

    /// Add a const decorator
    pub fn with_const(mut self, value: u64) -> Self {
        self.decorators.push(FieldDecorator::Const(value));
        self
    }

    /// Add a range decorator
    pub fn with_range(mut self, min: i64, max: i64) -> Self {
        self.decorators.push(FieldDecorator::Range(min, max));
        self
    }

    /// Add documentation
    pub fn with_doc(mut self, doc: &str) -> Self {
        self.decorators.push(FieldDecorator::Doc(doc.to_string()));
        self
    }

    /// Check if field is optional
    pub fn is_optional(&self) -> bool {
        self.decorators.iter().any(|d| matches!(d, FieldDecorator::Optional))
    }

    /// Get const value if present
    pub fn const_value(&self) -> Option<u64> {
        self.decorators.iter().find_map(|d| {
            if let FieldDecorator::Const(v) = d {
                Some(*v)
            } else {
                None
            }
        })
    }
}

/// A message schema (equivalent to Concordia's packet)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Message name/type
    pub name: String,
    /// Message type ID (for protocol dispatch)
    pub type_id: u16,
    /// Fields in order
    pub fields: Vec<Field>,
    /// Version number
    pub version: u16,
}

impl Message {
    /// Create a new message
    pub fn new(name: &str, type_id: u16) -> Self {
        Self {
            name: name.to_string(),
            type_id,
            fields: Vec::new(),
            version: 1,
        }
    }

    /// Add a field
    pub fn field(mut self, field: Field) -> Self {
        self.fields.push(field);
        self
    }

    /// Get field by name
    pub fn get_field(&self, name: &str) -> Option<&Field> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// Calculate minimum size (fixed fields only)
    pub fn min_size(&self) -> usize {
        self.fields
            .iter()
            .filter_map(|f| f.field_type.fixed_size())
            .sum()
    }
}

/// Complete schema containing all message types
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MessageSchema {
    /// Schema name
    pub name: String,
    /// Schema version
    pub version: u16,
    /// All message types
    pub messages: HashMap<String, Message>,
    /// Struct definitions
    pub structs: HashMap<String, Message>,
    /// Enum definitions
    pub enums: HashMap<String, EnumDef>,
}

impl MessageSchema {
    /// Create a new schema
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            version: 1,
            messages: HashMap::new(),
            structs: HashMap::new(),
            enums: HashMap::new(),
        }
    }

    /// Add a message
    pub fn add_message(&mut self, message: Message) {
        self.messages.insert(message.name.clone(), message);
    }

    /// Add a struct
    pub fn add_struct(&mut self, s: Message) {
        self.structs.insert(s.name.clone(), s);
    }

    /// Add an enum
    pub fn add_enum(&mut self, e: EnumDef) {
        self.enums.insert(e.name.clone(), e);
    }

    /// Get message by name
    pub fn get_message(&self, name: &str) -> Option<&Message> {
        self.messages.get(name)
    }

    /// Get message by type ID
    pub fn get_message_by_id(&self, type_id: u16) -> Option<&Message> {
        self.messages.values().find(|m| m.type_id == type_id)
    }
}

/// Enum definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumDef {
    /// Enum name
    pub name: String,
    /// Base type
    pub base_type: PrimitiveType,
    /// Variants (name -> value)
    pub variants: HashMap<String, u64>,
}

impl EnumDef {
    /// Create a new enum
    pub fn new(name: &str, base_type: PrimitiveType) -> Self {
        Self {
            name: name.to_string(),
            base_type,
            variants: HashMap::new(),
        }
    }

    /// Add a variant
    pub fn variant(mut self, name: &str, value: u64) -> Self {
        self.variants.insert(name.to_string(), value);
        self
    }

    /// Check if value is valid
    pub fn is_valid(&self, value: u64) -> bool {
        self.variants.values().any(|&v| v == value)
    }

    /// Get variant name for value
    pub fn variant_name(&self, value: u64) -> Option<&str> {
        self.variants
            .iter()
            .find(|(_, &v)| v == value)
            .map(|(k, _)| k.as_str())
    }
}

/// Schema type alias for external use
pub type SchemaType = MessageSchema;

/// Create the ShardSafe protocol schema
pub fn shardsafe_schema() -> MessageSchema {
    let mut schema = MessageSchema::new("shardsafe");
    schema.version = 1;

    // Message type enum
    let msg_type = EnumDef::new("MessageType", PrimitiveType::U8)
        .variant("ChunkRequest", 0x01)
        .variant("ChunkResponse", 0x02)
        .variant("ChunkStore", 0x03)
        .variant("ChunkStored", 0x04)
        .variant("ChunkHas", 0x05)
        .variant("ChunkHasResult", 0x06)
        .variant("AuthorityQuery", 0x10)
        .variant("AuthorityResponse", 0x11)
        .variant("ValidationVote", 0x20)
        .variant("ConsensusResult", 0x21)
        .variant("Error", 0xFF);
    schema.add_enum(msg_type);

    // Chunk request message
    let chunk_request = Message::new("ChunkRequest", 0x01)
        .field(Field::primitive("type", PrimitiveType::U8).with_const(0x01))
        .field(Field {
            name: "chunk_id".to_string(),
            field_type: FieldType::ChunkId,
            decorators: vec![FieldDecorator::Doc("32-byte BLAKE3 hash".to_string())],
            field_id: 1,
        });
    schema.add_message(chunk_request);

    // Chunk response message
    let chunk_response = Message::new("ChunkResponse", 0x02)
        .field(Field::primitive("type", PrimitiveType::U8).with_const(0x02))
        .field(Field {
            name: "chunk_id".to_string(),
            field_type: FieldType::ChunkId,
            decorators: vec![],
            field_id: 1,
        })
        .field(Field {
            name: "data".to_string(),
            field_type: FieldType::VarBytes(PrimitiveType::U32),
            decorators: vec![FieldDecorator::Doc("Chunk data with 4-byte length prefix".to_string())],
            field_id: 2,
        });
    schema.add_message(chunk_response);

    // Authority query message
    let auth_query = Message::new("AuthorityQuery", 0x10)
        .field(Field::primitive("type", PrimitiveType::U8).with_const(0x10))
        .field(Field::primitive("top_n", PrimitiveType::U8).with_range(1, 100));
    schema.add_message(auth_query);

    // Authority response message
    let auth_response = Message::new("AuthorityResponse", 0x11)
        .field(Field::primitive("type", PrimitiveType::U8).with_const(0x11))
        .field(Field {
            name: "authorities".to_string(),
            field_type: FieldType::VarArray(PrimitiveType::U8, PrimitiveType::U8),
            decorators: vec![FieldDecorator::Doc("List of (PeerId, score) pairs".to_string())],
            field_id: 1,
        });
    schema.add_message(auth_response);

    // Validation vote message
    let validation_vote = Message::new("ValidationVote", 0x20)
        .field(Field::primitive("type", PrimitiveType::U8).with_const(0x20))
        .field(Field {
            name: "chunk_id".to_string(),
            field_type: FieldType::ChunkId,
            decorators: vec![],
            field_id: 1,
        })
        .field(Field::primitive("is_valid", PrimitiveType::Bool))
        .field(Field::primitive("confidence", PrimitiveType::F32).with_range(0, 1))
        .field(Field::primitive("timestamp", PrimitiveType::U64));
    schema.add_message(validation_vote);

    schema
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_primitive_sizes() {
        assert_eq!(PrimitiveType::U8.size(), 1);
        assert_eq!(PrimitiveType::U32.size(), 4);
        assert_eq!(PrimitiveType::F64.size(), 8);
    }

    #[test]
    fn test_field_creation() {
        let field = Field::primitive("version", PrimitiveType::U16)
            .with_const(1)
            .with_doc("Protocol version");

        assert_eq!(field.name, "version");
        assert!(field.const_value().is_some());
        assert_eq!(field.const_value().unwrap(), 1);
    }

    #[test]
    fn test_schema_creation() {
        let schema = shardsafe_schema();
        assert!(!schema.messages.is_empty());
        assert!(schema.get_message("ChunkRequest").is_some());
        assert!(schema.get_message_by_id(0x01).is_some());
    }

    #[test]
    fn test_enum_validation() {
        let msg_type = EnumDef::new("Test", PrimitiveType::U8)
            .variant("A", 1)
            .variant("B", 2);

        assert!(msg_type.is_valid(1));
        assert!(msg_type.is_valid(2));
        assert!(!msg_type.is_valid(3));
        assert_eq!(msg_type.variant_name(1), Some("A"));
    }
}
