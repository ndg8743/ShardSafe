//! Schema Module - Concordia-Inspired Protocol Definition
//!
//! Implements a schema-driven approach to protocol messages, inspired by
//! Concordia's IL-based serialization framework. Key concepts:
//!
//! 1. **Schema Definition** - Type-safe message definitions with validation
//! 2. **Hot-Reloadable Rules** - Authority and consensus rules as bytecode
//! 3. **Expression Evaluation** - Stack-based computation for dynamic scoring
//! 4. **Validation Decorators** - @const, @range, @hash checks on fields

pub mod types;
pub mod rules;
pub mod expr;
pub mod validation;
pub mod codec;

pub use types::{SchemaType, Field, FieldType, Message, MessageSchema};
pub use rules::{RuleEngine, Rule, RuleSet, RuleContext};
pub use expr::{ExprVM, Opcode, Value, ExprError};
pub use validation::{Validator, ValidationRule, ValidationResult as SchemaValidationResult};
pub use codec::{Codec, CodecError, EncodeContext, DecodeContext};
