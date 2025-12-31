//! Validation Framework - Concordia-Inspired Field Validation
//!
//! Implements a comprehensive validation system inspired by Concordia's
//! decorator-based validation (@const, @range, @crc, etc.). This module provides:
//!
//! - Field-level validation rules
//! - Message-level validation with detailed results
//! - Support for custom expression-based validation
//! - Hash verification between fields

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::schema::expr::{ExprContext, ExprVM, Value};

/// Validation rules that can be applied to fields
/// Inspired by Concordia's validation decorators
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ValidationRule {
    /// Value must equal a constant (@const decorator)
    Const(u64),

    /// Value must be within range [min, max] inclusive (@range decorator)
    Range(i64, i64),

    /// Field contains hash of another field's data (@hash decorator)
    /// The String is the name of the field being hashed
    Hash(String),

    /// Custom expression bytecode that must evaluate to true (@expr decorator)
    /// The bytecode is executed in the ExprVM
    Expr(Vec<u8>),

    /// Bytes or string field must not be empty
    NonEmpty,

    /// Maximum length for bytes/string/array fields
    MaxLen(usize),

    /// Minimum length for bytes/string/array fields
    MinLen(usize),

    /// String must match regex pattern
    Pattern(String),

    /// Value must be one of the specified values
    OneOf(Vec<i64>),

    /// Value must be a valid enum variant
    EnumVariant(String),

    /// Field must be present (not optional/missing)
    Required,

    /// CRC check over specified fields
    Crc {
        /// Field names to compute CRC over
        fields: Vec<String>,
        /// CRC width in bits (8, 16, 32)
        width: u8,
    },
}

impl ValidationRule {
    /// Create a const validation rule
    pub fn const_value(value: u64) -> Self {
        ValidationRule::Const(value)
    }

    /// Create a range validation rule
    pub fn range(min: i64, max: i64) -> Self {
        ValidationRule::Range(min, max)
    }

    /// Create a hash validation rule
    pub fn hash_of(field_name: &str) -> Self {
        ValidationRule::Hash(field_name.to_string())
    }

    /// Create an expression validation rule
    pub fn expr(bytecode: Vec<u8>) -> Self {
        ValidationRule::Expr(bytecode)
    }

    /// Create a pattern validation rule
    pub fn pattern(regex: &str) -> Self {
        ValidationRule::Pattern(regex.to_string())
    }

    /// Create a max length validation rule
    pub fn max_len(len: usize) -> Self {
        ValidationRule::MaxLen(len)
    }

    /// Create a min length validation rule
    pub fn min_len(len: usize) -> Self {
        ValidationRule::MinLen(len)
    }
}

/// Detailed error information for a validation failure
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidationError {
    /// Name of the field that failed validation
    pub field: String,

    /// The rule that was violated
    pub rule: String,

    /// Human-readable error message
    pub message: String,

    /// Expected value or constraint (for display)
    pub expected: Option<String>,

    /// Actual value found (for display)
    pub actual: Option<String>,
}

impl ValidationError {
    /// Create a new validation error
    pub fn new(field: &str, rule: &str, message: &str) -> Self {
        Self {
            field: field.to_string(),
            rule: rule.to_string(),
            message: message.to_string(),
            expected: None,
            actual: None,
        }
    }

    /// Add expected value to error
    pub fn with_expected(mut self, expected: &str) -> Self {
        self.expected = Some(expected.to_string());
        self
    }

    /// Add actual value to error
    pub fn with_actual(mut self, actual: &str) -> Self {
        self.actual = Some(actual.to_string());
        self
    }
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Field '{}' failed {}: {}", self.field, self.rule, self.message)?;
        if let Some(ref expected) = self.expected {
            write!(f, " (expected: {})", expected)?;
        }
        if let Some(ref actual) = self.actual {
            write!(f, " (actual: {})", actual)?;
        }
        Ok(())
    }
}

impl std::error::Error for ValidationError {}

/// Result of validating a message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Whether the entire message is valid
    pub is_valid: bool,

    /// List of all validation errors
    pub errors: Vec<ValidationError>,

    /// Per-field validation status (true = passed, false = failed)
    pub field_results: HashMap<String, bool>,

    /// Fields that were validated
    pub validated_fields: Vec<String>,

    /// Fields that were skipped (not found in message)
    pub skipped_fields: Vec<String>,
}

impl ValidationResult {
    /// Create a successful validation result
    pub fn success() -> Self {
        Self {
            is_valid: true,
            errors: Vec::new(),
            field_results: HashMap::new(),
            validated_fields: Vec::new(),
            skipped_fields: Vec::new(),
        }
    }

    /// Create a failed validation result with errors
    pub fn failure(errors: Vec<ValidationError>) -> Self {
        let mut field_results = HashMap::new();
        for error in &errors {
            field_results.insert(error.field.clone(), false);
        }

        Self {
            is_valid: false,
            errors,
            field_results,
            validated_fields: Vec::new(),
            skipped_fields: Vec::new(),
        }
    }

    /// Add a field result
    pub fn add_field_result(&mut self, field: &str, passed: bool) {
        self.field_results.insert(field.to_string(), passed);
        self.validated_fields.push(field.to_string());
        if !passed {
            self.is_valid = false;
        }
    }

    /// Add an error
    pub fn add_error(&mut self, error: ValidationError) {
        self.field_results.insert(error.field.clone(), false);
        self.errors.push(error);
        self.is_valid = false;
    }

    /// Add a skipped field
    pub fn add_skipped(&mut self, field: &str) {
        self.skipped_fields.push(field.to_string());
    }

    /// Merge another validation result into this one
    pub fn merge(&mut self, other: ValidationResult) {
        if !other.is_valid {
            self.is_valid = false;
        }
        self.errors.extend(other.errors);
        self.field_results.extend(other.field_results);
        self.validated_fields.extend(other.validated_fields);
        self.skipped_fields.extend(other.skipped_fields);
    }

    /// Get count of passed fields
    pub fn passed_count(&self) -> usize {
        self.field_results.values().filter(|&&v| v).count()
    }

    /// Get count of failed fields
    pub fn failed_count(&self) -> usize {
        self.field_results.values().filter(|&&v| !v).count()
    }
}

impl Default for ValidationResult {
    fn default() -> Self {
        Self::success()
    }
}

/// A value that can be validated
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FieldValue {
    /// Integer value
    Int(i64),
    /// Unsigned integer value
    UInt(u64),
    /// Floating point value
    Float(f64),
    /// Boolean value
    Bool(bool),
    /// Byte array
    Bytes(Vec<u8>),
    /// String value
    String(String),
    /// Array of integers
    IntArray(Vec<i64>),
    /// Nested structure (field name -> value)
    Struct(HashMap<String, FieldValue>),
    /// Null/missing value
    Null,
}

impl FieldValue {
    /// Try to get as i64
    pub fn as_int(&self) -> Option<i64> {
        match self {
            FieldValue::Int(i) => Some(*i),
            FieldValue::UInt(u) => i64::try_from(*u).ok(),
            FieldValue::Float(f) => Some(*f as i64),
            FieldValue::Bool(b) => Some(*b as i64),
            _ => None,
        }
    }

    /// Try to get as u64
    pub fn as_uint(&self) -> Option<u64> {
        match self {
            FieldValue::Int(i) => u64::try_from(*i).ok(),
            FieldValue::UInt(u) => Some(*u),
            FieldValue::Float(f) => Some(*f as u64),
            FieldValue::Bool(b) => Some(*b as u64),
            _ => None,
        }
    }

    /// Try to get as bytes
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            FieldValue::Bytes(b) => Some(b),
            FieldValue::String(s) => Some(s.as_bytes()),
            _ => None,
        }
    }

    /// Try to get as string
    pub fn as_str(&self) -> Option<&str> {
        match self {
            FieldValue::String(s) => Some(s),
            _ => None,
        }
    }

    /// Get the length for length-based validations
    pub fn len(&self) -> Option<usize> {
        match self {
            FieldValue::Bytes(b) => Some(b.len()),
            FieldValue::String(s) => Some(s.len()),
            FieldValue::IntArray(a) => Some(a.len()),
            _ => None,
        }
    }

    /// Check if value is empty
    pub fn is_empty(&self) -> bool {
        match self {
            FieldValue::Bytes(b) => b.is_empty(),
            FieldValue::String(s) => s.is_empty(),
            FieldValue::IntArray(a) => a.is_empty(),
            FieldValue::Null => true,
            _ => false,
        }
    }

    /// Check if value is null
    pub fn is_null(&self) -> bool {
        matches!(self, FieldValue::Null)
    }
}

/// Message to be validated (collection of field values)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MessageData {
    /// Field name to value mapping
    pub fields: HashMap<String, FieldValue>,
}

impl MessageData {
    /// Create a new empty message
    pub fn new() -> Self {
        Self {
            fields: HashMap::new(),
        }
    }

    /// Set a field value
    pub fn set(&mut self, name: &str, value: FieldValue) {
        self.fields.insert(name.to_string(), value);
    }

    /// Get a field value
    pub fn get(&self, name: &str) -> Option<&FieldValue> {
        self.fields.get(name)
    }

    /// Check if field exists
    pub fn has(&self, name: &str) -> bool {
        self.fields.contains_key(name)
    }

    /// Builder pattern: add an integer field
    pub fn with_int(mut self, name: &str, value: i64) -> Self {
        self.set(name, FieldValue::Int(value));
        self
    }

    /// Builder pattern: add an unsigned integer field
    pub fn with_uint(mut self, name: &str, value: u64) -> Self {
        self.set(name, FieldValue::UInt(value));
        self
    }

    /// Builder pattern: add a bytes field
    pub fn with_bytes(mut self, name: &str, value: Vec<u8>) -> Self {
        self.set(name, FieldValue::Bytes(value));
        self
    }

    /// Builder pattern: add a string field
    pub fn with_string(mut self, name: &str, value: &str) -> Self {
        self.set(name, FieldValue::String(value.to_string()));
        self
    }
}

/// Validator that holds field rules and validates messages
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Validator {
    /// Field name to list of rules mapping
    rules: HashMap<String, Vec<ValidationRule>>,

    /// Whether to fail on unknown fields
    strict_mode: bool,

    /// Optional name for this validator (e.g., message type name)
    name: Option<String>,
}

impl Validator {
    /// Create a new empty validator
    pub fn new() -> Self {
        Self {
            rules: HashMap::new(),
            strict_mode: false,
            name: None,
        }
    }

    /// Create a validator with a name
    pub fn named(name: &str) -> Self {
        Self {
            rules: HashMap::new(),
            strict_mode: false,
            name: Some(name.to_string()),
        }
    }

    /// Enable strict mode (fail on unknown fields)
    pub fn strict(mut self) -> Self {
        self.strict_mode = true;
        self
    }

    /// Add a rule for a field
    pub fn add_rule(&mut self, field: &str, rule: ValidationRule) {
        self.rules
            .entry(field.to_string())
            .or_default()
            .push(rule);
    }

    /// Builder pattern: add a rule for a field
    pub fn rule(mut self, field: &str, rule: ValidationRule) -> Self {
        self.add_rule(field, rule);
        self
    }

    /// Builder pattern: add multiple rules for a field
    pub fn rules(mut self, field: &str, rules: Vec<ValidationRule>) -> Self {
        for rule in rules {
            self.add_rule(field, rule);
        }
        self
    }

    /// Get rules for a field
    pub fn get_rules(&self, field: &str) -> Option<&Vec<ValidationRule>> {
        self.rules.get(field)
    }

    /// Get all field names with rules
    pub fn field_names(&self) -> impl Iterator<Item = &String> {
        self.rules.keys()
    }

    /// Validate a message against the rules
    pub fn validate(&self, message: &MessageData) -> ValidationResult {
        let mut result = ValidationResult::success();

        // Validate each field that has rules
        for (field_name, rules) in &self.rules {
            match message.get(field_name) {
                Some(value) => {
                    let field_valid = self.validate_field(field_name, value, rules, message, &mut result);
                    result.add_field_result(field_name, field_valid);
                }
                None => {
                    // Check if field is required
                    if rules.iter().any(|r| matches!(r, ValidationRule::Required)) {
                        result.add_error(ValidationError::new(
                            field_name,
                            "Required",
                            "Required field is missing",
                        ));
                        result.add_field_result(field_name, false);
                    } else {
                        result.add_skipped(field_name);
                    }
                }
            }
        }

        // In strict mode, check for unknown fields
        if self.strict_mode {
            for field_name in message.fields.keys() {
                if !self.rules.contains_key(field_name) {
                    result.add_error(ValidationError::new(
                        field_name,
                        "UnknownField",
                        "Unknown field in strict mode",
                    ));
                }
            }
        }

        result
    }

    /// Validate a single field against its rules
    fn validate_field(
        &self,
        field_name: &str,
        value: &FieldValue,
        rules: &[ValidationRule],
        message: &MessageData,
        result: &mut ValidationResult,
    ) -> bool {
        let mut field_valid = true;

        for rule in rules {
            match self.check_rule(field_name, value, rule, message) {
                Ok(()) => {}
                Err(error) => {
                    result.add_error(error);
                    field_valid = false;
                }
            }
        }

        field_valid
    }

    /// Check a single rule against a value
    fn check_rule(
        &self,
        field_name: &str,
        value: &FieldValue,
        rule: &ValidationRule,
        message: &MessageData,
    ) -> Result<(), ValidationError> {
        match rule {
            ValidationRule::Const(expected) => {
                let actual = value.as_uint().ok_or_else(|| {
                    ValidationError::new(field_name, "Const", "Cannot convert to integer")
                })?;
                if actual != *expected {
                    return Err(ValidationError::new(
                        field_name,
                        "Const",
                        "Value does not match constant",
                    )
                    .with_expected(&expected.to_string())
                    .with_actual(&actual.to_string()));
                }
            }

            ValidationRule::Range(min, max) => {
                let actual = value.as_int().ok_or_else(|| {
                    ValidationError::new(field_name, "Range", "Cannot convert to integer")
                })?;
                if actual < *min || actual > *max {
                    return Err(ValidationError::new(
                        field_name,
                        "Range",
                        "Value out of range",
                    )
                    .with_expected(&format!("[{}, {}]", min, max))
                    .with_actual(&actual.to_string()));
                }
            }

            ValidationRule::Hash(source_field) => {
                let source_value = message.get(source_field).ok_or_else(|| {
                    ValidationError::new(
                        field_name,
                        "Hash",
                        &format!("Source field '{}' not found", source_field),
                    )
                })?;

                let source_bytes = source_value.as_bytes().ok_or_else(|| {
                    ValidationError::new(field_name, "Hash", "Source field is not bytes")
                })?;

                let expected_hash = blake3::hash(source_bytes);
                let actual_hash = value.as_bytes().ok_or_else(|| {
                    ValidationError::new(field_name, "Hash", "Hash field is not bytes")
                })?;

                if actual_hash != expected_hash.as_bytes() {
                    return Err(ValidationError::new(
                        field_name,
                        "Hash",
                        "Hash does not match source field",
                    )
                    .with_expected(&hex::encode(expected_hash.as_bytes()))
                    .with_actual(&hex::encode(actual_hash)));
                }
            }

            ValidationRule::Expr(bytecode) => {
                let mut vm = ExprVM::new();
                let mut ctx = ExprContext::new();

                // Add current field value to context
                match value {
                    FieldValue::Int(i) => ctx.set_var("value", Value::Int(*i)),
                    FieldValue::UInt(u) => ctx.set_var("value", Value::Int(*u as i64)),
                    FieldValue::Float(f) => ctx.set_var("value", Value::Float(*f)),
                    FieldValue::Bool(b) => ctx.set_var("value", Value::Bool(*b)),
                    _ => {}
                }

                // Add other field values to context
                for (name, fv) in &message.fields {
                    match fv {
                        FieldValue::Int(i) => ctx.set_var(name, Value::Int(*i)),
                        FieldValue::UInt(u) => ctx.set_var(name, Value::Int(*u as i64)),
                        FieldValue::Float(f) => ctx.set_var(name, Value::Float(*f)),
                        FieldValue::Bool(b) => ctx.set_var(name, Value::Bool(*b)),
                        _ => {}
                    }
                }

                match vm.execute(bytecode, &ctx) {
                    Ok(result) => {
                        if !result.is_truthy() {
                            return Err(ValidationError::new(
                                field_name,
                                "Expr",
                                "Expression evaluated to false",
                            ));
                        }
                    }
                    Err(e) => {
                        return Err(ValidationError::new(
                            field_name,
                            "Expr",
                            &format!("Expression error: {}", e),
                        ));
                    }
                }
            }

            ValidationRule::NonEmpty => {
                if value.is_empty() {
                    return Err(ValidationError::new(
                        field_name,
                        "NonEmpty",
                        "Value must not be empty",
                    ));
                }
            }

            ValidationRule::MaxLen(max) => {
                if let Some(len) = value.len() {
                    if len > *max {
                        return Err(ValidationError::new(
                            field_name,
                            "MaxLen",
                            "Value exceeds maximum length",
                        )
                        .with_expected(&format!("<= {}", max))
                        .with_actual(&len.to_string()));
                    }
                }
            }

            ValidationRule::MinLen(min) => {
                if let Some(len) = value.len() {
                    if len < *min {
                        return Err(ValidationError::new(
                            field_name,
                            "MinLen",
                            "Value below minimum length",
                        )
                        .with_expected(&format!(">= {}", min))
                        .with_actual(&len.to_string()));
                    }
                }
            }

            ValidationRule::Pattern(pattern) => {
                let s = value.as_str().ok_or_else(|| {
                    ValidationError::new(field_name, "Pattern", "Value is not a string")
                })?;

                // Simple pattern matching (supports * wildcard and ^ $ anchors)
                if !simple_pattern_match(pattern, s) {
                    return Err(ValidationError::new(
                        field_name,
                        "Pattern",
                        "Value does not match pattern",
                    )
                    .with_expected(pattern)
                    .with_actual(s));
                }
            }

            ValidationRule::OneOf(values) => {
                let actual = value.as_int().ok_or_else(|| {
                    ValidationError::new(field_name, "OneOf", "Cannot convert to integer")
                })?;

                if !values.contains(&actual) {
                    return Err(ValidationError::new(
                        field_name,
                        "OneOf",
                        "Value not in allowed set",
                    )
                    .with_expected(&format!("{:?}", values))
                    .with_actual(&actual.to_string()));
                }
            }

            ValidationRule::EnumVariant(enum_name) => {
                // This would integrate with schema enum definitions
                // For now, just check that it's a valid integer
                if value.as_int().is_none() && value.as_str().is_none() {
                    return Err(ValidationError::new(
                        field_name,
                        "EnumVariant",
                        &format!("Invalid variant for enum '{}'", enum_name),
                    ));
                }
            }

            ValidationRule::Required => {
                if value.is_null() {
                    return Err(ValidationError::new(
                        field_name,
                        "Required",
                        "Required field is null",
                    ));
                }
            }

            ValidationRule::Crc { fields, width } => {
                // Collect bytes from specified fields
                let mut data = Vec::new();
                for source_field in fields {
                    if let Some(fv) = message.get(source_field) {
                        if let Some(bytes) = fv.as_bytes() {
                            data.extend_from_slice(bytes);
                        }
                    }
                }

                let expected_crc = value.as_uint().ok_or_else(|| {
                    ValidationError::new(field_name, "Crc", "CRC field is not an integer")
                })?;

                let computed_crc = match width {
                    8 => compute_crc8(&data) as u64,
                    16 => compute_crc16(&data) as u64,
                    32 => compute_crc32(&data) as u64,
                    _ => {
                        return Err(ValidationError::new(
                            field_name,
                            "Crc",
                            &format!("Unsupported CRC width: {}", width),
                        ));
                    }
                };

                if expected_crc != computed_crc {
                    return Err(ValidationError::new(field_name, "Crc", "CRC mismatch")
                        .with_expected(&format!("0x{:X}", computed_crc))
                        .with_actual(&format!("0x{:X}", expected_crc)));
                }
            }
        }

        Ok(())
    }
}

/// Simple pattern matching supporting basic wildcards
/// Supports: * (any chars), ? (any single char), ^ (start), $ (end)
fn simple_pattern_match(pattern: &str, text: &str) -> bool {
    let pattern = pattern.trim();
    let text = text.trim();

    // Handle anchors
    let (pattern, must_start) = if let Some(p) = pattern.strip_prefix('^') {
        (p, true)
    } else {
        (pattern, false)
    };

    let (pattern, must_end) = if let Some(p) = pattern.strip_suffix('$') {
        (p, true)
    } else {
        (pattern, false)
    };

    // Simple wildcard matching
    let parts: Vec<&str> = pattern.split('*').collect();

    if parts.len() == 1 {
        // No wildcards
        if must_start && must_end {
            return text == pattern;
        } else if must_start {
            return text.starts_with(pattern);
        } else if must_end {
            return text.ends_with(pattern);
        } else {
            return text.contains(pattern);
        }
    }

    // Multiple parts with wildcards
    let mut pos = 0;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }

        if i == 0 && must_start {
            if !text.starts_with(part) {
                return false;
            }
            pos = part.len();
        } else if let Some(found) = text[pos..].find(part) {
            pos += found + part.len();
        } else {
            return false;
        }
    }

    if must_end && !parts.last().unwrap_or(&"").is_empty() {
        text.ends_with(parts.last().unwrap_or(&""))
    } else {
        true
    }
}

/// Compute CRC-8 (simple polynomial)
fn compute_crc8(data: &[u8]) -> u8 {
    let mut crc: u8 = 0xFF;
    for byte in data {
        crc ^= byte;
        for _ in 0..8 {
            if crc & 0x80 != 0 {
                crc = (crc << 1) ^ 0x31;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// Compute CRC-16 (CCITT polynomial)
fn compute_crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for byte in data {
        crc ^= (*byte as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// Compute CRC-32 (IEEE polynomial)
fn compute_crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for byte in data {
        crc ^= *byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::expr::{BytecodeBuilder, Opcode};

    #[test]
    fn test_const_validation() {
        let validator = Validator::new()
            .rule("version", ValidationRule::Const(1));

        // Valid case
        let msg = MessageData::new().with_uint("version", 1);
        let result = validator.validate(&msg);
        assert!(result.is_valid);

        // Invalid case
        let msg = MessageData::new().with_uint("version", 2);
        let result = validator.validate(&msg);
        assert!(!result.is_valid);
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].rule, "Const");
    }

    #[test]
    fn test_range_validation() {
        let validator = Validator::new()
            .rule("age", ValidationRule::Range(0, 150));

        // Valid cases
        let msg = MessageData::new().with_int("age", 25);
        assert!(validator.validate(&msg).is_valid);

        let msg = MessageData::new().with_int("age", 0);
        assert!(validator.validate(&msg).is_valid);

        let msg = MessageData::new().with_int("age", 150);
        assert!(validator.validate(&msg).is_valid);

        // Invalid cases
        let msg = MessageData::new().with_int("age", -1);
        assert!(!validator.validate(&msg).is_valid);

        let msg = MessageData::new().with_int("age", 151);
        assert!(!validator.validate(&msg).is_valid);
    }

    #[test]
    fn test_hash_validation() {
        let validator = Validator::new()
            .rule("data_hash", ValidationRule::Hash("data".to_string()));

        let data = b"hello world".to_vec();
        let hash = blake3::hash(&data);

        // Valid case
        let mut msg = MessageData::new();
        msg.set("data", FieldValue::Bytes(data.clone()));
        msg.set("data_hash", FieldValue::Bytes(hash.as_bytes().to_vec()));
        assert!(validator.validate(&msg).is_valid);

        // Invalid case
        let mut msg = MessageData::new();
        msg.set("data", FieldValue::Bytes(data));
        msg.set("data_hash", FieldValue::Bytes(vec![0; 32]));
        let result = validator.validate(&msg);
        assert!(!result.is_valid);
        assert_eq!(result.errors[0].rule, "Hash");
    }

    #[test]
    fn test_expr_validation() {
        // Expression: value > 10
        let bytecode = BytecodeBuilder::new()
            .load_var("value")
            .push_float(10.0)
            .op(Opcode::Gt)
            .build();

        let validator = Validator::new()
            .rule("score", ValidationRule::Expr(bytecode));

        // Valid case
        let msg = MessageData::new().with_int("score", 15);
        assert!(validator.validate(&msg).is_valid);

        // Invalid case
        let msg = MessageData::new().with_int("score", 5);
        assert!(!validator.validate(&msg).is_valid);
    }

    #[test]
    fn test_non_empty_validation() {
        let validator = Validator::new()
            .rule("name", ValidationRule::NonEmpty);

        // Valid case
        let msg = MessageData::new().with_string("name", "Alice");
        assert!(validator.validate(&msg).is_valid);

        // Invalid case
        let msg = MessageData::new().with_string("name", "");
        assert!(!validator.validate(&msg).is_valid);

        // Invalid case with empty bytes
        let mut msg = MessageData::new();
        msg.set("name", FieldValue::Bytes(vec![]));
        assert!(!validator.validate(&msg).is_valid);
    }

    #[test]
    fn test_max_len_validation() {
        let validator = Validator::new()
            .rule("username", ValidationRule::MaxLen(10));

        // Valid case
        let msg = MessageData::new().with_string("username", "alice");
        assert!(validator.validate(&msg).is_valid);

        // Boundary case
        let msg = MessageData::new().with_string("username", "alicebob12");
        assert!(validator.validate(&msg).is_valid);

        // Invalid case
        let msg = MessageData::new().with_string("username", "alicebob123");
        assert!(!validator.validate(&msg).is_valid);
    }

    #[test]
    fn test_min_len_validation() {
        let validator = Validator::new()
            .rule("password", ValidationRule::MinLen(8));

        // Valid case
        let msg = MessageData::new().with_string("password", "securepassword");
        assert!(validator.validate(&msg).is_valid);

        // Invalid case
        let msg = MessageData::new().with_string("password", "short");
        assert!(!validator.validate(&msg).is_valid);
    }

    #[test]
    fn test_pattern_validation() {
        let validator = Validator::new()
            .rule("email", ValidationRule::Pattern("*@*.*".to_string()));

        // Valid case
        let msg = MessageData::new().with_string("email", "test@example.com");
        assert!(validator.validate(&msg).is_valid);

        // Invalid case
        let msg = MessageData::new().with_string("email", "not-an-email");
        assert!(!validator.validate(&msg).is_valid);
    }

    #[test]
    fn test_one_of_validation() {
        let validator = Validator::new()
            .rule("status", ValidationRule::OneOf(vec![0, 1, 2]));

        // Valid cases
        for status in [0, 1, 2] {
            let msg = MessageData::new().with_int("status", status);
            assert!(validator.validate(&msg).is_valid);
        }

        // Invalid case
        let msg = MessageData::new().with_int("status", 3);
        assert!(!validator.validate(&msg).is_valid);
    }

    #[test]
    fn test_required_validation() {
        let validator = Validator::new()
            .rule("id", ValidationRule::Required);

        // Valid case
        let msg = MessageData::new().with_uint("id", 123);
        assert!(validator.validate(&msg).is_valid);

        // Invalid case - missing field
        let msg = MessageData::new();
        let result = validator.validate(&msg);
        assert!(!result.is_valid);
        assert_eq!(result.errors[0].rule, "Required");
    }

    #[test]
    fn test_crc_validation() {
        let validator = Validator::new().rule(
            "checksum",
            ValidationRule::Crc {
                fields: vec!["header".to_string(), "payload".to_string()],
                width: 32,
            },
        );

        // Compute expected CRC
        let header = b"HEADER";
        let payload = b"PAYLOAD";
        let mut data = Vec::new();
        data.extend_from_slice(header);
        data.extend_from_slice(payload);
        let expected_crc = compute_crc32(&data);

        // Valid case
        let mut msg = MessageData::new();
        msg.set("header", FieldValue::Bytes(header.to_vec()));
        msg.set("payload", FieldValue::Bytes(payload.to_vec()));
        msg.set("checksum", FieldValue::UInt(expected_crc as u64));
        assert!(validator.validate(&msg).is_valid);

        // Invalid case
        let mut msg = MessageData::new();
        msg.set("header", FieldValue::Bytes(header.to_vec()));
        msg.set("payload", FieldValue::Bytes(payload.to_vec()));
        msg.set("checksum", FieldValue::UInt(0));
        assert!(!validator.validate(&msg).is_valid);
    }

    #[test]
    fn test_multiple_rules_per_field() {
        let validator = Validator::new()
            .rule("port", ValidationRule::Required)
            .rule("port", ValidationRule::Range(1, 65535));

        // Valid case
        let msg = MessageData::new().with_int("port", 8080);
        assert!(validator.validate(&msg).is_valid);

        // Invalid - out of range
        let msg = MessageData::new().with_int("port", 0);
        let result = validator.validate(&msg);
        assert!(!result.is_valid);

        // Invalid - missing
        let msg = MessageData::new();
        let result = validator.validate(&msg);
        assert!(!result.is_valid);
    }

    #[test]
    fn test_strict_mode() {
        let validator = Validator::new()
            .strict()
            .rule("id", ValidationRule::Required);

        // Valid case
        let msg = MessageData::new().with_uint("id", 1);
        assert!(validator.validate(&msg).is_valid);

        // Invalid - unknown field
        let msg = MessageData::new()
            .with_uint("id", 1)
            .with_string("unknown", "value");
        let result = validator.validate(&msg);
        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|e| e.rule == "UnknownField"));
    }

    #[test]
    fn test_validation_result_counts() {
        let validator = Validator::new()
            .rule("a", ValidationRule::Range(0, 10))
            .rule("b", ValidationRule::Range(0, 10))
            .rule("c", ValidationRule::Range(0, 10));

        let msg = MessageData::new()
            .with_int("a", 5)   // valid
            .with_int("b", 15)  // invalid
            .with_int("c", 3);  // valid

        let result = validator.validate(&msg);
        assert!(!result.is_valid);
        assert_eq!(result.passed_count(), 2);
        assert_eq!(result.failed_count(), 1);
    }

    #[test]
    fn test_validation_result_merge() {
        let mut result1 = ValidationResult::success();
        result1.add_field_result("field1", true);

        let mut result2 = ValidationResult::success();
        result2.add_error(ValidationError::new("field2", "Test", "Test error"));

        result1.merge(result2);

        assert!(!result1.is_valid);
        assert_eq!(result1.errors.len(), 1);
        assert_eq!(result1.field_results.len(), 2);
    }

    #[test]
    fn test_simple_pattern_match() {
        // Basic wildcard
        assert!(simple_pattern_match("hello*", "hello world"));
        assert!(simple_pattern_match("*world", "hello world"));
        assert!(simple_pattern_match("*llo wor*", "hello world"));

        // Anchors
        assert!(simple_pattern_match("^hello", "hello world"));
        assert!(!simple_pattern_match("^world", "hello world"));
        assert!(simple_pattern_match("world$", "hello world"));
        assert!(!simple_pattern_match("hello$", "hello world"));

        // Exact match
        assert!(simple_pattern_match("^hello world$", "hello world"));
        assert!(!simple_pattern_match("^hello$", "hello world"));
    }

    #[test]
    fn test_crc_functions() {
        let data = b"123456789";

        // These are standard test vectors
        let crc8 = compute_crc8(data);
        let crc16 = compute_crc16(data);
        let crc32 = compute_crc32(data);

        // Verify CRCs are non-zero and consistent
        assert!(crc8 != 0);
        assert!(crc16 != 0);
        assert!(crc32 != 0);

        // Verify same input produces same output
        assert_eq!(crc8, compute_crc8(data));
        assert_eq!(crc16, compute_crc16(data));
        assert_eq!(crc32, compute_crc32(data));

        // Different input produces different output
        let other_data = b"987654321";
        assert_ne!(crc32, compute_crc32(other_data));
    }

    #[test]
    fn test_field_value_conversions() {
        let int_val = FieldValue::Int(42);
        assert_eq!(int_val.as_int(), Some(42));
        assert_eq!(int_val.as_uint(), Some(42));
        assert!(!int_val.is_empty());
        assert!(!int_val.is_null());

        let bytes_val = FieldValue::Bytes(vec![1, 2, 3]);
        assert_eq!(bytes_val.len(), Some(3));
        assert!(!bytes_val.is_empty());

        let empty_bytes = FieldValue::Bytes(vec![]);
        assert!(empty_bytes.is_empty());

        let null_val = FieldValue::Null;
        assert!(null_val.is_null());
        assert!(null_val.is_empty());
    }

    #[test]
    fn test_validation_error_display() {
        let error = ValidationError::new("field", "Range", "Value out of range")
            .with_expected("[0, 100]")
            .with_actual("150");

        let display = format!("{}", error);
        assert!(display.contains("field"));
        assert!(display.contains("Range"));
        assert!(display.contains("[0, 100]"));
        assert!(display.contains("150"));
    }

    #[test]
    fn test_complex_message_validation() {
        // Create a validator for a chunk message
        let validator = Validator::named("ChunkMessage")
            .rule("type", ValidationRule::Const(0x02))
            .rule("chunk_id", ValidationRule::Required)
            .rule("chunk_id", ValidationRule::MinLen(32))
            .rule("chunk_id", ValidationRule::MaxLen(32))
            .rule("data", ValidationRule::NonEmpty)
            .rule("data", ValidationRule::MaxLen(1024 * 1024));

        // Valid message
        let msg = MessageData::new()
            .with_uint("type", 0x02)
            .with_bytes("chunk_id", vec![0u8; 32])
            .with_bytes("data", vec![1, 2, 3, 4, 5]);

        let result = validator.validate(&msg);
        assert!(result.is_valid);
        assert_eq!(result.passed_count(), 3);

        // Invalid - wrong type
        let msg = MessageData::new()
            .with_uint("type", 0x01)
            .with_bytes("chunk_id", vec![0u8; 32])
            .with_bytes("data", vec![1, 2, 3]);

        let result = validator.validate(&msg);
        assert!(!result.is_valid);

        // Invalid - chunk_id wrong size
        let msg = MessageData::new()
            .with_uint("type", 0x02)
            .with_bytes("chunk_id", vec![0u8; 16])
            .with_bytes("data", vec![1, 2, 3]);

        let result = validator.validate(&msg);
        assert!(!result.is_valid);
    }
}
