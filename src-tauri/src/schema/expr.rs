//! Expression Evaluator - Stack-Based VM
//!
//! A lightweight stack-based virtual machine for evaluating expressions,
//! inspired by Concordia's expression opcodes. Used for:
//!
//! - Dynamic authority score computation
//! - Custom validation expressions
//! - Hot-reloadable scoring formulas
//! - Reputation decay functions

use std::collections::HashMap;

/// Value types in the expression VM
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Int(i64),
    Float(f64),
    Bool(bool),
    Bytes(Vec<u8>),
}

impl Value {
    /// Convert to i64
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            Value::Float(f) => Some(*f as i64),
            Value::Bool(b) => Some(*b as i64),
            _ => None,
        }
    }

    /// Convert to f64
    pub fn as_float(&self) -> Option<f64> {
        match self {
            Value::Int(i) => Some(*i as f64),
            Value::Float(f) => Some(*f),
            Value::Bool(b) => Some(*b as u8 as f64),
            _ => None,
        }
    }

    /// Convert to bool
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Int(i) => Some(*i != 0),
            Value::Float(f) => Some(*f != 0.0),
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Check if truthy
    pub fn is_truthy(&self) -> bool {
        self.as_bool().unwrap_or(false)
    }
}

/// Opcodes for the expression VM
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    /// No operation
    Nop = 0x00,

    // Stack operations
    /// Push immediate i64 value (followed by 8 bytes)
    PushInt = 0x01,
    /// Push immediate f64 value (followed by 8 bytes)
    PushFloat = 0x02,
    /// Push true
    PushTrue = 0x03,
    /// Push false
    PushFalse = 0x04,
    /// Duplicate top of stack
    Dup = 0x05,
    /// Pop and discard
    Pop = 0x06,
    /// Swap top two values
    Swap = 0x07,

    // Load operations
    /// Load variable by name (followed by string length + string)
    LoadVar = 0x10,
    /// Load field from context by ID (followed by u16)
    LoadField = 0x11,
    /// Load constant by ID (followed by u16)
    LoadConst = 0x12,

    // Arithmetic operations
    Add = 0x20,
    Sub = 0x21,
    Mul = 0x22,
    Div = 0x23,
    Mod = 0x24,
    Neg = 0x25,
    Abs = 0x26,
    Min = 0x27,
    Max = 0x28,
    Pow = 0x29,
    Sqrt = 0x2A,
    Log = 0x2B,
    Exp = 0x2C,

    // Comparison operations
    Eq = 0x30,
    Ne = 0x31,
    Lt = 0x32,
    Le = 0x33,
    Gt = 0x34,
    Ge = 0x35,

    // Logical operations
    And = 0x40,
    Or = 0x41,
    Not = 0x42,

    // Bitwise operations
    BitAnd = 0x50,
    BitOr = 0x51,
    BitXor = 0x52,
    BitNot = 0x53,
    Shl = 0x54,
    Shr = 0x55,

    // Control flow
    /// Jump forward (followed by u16 offset)
    Jump = 0x60,
    /// Jump if top is false (followed by u16 offset)
    JumpIfFalse = 0x61,
    /// Jump if top is true (followed by u16 offset)
    JumpIfTrue = 0x62,

    // Special operations
    /// Clamp to range (pops max, min, value, pushes clamped)
    Clamp = 0x70,
    /// Linear interpolation (pops t, b, a, pushes lerp)
    Lerp = 0x71,
    /// Map value from one range to another
    Map = 0x72,

    // Authority-specific operations
    /// Compute eigenvector centrality contribution
    Centrality = 0x80,
    /// Apply time decay
    TimeDecay = 0x81,
    /// Weighted average (pops count, then count pairs of value/weight)
    WeightedAvg = 0x82,

    /// Return result (terminates execution)
    Return = 0xFF,
}

impl TryFrom<u8> for Opcode {
    type Error = ExprError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Opcode::Nop),
            0x01 => Ok(Opcode::PushInt),
            0x02 => Ok(Opcode::PushFloat),
            0x03 => Ok(Opcode::PushTrue),
            0x04 => Ok(Opcode::PushFalse),
            0x05 => Ok(Opcode::Dup),
            0x06 => Ok(Opcode::Pop),
            0x07 => Ok(Opcode::Swap),
            0x10 => Ok(Opcode::LoadVar),
            0x11 => Ok(Opcode::LoadField),
            0x12 => Ok(Opcode::LoadConst),
            0x20 => Ok(Opcode::Add),
            0x21 => Ok(Opcode::Sub),
            0x22 => Ok(Opcode::Mul),
            0x23 => Ok(Opcode::Div),
            0x24 => Ok(Opcode::Mod),
            0x25 => Ok(Opcode::Neg),
            0x26 => Ok(Opcode::Abs),
            0x27 => Ok(Opcode::Min),
            0x28 => Ok(Opcode::Max),
            0x29 => Ok(Opcode::Pow),
            0x2A => Ok(Opcode::Sqrt),
            0x2B => Ok(Opcode::Log),
            0x2C => Ok(Opcode::Exp),
            0x30 => Ok(Opcode::Eq),
            0x31 => Ok(Opcode::Ne),
            0x32 => Ok(Opcode::Lt),
            0x33 => Ok(Opcode::Le),
            0x34 => Ok(Opcode::Gt),
            0x35 => Ok(Opcode::Ge),
            0x40 => Ok(Opcode::And),
            0x41 => Ok(Opcode::Or),
            0x42 => Ok(Opcode::Not),
            0x50 => Ok(Opcode::BitAnd),
            0x51 => Ok(Opcode::BitOr),
            0x52 => Ok(Opcode::BitXor),
            0x53 => Ok(Opcode::BitNot),
            0x54 => Ok(Opcode::Shl),
            0x55 => Ok(Opcode::Shr),
            0x60 => Ok(Opcode::Jump),
            0x61 => Ok(Opcode::JumpIfFalse),
            0x62 => Ok(Opcode::JumpIfTrue),
            0x70 => Ok(Opcode::Clamp),
            0x71 => Ok(Opcode::Lerp),
            0x72 => Ok(Opcode::Map),
            0x80 => Ok(Opcode::Centrality),
            0x81 => Ok(Opcode::TimeDecay),
            0x82 => Ok(Opcode::WeightedAvg),
            0xFF => Ok(Opcode::Return),
            _ => Err(ExprError::InvalidOpcode(value)),
        }
    }
}

/// Errors from expression evaluation
#[derive(Debug, Clone)]
pub enum ExprError {
    StackUnderflow,
    StackOverflow,
    InvalidOpcode(u8),
    DivisionByZero,
    TypeMismatch,
    VariableNotFound(String),
    FieldNotFound(u16),
    InvalidBytecode,
    ExecutionLimit,
}

impl std::fmt::Display for ExprError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExprError::StackUnderflow => write!(f, "Stack underflow"),
            ExprError::StackOverflow => write!(f, "Stack overflow"),
            ExprError::InvalidOpcode(op) => write!(f, "Invalid opcode: 0x{:02X}", op),
            ExprError::DivisionByZero => write!(f, "Division by zero"),
            ExprError::TypeMismatch => write!(f, "Type mismatch"),
            ExprError::VariableNotFound(name) => write!(f, "Variable not found: {}", name),
            ExprError::FieldNotFound(id) => write!(f, "Field not found: {}", id),
            ExprError::InvalidBytecode => write!(f, "Invalid bytecode"),
            ExprError::ExecutionLimit => write!(f, "Execution limit exceeded"),
        }
    }
}

impl std::error::Error for ExprError {}

/// Context for expression evaluation
#[derive(Default)]
pub struct ExprContext {
    /// Named variables
    pub variables: HashMap<String, Value>,
    /// Field values by ID
    pub fields: HashMap<u16, Value>,
    /// Constants by ID
    pub constants: HashMap<u16, Value>,
}

impl ExprContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_var(&mut self, name: &str, value: Value) {
        self.variables.insert(name.to_string(), value);
    }

    pub fn set_field(&mut self, id: u16, value: Value) {
        self.fields.insert(id, value);
    }

    /// Create context with common authority variables
    pub fn authority_context(
        centrality: f64,
        reputation: f64,
        age_secs: u64,
        interactions: u64,
    ) -> Self {
        let mut ctx = Self::new();
        ctx.set_var("centrality", Value::Float(centrality));
        ctx.set_var("reputation", Value::Float(reputation));
        ctx.set_var("age", Value::Int(age_secs as i64));
        ctx.set_var("interactions", Value::Int(interactions as i64));
        ctx.set_var("now", Value::Int(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
        ));
        ctx
    }
}

/// Stack-based expression virtual machine
pub struct ExprVM {
    /// Value stack
    stack: Vec<Value>,
    /// Maximum stack size
    max_stack: usize,
    /// Maximum instructions to execute
    max_instructions: usize,
}

impl ExprVM {
    /// Create a new VM with default limits
    pub fn new() -> Self {
        Self {
            stack: Vec::with_capacity(64),
            max_stack: 256,
            max_instructions: 10000,
        }
    }

    /// Create with custom limits
    pub fn with_limits(max_stack: usize, max_instructions: usize) -> Self {
        Self {
            stack: Vec::with_capacity(max_stack.min(64)),
            max_stack,
            max_instructions,
        }
    }

    /// Execute bytecode and return result
    pub fn execute(&mut self, bytecode: &[u8], ctx: &ExprContext) -> Result<Value, ExprError> {
        self.stack.clear();
        let mut ip = 0;
        let mut instruction_count = 0;

        while ip < bytecode.len() {
            instruction_count += 1;
            if instruction_count > self.max_instructions {
                return Err(ExprError::ExecutionLimit);
            }

            let opcode = Opcode::try_from(bytecode[ip])?;
            ip += 1;

            match opcode {
                Opcode::Nop => {}

                Opcode::PushInt => {
                    if ip + 8 > bytecode.len() {
                        return Err(ExprError::InvalidBytecode);
                    }
                    let value = i64::from_le_bytes(bytecode[ip..ip + 8].try_into().unwrap());
                    ip += 8;
                    self.push(Value::Int(value))?;
                }

                Opcode::PushFloat => {
                    if ip + 8 > bytecode.len() {
                        return Err(ExprError::InvalidBytecode);
                    }
                    let value = f64::from_le_bytes(bytecode[ip..ip + 8].try_into().unwrap());
                    ip += 8;
                    self.push(Value::Float(value))?;
                }

                Opcode::PushTrue => self.push(Value::Bool(true))?,
                Opcode::PushFalse => self.push(Value::Bool(false))?,

                Opcode::Dup => {
                    let val = self.peek()?.clone();
                    self.push(val)?;
                }

                Opcode::Pop => {
                    self.pop()?;
                }

                Opcode::Swap => {
                    let len = self.stack.len();
                    if len < 2 {
                        return Err(ExprError::StackUnderflow);
                    }
                    self.stack.swap(len - 1, len - 2);
                }

                Opcode::LoadVar => {
                    if ip >= bytecode.len() {
                        return Err(ExprError::InvalidBytecode);
                    }
                    let name_len = bytecode[ip] as usize;
                    ip += 1;
                    if ip + name_len > bytecode.len() {
                        return Err(ExprError::InvalidBytecode);
                    }
                    let name = std::str::from_utf8(&bytecode[ip..ip + name_len])
                        .map_err(|_| ExprError::InvalidBytecode)?;
                    ip += name_len;

                    let value = ctx.variables.get(name)
                        .ok_or_else(|| ExprError::VariableNotFound(name.to_string()))?
                        .clone();
                    self.push(value)?;
                }

                Opcode::LoadField => {
                    if ip + 2 > bytecode.len() {
                        return Err(ExprError::InvalidBytecode);
                    }
                    let field_id = u16::from_le_bytes(bytecode[ip..ip + 2].try_into().unwrap());
                    ip += 2;

                    let value = ctx.fields.get(&field_id)
                        .ok_or(ExprError::FieldNotFound(field_id))?
                        .clone();
                    self.push(value)?;
                }

                Opcode::LoadConst => {
                    if ip + 2 > bytecode.len() {
                        return Err(ExprError::InvalidBytecode);
                    }
                    let const_id = u16::from_le_bytes(bytecode[ip..ip + 2].try_into().unwrap());
                    ip += 2;

                    let value = ctx.constants.get(&const_id)
                        .ok_or(ExprError::FieldNotFound(const_id))?
                        .clone();
                    self.push(value)?;
                }

                // Arithmetic
                Opcode::Add => self.binary_op(|a, b| a + b)?,
                Opcode::Sub => self.binary_op(|a, b| a - b)?,
                Opcode::Mul => self.binary_op(|a, b| a * b)?,
                Opcode::Div => {
                    let b = self.pop_float()?;
                    if b == 0.0 {
                        return Err(ExprError::DivisionByZero);
                    }
                    let a = self.pop_float()?;
                    self.push(Value::Float(a / b))?;
                }
                Opcode::Mod => {
                    let b = self.pop_int()?;
                    if b == 0 {
                        return Err(ExprError::DivisionByZero);
                    }
                    let a = self.pop_int()?;
                    self.push(Value::Int(a % b))?;
                }
                Opcode::Neg => {
                    let a = self.pop_float()?;
                    self.push(Value::Float(-a))?;
                }
                Opcode::Abs => {
                    let a = self.pop_float()?;
                    self.push(Value::Float(a.abs()))?;
                }
                Opcode::Min => {
                    let b = self.pop_float()?;
                    let a = self.pop_float()?;
                    self.push(Value::Float(a.min(b)))?;
                }
                Opcode::Max => {
                    let b = self.pop_float()?;
                    let a = self.pop_float()?;
                    self.push(Value::Float(a.max(b)))?;
                }
                Opcode::Pow => {
                    let b = self.pop_float()?;
                    let a = self.pop_float()?;
                    self.push(Value::Float(a.powf(b)))?;
                }
                Opcode::Sqrt => {
                    let a = self.pop_float()?;
                    self.push(Value::Float(a.sqrt()))?;
                }
                Opcode::Log => {
                    let a = self.pop_float()?;
                    self.push(Value::Float(a.ln()))?;
                }
                Opcode::Exp => {
                    let a = self.pop_float()?;
                    self.push(Value::Float(a.exp()))?;
                }

                // Comparison
                Opcode::Eq => self.compare_op(|a, b| a == b)?,
                Opcode::Ne => self.compare_op(|a, b| a != b)?,
                Opcode::Lt => self.compare_op(|a, b| a < b)?,
                Opcode::Le => self.compare_op(|a, b| a <= b)?,
                Opcode::Gt => self.compare_op(|a, b| a > b)?,
                Opcode::Ge => self.compare_op(|a, b| a >= b)?,

                // Logical
                Opcode::And => {
                    let b = self.pop()?.is_truthy();
                    let a = self.pop()?.is_truthy();
                    self.push(Value::Bool(a && b))?;
                }
                Opcode::Or => {
                    let b = self.pop()?.is_truthy();
                    let a = self.pop()?.is_truthy();
                    self.push(Value::Bool(a || b))?;
                }
                Opcode::Not => {
                    let a = self.pop()?.is_truthy();
                    self.push(Value::Bool(!a))?;
                }

                // Bitwise
                Opcode::BitAnd => {
                    let b = self.pop_int()?;
                    let a = self.pop_int()?;
                    self.push(Value::Int(a & b))?;
                }
                Opcode::BitOr => {
                    let b = self.pop_int()?;
                    let a = self.pop_int()?;
                    self.push(Value::Int(a | b))?;
                }
                Opcode::BitXor => {
                    let b = self.pop_int()?;
                    let a = self.pop_int()?;
                    self.push(Value::Int(a ^ b))?;
                }
                Opcode::BitNot => {
                    let a = self.pop_int()?;
                    self.push(Value::Int(!a))?;
                }
                Opcode::Shl => {
                    let b = self.pop_int()?;
                    let a = self.pop_int()?;
                    self.push(Value::Int(a << b))?;
                }
                Opcode::Shr => {
                    let b = self.pop_int()?;
                    let a = self.pop_int()?;
                    self.push(Value::Int(a >> b))?;
                }

                // Control flow
                Opcode::Jump => {
                    if ip + 2 > bytecode.len() {
                        return Err(ExprError::InvalidBytecode);
                    }
                    let offset = u16::from_le_bytes(bytecode[ip..ip + 2].try_into().unwrap());
                    ip = offset as usize;
                }
                Opcode::JumpIfFalse => {
                    if ip + 2 > bytecode.len() {
                        return Err(ExprError::InvalidBytecode);
                    }
                    let offset = u16::from_le_bytes(bytecode[ip..ip + 2].try_into().unwrap());
                    ip += 2;
                    if !self.pop()?.is_truthy() {
                        ip = offset as usize;
                    }
                }
                Opcode::JumpIfTrue => {
                    if ip + 2 > bytecode.len() {
                        return Err(ExprError::InvalidBytecode);
                    }
                    let offset = u16::from_le_bytes(bytecode[ip..ip + 2].try_into().unwrap());
                    ip += 2;
                    if self.pop()?.is_truthy() {
                        ip = offset as usize;
                    }
                }

                // Special operations
                Opcode::Clamp => {
                    let max = self.pop_float()?;
                    let min = self.pop_float()?;
                    let val = self.pop_float()?;
                    self.push(Value::Float(val.clamp(min, max)))?;
                }
                Opcode::Lerp => {
                    let t = self.pop_float()?;
                    let b = self.pop_float()?;
                    let a = self.pop_float()?;
                    self.push(Value::Float(a + (b - a) * t))?;
                }
                Opcode::Map => {
                    // Map value from [in_min, in_max] to [out_min, out_max]
                    let out_max = self.pop_float()?;
                    let out_min = self.pop_float()?;
                    let in_max = self.pop_float()?;
                    let in_min = self.pop_float()?;
                    let val = self.pop_float()?;

                    let mapped = out_min + (val - in_min) * (out_max - out_min) / (in_max - in_min);
                    self.push(Value::Float(mapped))?;
                }

                // Authority operations
                Opcode::TimeDecay => {
                    // Apply exponential time decay: value * 0.5^(age/half_life)
                    let half_life = self.pop_float()?;
                    let age = self.pop_float()?;
                    let value = self.pop_float()?;

                    let decay = 0.5_f64.powf(age / half_life);
                    self.push(Value::Float(value * decay))?;
                }

                Opcode::WeightedAvg => {
                    let count = self.pop_int()? as usize;
                    let mut sum = 0.0;
                    let mut weight_sum = 0.0;

                    for _ in 0..count {
                        let weight = self.pop_float()?;
                        let value = self.pop_float()?;
                        sum += value * weight;
                        weight_sum += weight;
                    }

                    let avg = if weight_sum > 0.0 { sum / weight_sum } else { 0.0 };
                    self.push(Value::Float(avg))?;
                }

                Opcode::Centrality => {
                    // Placeholder for centrality computation
                    // In real implementation, this would use graph context
                    self.push(Value::Float(1.0))?;
                }

                Opcode::Return => {
                    break;
                }
            }
        }

        self.stack.pop().ok_or(ExprError::StackUnderflow)
    }

    fn push(&mut self, value: Value) -> Result<(), ExprError> {
        if self.stack.len() >= self.max_stack {
            return Err(ExprError::StackOverflow);
        }
        self.stack.push(value);
        Ok(())
    }

    fn pop(&mut self) -> Result<Value, ExprError> {
        self.stack.pop().ok_or(ExprError::StackUnderflow)
    }

    fn peek(&self) -> Result<&Value, ExprError> {
        self.stack.last().ok_or(ExprError::StackUnderflow)
    }

    fn pop_int(&mut self) -> Result<i64, ExprError> {
        self.pop()?.as_int().ok_or(ExprError::TypeMismatch)
    }

    fn pop_float(&mut self) -> Result<f64, ExprError> {
        self.pop()?.as_float().ok_or(ExprError::TypeMismatch)
    }

    fn binary_op<F>(&mut self, f: F) -> Result<(), ExprError>
    where
        F: Fn(f64, f64) -> f64,
    {
        let b = self.pop_float()?;
        let a = self.pop_float()?;
        self.push(Value::Float(f(a, b)))
    }

    fn compare_op<F>(&mut self, f: F) -> Result<(), ExprError>
    where
        F: Fn(f64, f64) -> bool,
    {
        let b = self.pop_float()?;
        let a = self.pop_float()?;
        self.push(Value::Bool(f(a, b)))
    }
}

impl Default for ExprVM {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating bytecode
pub struct BytecodeBuilder {
    bytecode: Vec<u8>,
}

impl BytecodeBuilder {
    pub fn new() -> Self {
        Self { bytecode: Vec::new() }
    }

    pub fn push_int(mut self, value: i64) -> Self {
        self.bytecode.push(Opcode::PushInt as u8);
        self.bytecode.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub fn push_float(mut self, value: f64) -> Self {
        self.bytecode.push(Opcode::PushFloat as u8);
        self.bytecode.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub fn load_var(mut self, name: &str) -> Self {
        self.bytecode.push(Opcode::LoadVar as u8);
        self.bytecode.push(name.len() as u8);
        self.bytecode.extend_from_slice(name.as_bytes());
        self
    }

    pub fn op(mut self, opcode: Opcode) -> Self {
        self.bytecode.push(opcode as u8);
        self
    }

    pub fn build(mut self) -> Vec<u8> {
        self.bytecode.push(Opcode::Return as u8);
        self.bytecode
    }
}

impl Default for BytecodeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Create authority score computation bytecode
/// Formula: 0.6 * centrality + 0.4 * reputation * (1 - 0.5^(age/86400))
pub fn authority_score_bytecode() -> Vec<u8> {
    BytecodeBuilder::new()
        // 0.6 * centrality
        .push_float(0.6)
        .load_var("centrality")
        .op(Opcode::Mul)
        // 0.4 * reputation
        .push_float(0.4)
        .load_var("reputation")
        .op(Opcode::Mul)
        // age factor: 1 - 0.5^(age/86400)
        .load_var("age")
        .push_float(86400.0)
        .op(Opcode::Div)
        .push_float(0.5)
        .op(Opcode::Swap)
        .op(Opcode::Pow)
        .push_float(1.0)
        .op(Opcode::Swap)
        .op(Opcode::Sub)
        // Multiply reputation portion by age factor
        .op(Opcode::Mul)
        // Add centrality and reputation portions
        .op(Opcode::Add)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_arithmetic() {
        let bytecode = BytecodeBuilder::new()
            .push_float(10.0)
            .push_float(5.0)
            .op(Opcode::Add)
            .build();

        let mut vm = ExprVM::new();
        let ctx = ExprContext::new();
        let result = vm.execute(&bytecode, &ctx).unwrap();

        assert_eq!(result.as_float(), Some(15.0));
    }

    #[test]
    fn test_variables() {
        let bytecode = BytecodeBuilder::new()
            .load_var("x")
            .load_var("y")
            .op(Opcode::Mul)
            .build();

        let mut ctx = ExprContext::new();
        ctx.set_var("x", Value::Float(3.0));
        ctx.set_var("y", Value::Float(4.0));

        let mut vm = ExprVM::new();
        let result = vm.execute(&bytecode, &ctx).unwrap();

        assert_eq!(result.as_float(), Some(12.0));
    }

    #[test]
    fn test_comparison() {
        let bytecode = BytecodeBuilder::new()
            .push_float(10.0)
            .push_float(5.0)
            .op(Opcode::Gt)
            .build();

        let mut vm = ExprVM::new();
        let result = vm.execute(&bytecode, &ExprContext::new()).unwrap();

        assert_eq!(result.as_bool(), Some(true));
    }

    #[test]
    fn test_authority_score() {
        let bytecode = authority_score_bytecode();

        let ctx = ExprContext::authority_context(
            0.8,    // centrality
            0.9,    // reputation
            86400,  // age (1 day)
            100,    // interactions
        );

        let mut vm = ExprVM::new();
        let result = vm.execute(&bytecode, &ctx).unwrap();
        let score = result.as_float().unwrap();

        // 0.6 * 0.8 + 0.4 * 0.9 * (1 - 0.5^1) = 0.48 + 0.36 * 0.5 = 0.48 + 0.18 = 0.66
        assert!((score - 0.66).abs() < 0.01);
    }
}
