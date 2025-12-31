//! Hot-Reloadable Rule Engine
//!
//! A rule engine for authority and consensus rules, inspired by Concordia's
//! IL-based hot-reload system. Features:
//!
//! - Rules are bytecode programs executed by ExprVM
//! - RuleSet can be swapped at runtime (hot-reload)
//! - Thread-safe with Arc<RwLock>
//! - Built-in rules for authority scoring, trust thresholds, consensus weights

use super::expr::{BytecodeBuilder, ExprContext, ExprVM, Opcode, Value};
use libp2p::PeerId;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Metadata about a rule
#[derive(Debug, Clone)]
pub struct RuleMetadata {
    /// Human-readable description
    pub description: String,
    /// Version of the rule
    pub version: u32,
    /// Author or source of the rule
    pub author: Option<String>,
    /// Timestamp when rule was created/updated
    pub timestamp: u64,
    /// Tags for categorization
    pub tags: Vec<String>,
}

impl Default for RuleMetadata {
    fn default() -> Self {
        Self {
            description: String::new(),
            version: 1,
            author: None,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            tags: Vec::new(),
        }
    }
}

/// A named rule with bytecode and metadata
#[derive(Debug, Clone)]
pub struct Rule {
    /// Unique identifier for the rule
    pub name: String,
    /// Bytecode program for the ExprVM
    pub bytecode: Vec<u8>,
    /// Rule metadata
    pub metadata: RuleMetadata,
    /// Whether this rule is enabled
    pub enabled: bool,
}

impl Rule {
    /// Create a new rule with the given name and bytecode
    pub fn new(name: impl Into<String>, bytecode: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            bytecode,
            metadata: RuleMetadata::default(),
            enabled: true,
        }
    }

    /// Create a rule with metadata
    pub fn with_metadata(mut self, metadata: RuleMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    /// Set the rule description
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.metadata.description = description.into();
        self
    }

    /// Set the rule version
    pub fn with_version(mut self, version: u32) -> Self {
        self.metadata.version = version;
        self
    }

    /// Set tags for the rule
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.metadata.tags = tags;
        self
    }

    /// Enable or disable the rule
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Execute this rule with the given context
    pub fn execute(&self, vm: &mut ExprVM, ctx: &ExprContext) -> Result<Value, RuleError> {
        if !self.enabled {
            return Err(RuleError::RuleDisabled(self.name.clone()));
        }
        vm.execute(&self.bytecode, ctx)
            .map_err(|e| RuleError::ExecutionError(self.name.clone(), e.to_string()))
    }
}

/// Errors that can occur in rule operations
#[derive(Debug, Clone)]
pub enum RuleError {
    /// Rule not found in the ruleset
    RuleNotFound(String),
    /// Rule is disabled
    RuleDisabled(String),
    /// Error during rule execution
    ExecutionError(String, String),
    /// Invalid rule bytecode
    InvalidBytecode(String),
    /// Context missing required variable
    MissingVariable(String),
}

impl std::fmt::Display for RuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleError::RuleNotFound(name) => write!(f, "Rule not found: {}", name),
            RuleError::RuleDisabled(name) => write!(f, "Rule is disabled: {}", name),
            RuleError::ExecutionError(name, err) => {
                write!(f, "Rule execution error in '{}': {}", name, err)
            }
            RuleError::InvalidBytecode(name) => write!(f, "Invalid bytecode in rule: {}", name),
            RuleError::MissingVariable(var) => write!(f, "Missing required variable: {}", var),
        }
    }
}

impl std::error::Error for RuleError {}

/// A collection of rules that can be hot-reloaded
#[derive(Debug, Clone)]
pub struct RuleSet {
    /// Rules indexed by name
    rules: HashMap<String, Rule>,
    /// Version of this ruleset
    version: u32,
    /// Name of this ruleset
    name: String,
}

impl RuleSet {
    /// Create a new empty ruleset
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            rules: HashMap::new(),
            version: 1,
            name: name.into(),
        }
    }

    /// Create a ruleset with built-in rules
    pub fn with_defaults(name: impl Into<String>) -> Self {
        let mut ruleset = Self::new(name);
        ruleset.add_rule(Self::authority_score_rule());
        ruleset.add_rule(Self::trust_threshold_rule());
        ruleset.add_rule(Self::consensus_weight_rule());
        ruleset
    }

    /// Get the ruleset name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the ruleset version
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Add a rule to the ruleset
    pub fn add_rule(&mut self, rule: Rule) {
        self.rules.insert(rule.name.clone(), rule);
    }

    /// Remove a rule from the ruleset
    pub fn remove_rule(&mut self, name: &str) -> Option<Rule> {
        self.rules.remove(name)
    }

    /// Get a rule by name
    pub fn get_rule(&self, name: &str) -> Option<&Rule> {
        self.rules.get(name)
    }

    /// Get a mutable reference to a rule
    pub fn get_rule_mut(&mut self, name: &str) -> Option<&mut Rule> {
        self.rules.get_mut(name)
    }

    /// Check if a rule exists
    pub fn has_rule(&self, name: &str) -> bool {
        self.rules.contains_key(name)
    }

    /// Get all rule names
    pub fn rule_names(&self) -> Vec<&str> {
        self.rules.keys().map(|s| s.as_str()).collect()
    }

    /// Get the number of rules
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Check if the ruleset is empty
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Increment the version
    pub fn increment_version(&mut self) {
        self.version += 1;
    }

    /// Iterate over all rules
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Rule)> {
        self.rules.iter()
    }

    /// Built-in authority score rule
    /// Formula: 0.6 * centrality + 0.4 * reputation * (1 - 0.5^(age/86400))
    pub fn authority_score_rule() -> Rule {
        let bytecode = BytecodeBuilder::new()
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
            .build();

        Rule::new("authority_score", bytecode)
            .with_description("Computes authority score from centrality, reputation, and age")
            .with_tags(vec!["authority".into(), "scoring".into()])
    }

    /// Built-in trust threshold rule
    /// Returns true if trust_score >= threshold
    pub fn trust_threshold_rule() -> Rule {
        let bytecode = BytecodeBuilder::new()
            .load_var("trust_score")
            .load_var("threshold")
            .op(Opcode::Ge)
            .build();

        Rule::new("trust_threshold", bytecode)
            .with_description("Checks if trust score meets the threshold")
            .with_tags(vec!["trust".into(), "threshold".into()])
    }

    /// Built-in consensus weight rule
    /// Formula: authority_score * stake_weight * (1 + log(1 + successful_validations))
    pub fn consensus_weight_rule() -> Rule {
        let bytecode = BytecodeBuilder::new()
            // authority_score * stake_weight
            .load_var("authority_score")
            .load_var("stake_weight")
            .op(Opcode::Mul)
            // 1 + log(1 + successful_validations)
            .push_float(1.0)
            .load_var("successful_validations")
            .op(Opcode::Add)
            .op(Opcode::Log)
            .push_float(1.0)
            .op(Opcode::Add)
            // Multiply together
            .op(Opcode::Mul)
            .build();

        Rule::new("consensus_weight", bytecode)
            .with_description("Computes consensus weight from authority, stake, and validation history")
            .with_tags(vec!["consensus".into(), "weight".into()])
    }
}

impl Default for RuleSet {
    fn default() -> Self {
        Self::with_defaults("default")
    }
}

/// Context for rule evaluation with peer data
#[derive(Debug, Clone)]
pub struct RuleContext {
    /// The peer being evaluated
    pub peer_id: Option<PeerId>,
    /// Variables for expression evaluation
    pub variables: HashMap<String, Value>,
    /// Additional peer metadata
    pub peer_metadata: HashMap<String, String>,
}

impl RuleContext {
    /// Create a new empty rule context
    pub fn new() -> Self {
        Self {
            peer_id: None,
            variables: HashMap::new(),
            peer_metadata: HashMap::new(),
        }
    }

    /// Create a context for a specific peer
    pub fn for_peer(peer_id: PeerId) -> Self {
        Self {
            peer_id: Some(peer_id),
            variables: HashMap::new(),
            peer_metadata: HashMap::new(),
        }
    }

    /// Set a variable
    pub fn set_var(&mut self, name: impl Into<String>, value: Value) -> &mut Self {
        self.variables.insert(name.into(), value);
        self
    }

    /// Get a variable
    pub fn get_var(&self, name: &str) -> Option<&Value> {
        self.variables.get(name)
    }

    /// Set peer metadata
    pub fn set_metadata(&mut self, key: impl Into<String>, value: impl Into<String>) -> &mut Self {
        self.peer_metadata.insert(key.into(), value.into());
        self
    }

    /// Convert to ExprContext for VM execution
    pub fn to_expr_context(&self) -> ExprContext {
        let mut ctx = ExprContext::new();
        for (name, value) in &self.variables {
            ctx.set_var(name, value.clone());
        }
        ctx
    }

    /// Create a context for authority scoring
    pub fn authority_context(
        peer_id: PeerId,
        centrality: f64,
        reputation: f64,
        age_secs: u64,
        interactions: u64,
    ) -> Self {
        let mut ctx = Self::for_peer(peer_id);
        ctx.set_var("centrality", Value::Float(centrality))
            .set_var("reputation", Value::Float(reputation))
            .set_var("age", Value::Int(age_secs as i64))
            .set_var("interactions", Value::Int(interactions as i64))
            .set_var(
                "now",
                Value::Int(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64,
                ),
            );
        ctx
    }

    /// Create a context for trust threshold checking
    pub fn trust_context(peer_id: PeerId, trust_score: f64, threshold: f64) -> Self {
        let mut ctx = Self::for_peer(peer_id);
        ctx.set_var("trust_score", Value::Float(trust_score))
            .set_var("threshold", Value::Float(threshold));
        ctx
    }

    /// Create a context for consensus weight calculation
    pub fn consensus_context(
        peer_id: PeerId,
        authority_score: f64,
        stake_weight: f64,
        successful_validations: u64,
    ) -> Self {
        let mut ctx = Self::for_peer(peer_id);
        ctx.set_var("authority_score", Value::Float(authority_score))
            .set_var("stake_weight", Value::Float(stake_weight))
            .set_var(
                "successful_validations",
                Value::Float(successful_validations as f64),
            );
        ctx
    }
}

impl Default for RuleContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Result cache entry
#[derive(Debug, Clone)]
struct CacheEntry {
    result: Value,
    timestamp: u64,
    ruleset_version: u32,
}

/// Rule engine that executes rules and caches results
///
/// Thread-safe and supports hot-reloading of rulesets.
pub struct RuleEngine {
    /// The current ruleset (hot-reloadable)
    ruleset: Arc<RwLock<RuleSet>>,
    /// Result cache keyed by (rule_name, context_hash)
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    /// Cache TTL in seconds
    cache_ttl: u64,
    /// Maximum cache size
    max_cache_size: usize,
}

impl RuleEngine {
    /// Create a new rule engine with default settings
    pub fn new() -> Self {
        Self {
            ruleset: Arc::new(RwLock::new(RuleSet::default())),
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl: 300, // 5 minutes
            max_cache_size: 10000,
        }
    }

    /// Create a rule engine with a specific ruleset
    pub fn with_ruleset(ruleset: RuleSet) -> Self {
        Self {
            ruleset: Arc::new(RwLock::new(ruleset)),
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl: 300,
            max_cache_size: 10000,
        }
    }

    /// Create a rule engine with custom cache settings
    pub fn with_cache_settings(cache_ttl: u64, max_cache_size: usize) -> Self {
        Self {
            ruleset: Arc::new(RwLock::new(RuleSet::default())),
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl,
            max_cache_size,
        }
    }

    /// Get a clone of the current ruleset
    pub async fn get_ruleset(&self) -> RuleSet {
        self.ruleset.read().await.clone()
    }

    /// Hot-reload: replace the entire ruleset
    pub async fn reload_ruleset(&self, new_ruleset: RuleSet) {
        let mut ruleset = self.ruleset.write().await;
        *ruleset = new_ruleset;

        // Clear cache on reload
        let mut cache = self.cache.write().await;
        cache.clear();
    }

    /// Hot-reload: update a single rule
    pub async fn update_rule(&self, rule: Rule) {
        let mut ruleset = self.ruleset.write().await;
        let rule_name = rule.name.clone();
        ruleset.add_rule(rule);
        ruleset.increment_version();

        // Invalidate cache entries for this rule
        let mut cache = self.cache.write().await;
        cache.retain(|key, _| !key.starts_with(&format!("{}:", rule_name)));
    }

    /// Hot-reload: remove a rule
    pub async fn remove_rule(&self, name: &str) -> Option<Rule> {
        let mut ruleset = self.ruleset.write().await;
        let rule = ruleset.remove_rule(name);

        if rule.is_some() {
            ruleset.increment_version();

            // Invalidate cache entries for this rule
            let mut cache = self.cache.write().await;
            cache.retain(|key, _| !key.starts_with(&format!("{}:", name)));
        }

        rule
    }

    /// Execute a rule by name
    pub async fn execute(&self, rule_name: &str, ctx: &RuleContext) -> Result<Value, RuleError> {
        let cache_key = self.compute_cache_key(rule_name, ctx);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Check cache first
        {
            let ruleset = self.ruleset.read().await;
            let cache = self.cache.read().await;

            if let Some(entry) = cache.get(&cache_key) {
                if entry.ruleset_version == ruleset.version()
                    && now - entry.timestamp < self.cache_ttl
                {
                    return Ok(entry.result.clone());
                }
            }
        }

        // Execute the rule
        let (result, version) = {
            let ruleset = self.ruleset.read().await;
            let rule = ruleset
                .get_rule(rule_name)
                .ok_or_else(|| RuleError::RuleNotFound(rule_name.to_string()))?;

            let expr_ctx = ctx.to_expr_context();
            let mut vm = ExprVM::new();
            let result = rule.execute(&mut vm, &expr_ctx)?;
            (result, ruleset.version())
        };

        // Update cache
        {
            let mut cache = self.cache.write().await;

            // Evict old entries if cache is full
            if cache.len() >= self.max_cache_size {
                let cutoff = now - self.cache_ttl;
                cache.retain(|_, entry| entry.timestamp > cutoff);

                // If still too large, remove oldest entries
                if cache.len() >= self.max_cache_size {
                    let mut entries: Vec<_> = cache.iter().collect();
                    entries.sort_by_key(|(_, e)| e.timestamp);
                    let to_remove: Vec<_> = entries
                        .iter()
                        .take(self.max_cache_size / 4)
                        .map(|(k, _)| (*k).clone())
                        .collect();
                    for key in to_remove {
                        cache.remove(&key);
                    }
                }
            }

            cache.insert(
                cache_key,
                CacheEntry {
                    result: result.clone(),
                    timestamp: now,
                    ruleset_version: version,
                },
            );
        }

        Ok(result)
    }

    /// Execute a rule without caching
    pub async fn execute_uncached(
        &self,
        rule_name: &str,
        ctx: &RuleContext,
    ) -> Result<Value, RuleError> {
        let ruleset = self.ruleset.read().await;
        let rule = ruleset
            .get_rule(rule_name)
            .ok_or_else(|| RuleError::RuleNotFound(rule_name.to_string()))?;

        let expr_ctx = ctx.to_expr_context();
        let mut vm = ExprVM::new();
        rule.execute(&mut vm, &expr_ctx)
    }

    /// Calculate authority score for a peer
    pub async fn authority_score(&self, ctx: &RuleContext) -> Result<f64, RuleError> {
        let result = self.execute("authority_score", ctx).await?;
        result
            .as_float()
            .ok_or_else(|| RuleError::ExecutionError("authority_score".into(), "Expected float result".into()))
    }

    /// Check if a peer meets the trust threshold
    pub async fn meets_trust_threshold(&self, ctx: &RuleContext) -> Result<bool, RuleError> {
        let result = self.execute("trust_threshold", ctx).await?;
        result
            .as_bool()
            .ok_or_else(|| RuleError::ExecutionError("trust_threshold".into(), "Expected bool result".into()))
    }

    /// Calculate consensus weight for a peer
    pub async fn consensus_weight(&self, ctx: &RuleContext) -> Result<f64, RuleError> {
        let result = self.execute("consensus_weight", ctx).await?;
        result
            .as_float()
            .ok_or_else(|| RuleError::ExecutionError("consensus_weight".into(), "Expected float result".into()))
    }

    /// Clear the result cache
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
    }

    /// Get cache statistics
    pub async fn cache_stats(&self) -> (usize, usize) {
        let cache = self.cache.read().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let total = cache.len();
        let valid = cache
            .values()
            .filter(|e| now - e.timestamp < self.cache_ttl)
            .count();

        (total, valid)
    }

    /// Compute a cache key from rule name and context
    fn compute_cache_key(&self, rule_name: &str, ctx: &RuleContext) -> String {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();

        // Hash peer ID if present
        if let Some(ref peer_id) = ctx.peer_id {
            peer_id.to_bytes().hash(&mut hasher);
        }

        // Hash variables (sorted by key for consistency)
        let mut vars: Vec<_> = ctx.variables.iter().collect();
        vars.sort_by_key(|(k, _)| *k);
        for (key, value) in vars {
            key.hash(&mut hasher);
            // Hash the value representation
            match value {
                Value::Int(i) => i.hash(&mut hasher),
                Value::Float(f) => f.to_bits().hash(&mut hasher),
                Value::Bool(b) => b.hash(&mut hasher),
                Value::Bytes(b) => b.hash(&mut hasher),
            }
        }

        format!("{}:{:016x}", rule_name, hasher.finish())
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for RuleEngine {
    fn clone(&self) -> Self {
        Self {
            ruleset: Arc::clone(&self.ruleset),
            cache: Arc::clone(&self.cache),
            cache_ttl: self.cache_ttl,
            max_cache_size: self.max_cache_size,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_peer_id() -> PeerId {
        PeerId::random()
    }

    #[test]
    fn test_rule_creation() {
        let bytecode = BytecodeBuilder::new()
            .push_float(42.0)
            .build();

        let rule = Rule::new("test_rule", bytecode.clone())
            .with_description("A test rule")
            .with_version(2)
            .with_tags(vec!["test".into()]);

        assert_eq!(rule.name, "test_rule");
        assert_eq!(rule.metadata.description, "A test rule");
        assert_eq!(rule.metadata.version, 2);
        assert!(rule.enabled);
        assert_eq!(rule.bytecode, bytecode);
    }

    #[test]
    fn test_rule_execution() {
        let bytecode = BytecodeBuilder::new()
            .load_var("x")
            .load_var("y")
            .op(Opcode::Add)
            .build();

        let rule = Rule::new("add_rule", bytecode);

        let mut ctx = ExprContext::new();
        ctx.set_var("x", Value::Float(10.0));
        ctx.set_var("y", Value::Float(20.0));

        let mut vm = ExprVM::new();
        let result = rule.execute(&mut vm, &ctx).unwrap();

        assert_eq!(result.as_float(), Some(30.0));
    }

    #[test]
    fn test_disabled_rule() {
        let bytecode = BytecodeBuilder::new()
            .push_float(42.0)
            .build();

        let mut rule = Rule::new("disabled_rule", bytecode);
        rule.set_enabled(false);

        let ctx = ExprContext::new();
        let mut vm = ExprVM::new();
        let result = rule.execute(&mut vm, &ctx);

        assert!(matches!(result, Err(RuleError::RuleDisabled(_))));
    }

    #[test]
    fn test_ruleset_operations() {
        let mut ruleset = RuleSet::new("test_ruleset");

        let rule1 = Rule::new("rule1", BytecodeBuilder::new().push_float(1.0).build());
        let rule2 = Rule::new("rule2", BytecodeBuilder::new().push_float(2.0).build());

        ruleset.add_rule(rule1);
        ruleset.add_rule(rule2);

        assert_eq!(ruleset.len(), 2);
        assert!(ruleset.has_rule("rule1"));
        assert!(ruleset.has_rule("rule2"));
        assert!(!ruleset.has_rule("rule3"));

        let removed = ruleset.remove_rule("rule1");
        assert!(removed.is_some());
        assert_eq!(ruleset.len(), 1);
        assert!(!ruleset.has_rule("rule1"));
    }

    #[test]
    fn test_ruleset_with_defaults() {
        let ruleset = RuleSet::with_defaults("default");

        assert!(ruleset.has_rule("authority_score"));
        assert!(ruleset.has_rule("trust_threshold"));
        assert!(ruleset.has_rule("consensus_weight"));
        assert_eq!(ruleset.len(), 3);
    }

    #[test]
    fn test_rule_context() {
        let peer_id = test_peer_id();
        let mut ctx = RuleContext::for_peer(peer_id);

        ctx.set_var("test_var", Value::Float(42.0))
            .set_metadata("key", "value");

        assert!(ctx.peer_id.is_some());
        assert_eq!(ctx.get_var("test_var"), Some(&Value::Float(42.0)));
        assert_eq!(ctx.peer_metadata.get("key"), Some(&"value".to_string()));

        let expr_ctx = ctx.to_expr_context();
        assert!(expr_ctx.variables.contains_key("test_var"));
    }

    #[test]
    fn test_authority_context() {
        let peer_id = test_peer_id();
        let ctx = RuleContext::authority_context(peer_id, 0.8, 0.9, 86400, 100);

        assert!(ctx.peer_id.is_some());
        assert_eq!(ctx.get_var("centrality"), Some(&Value::Float(0.8)));
        assert_eq!(ctx.get_var("reputation"), Some(&Value::Float(0.9)));
        assert_eq!(ctx.get_var("age"), Some(&Value::Int(86400)));
        assert_eq!(ctx.get_var("interactions"), Some(&Value::Int(100)));
    }

    #[tokio::test]
    async fn test_rule_engine_creation() {
        let engine = RuleEngine::new();
        let ruleset = engine.get_ruleset().await;

        assert!(ruleset.has_rule("authority_score"));
        assert!(ruleset.has_rule("trust_threshold"));
        assert!(ruleset.has_rule("consensus_weight"));
    }

    #[tokio::test]
    async fn test_rule_engine_execute() {
        let engine = RuleEngine::new();
        let peer_id = test_peer_id();

        let ctx = RuleContext::authority_context(peer_id, 0.8, 0.9, 86400, 100);
        let result = engine.execute("authority_score", &ctx).await.unwrap();

        // 0.6 * 0.8 + 0.4 * 0.9 * (1 - 0.5^1) = 0.48 + 0.36 * 0.5 = 0.48 + 0.18 = 0.66
        let score = result.as_float().unwrap();
        assert!((score - 0.66).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_trust_threshold_rule() {
        let engine = RuleEngine::new();
        let peer_id = test_peer_id();

        // Above threshold
        let ctx = RuleContext::trust_context(peer_id, 0.8, 0.5);
        let result = engine.meets_trust_threshold(&ctx).await.unwrap();
        assert!(result);

        // Below threshold
        let ctx = RuleContext::trust_context(peer_id, 0.3, 0.5);
        let result = engine.meets_trust_threshold(&ctx).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_consensus_weight_rule() {
        let engine = RuleEngine::new();
        let peer_id = test_peer_id();

        let ctx = RuleContext::consensus_context(peer_id, 0.8, 1.0, 10);
        let result = engine.consensus_weight(&ctx).await.unwrap();

        // 0.8 * 1.0 * (1 + ln(11)) = 0.8 * (1 + 2.398) = 0.8 * 3.398 = 2.718
        assert!(result > 2.5 && result < 3.0);
    }

    #[tokio::test]
    async fn test_hot_reload_ruleset() {
        let engine = RuleEngine::new();

        // Create a new ruleset with a custom rule
        let mut new_ruleset = RuleSet::new("custom");
        let custom_rule = Rule::new(
            "custom_rule",
            BytecodeBuilder::new().push_float(99.0).build(),
        );
        new_ruleset.add_rule(custom_rule);

        // Reload
        engine.reload_ruleset(new_ruleset).await;

        let ruleset = engine.get_ruleset().await;
        assert!(ruleset.has_rule("custom_rule"));
        assert!(!ruleset.has_rule("authority_score")); // Default rules replaced

        // Execute custom rule
        let ctx = RuleContext::new();
        let result = engine.execute("custom_rule", &ctx).await.unwrap();
        assert_eq!(result.as_float(), Some(99.0));
    }

    #[tokio::test]
    async fn test_hot_reload_single_rule() {
        let engine = RuleEngine::new();

        // Update the authority_score rule
        let new_rule = Rule::new(
            "authority_score",
            BytecodeBuilder::new()
                .load_var("centrality")
                .load_var("reputation")
                .op(Opcode::Add)
                .build(),
        )
        .with_description("Simplified authority score");

        engine.update_rule(new_rule).await;

        let ruleset = engine.get_ruleset().await;
        let rule = ruleset.get_rule("authority_score").unwrap();
        assert_eq!(rule.metadata.description, "Simplified authority score");

        // Execute updated rule
        let peer_id = test_peer_id();
        let ctx = RuleContext::authority_context(peer_id, 0.8, 0.9, 86400, 100);
        let result = engine.authority_score(&ctx).await.unwrap();

        // New formula: centrality + reputation = 0.8 + 0.9 = 1.7
        assert!((result - 1.7).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_rule_not_found() {
        let engine = RuleEngine::new();
        let ctx = RuleContext::new();

        let result = engine.execute("nonexistent_rule", &ctx).await;
        assert!(matches!(result, Err(RuleError::RuleNotFound(_))));
    }

    #[tokio::test]
    async fn test_cache_invalidation_on_reload() {
        let engine = RuleEngine::new();
        let peer_id = test_peer_id();
        let ctx = RuleContext::authority_context(peer_id, 0.8, 0.9, 86400, 100);

        // Execute to populate cache
        let _result1 = engine.execute("authority_score", &ctx).await.unwrap();

        let (total1, _) = engine.cache_stats().await;
        assert!(total1 > 0);

        // Reload clears cache
        engine.reload_ruleset(RuleSet::default()).await;

        let (total2, _) = engine.cache_stats().await;
        assert_eq!(total2, 0);
    }

    #[tokio::test]
    async fn test_remove_rule() {
        let engine = RuleEngine::new();

        let removed = engine.remove_rule("authority_score").await;
        assert!(removed.is_some());

        let ruleset = engine.get_ruleset().await;
        assert!(!ruleset.has_rule("authority_score"));

        // Try to execute removed rule
        let ctx = RuleContext::new();
        let result = engine.execute("authority_score", &ctx).await;
        assert!(matches!(result, Err(RuleError::RuleNotFound(_))));
    }

    #[tokio::test]
    async fn test_engine_clone() {
        let engine1 = RuleEngine::new();

        // Update a rule
        let new_rule = Rule::new(
            "test_rule",
            BytecodeBuilder::new().push_float(42.0).build(),
        );
        engine1.update_rule(new_rule).await;

        // Clone the engine
        let engine2 = engine1.clone();

        // Both should see the same ruleset
        let ruleset1 = engine1.get_ruleset().await;
        let ruleset2 = engine2.get_ruleset().await;

        assert!(ruleset1.has_rule("test_rule"));
        assert!(ruleset2.has_rule("test_rule"));

        // Update via engine2 should be visible to engine1
        let another_rule = Rule::new(
            "another_rule",
            BytecodeBuilder::new().push_float(100.0).build(),
        );
        engine2.update_rule(another_rule).await;

        let ruleset1_updated = engine1.get_ruleset().await;
        assert!(ruleset1_updated.has_rule("another_rule"));
    }

    #[tokio::test]
    async fn test_execute_uncached() {
        let engine = RuleEngine::new();
        let peer_id = test_peer_id();
        let ctx = RuleContext::authority_context(peer_id, 0.8, 0.9, 86400, 100);

        // Execute uncached multiple times
        let result1 = engine.execute_uncached("authority_score", &ctx).await.unwrap();
        let result2 = engine.execute_uncached("authority_score", &ctx).await.unwrap();

        assert_eq!(result1.as_float(), result2.as_float());

        // Cache should remain empty
        let (total, _) = engine.cache_stats().await;
        assert_eq!(total, 0);
    }
}
