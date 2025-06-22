//! Security policy framework
//!
//! This module provides a security policy framework for the TLS implementation.
//! It defines the allowed cipher suites, named groups, and other security parameters.

use crate::crypto::CipherSuite;
use crate::crypto::cipher_suites::{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256};
use crate::handshake::NamedGroup;
use crate::error::{Error, ConfigError};

/// Security policy
#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    /// Policy name
    name: String,
    /// Allowed cipher suites
    cipher_suites: Vec<CipherSuite>,
    /// Allowed named groups
    named_groups: Vec<NamedGroup>,
    /// Minimum TLS version
    min_tls_version: TlsVersion,
    /// Maximum TLS version
    max_tls_version: TlsVersion,
    /// Require client certificate
    require_client_cert: bool,
}

/// TLS version
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TlsVersion {
    /// TLS 1.0
    Tls10,
    /// TLS 1.1
    Tls11,
    /// TLS 1.2
    Tls12,
    /// TLS 1.3
    Tls13,
}

impl SecurityPolicy {
    /// Create a new security policy
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            cipher_suites: Vec::new(),
            named_groups: Vec::new(),
            min_tls_version: TlsVersion::Tls13, // Default to TLS 1.3 only
            max_tls_version: TlsVersion::Tls13,
            require_client_cert: false,
        }
    }
    
    /// Get the policy name
    pub fn name(&self) -> &str {
        &self.name
    }
    
    /// Get the allowed cipher suites
    pub fn cipher_suites(&self) -> &[CipherSuite] {
        &self.cipher_suites
    }
    
    /// Get the allowed named groups
    pub fn named_groups(&self) -> &[NamedGroup] {
        &self.named_groups
    }
    
    /// Get the minimum TLS version
    pub fn min_tls_version(&self) -> TlsVersion {
        self.min_tls_version
    }
    
    /// Get the maximum TLS version
    pub fn max_tls_version(&self) -> TlsVersion {
        self.max_tls_version
    }
    
    /// Check if client certificate is required
    pub fn require_client_cert(&self) -> bool {
        self.require_client_cert
    }
    
    /// Get the default security policy
    pub fn default() -> Self {
        Self::tls13_default()
    }
    
    /// Get the TLS 1.3 default security policy
    pub fn tls13_default() -> Self {
        let mut policy = Self::new("default");
        
        // Add TLS 1.3 cipher suites
        policy.cipher_suites.push(TLS_AES_128_GCM_SHA256);
        policy.cipher_suites.push(TLS_AES_256_GCM_SHA384);
        policy.cipher_suites.push(TLS_CHACHA20_POLY1305_SHA256);
        
        // Add named groups
        policy.named_groups.push(NamedGroup::X25519);
        policy.named_groups.push(NamedGroup::Secp256r1);
        policy.named_groups.push(NamedGroup::Secp384r1);
        
        // Set TLS version range
        policy.min_tls_version = TlsVersion::Tls13;
        policy.max_tls_version = TlsVersion::Tls13;
        
        policy
    }
    
    /// Get the TLS 1.3 strict security policy
    pub fn tls13_strict() -> Self {
        let mut policy = Self::new("tls13_strict");
        
        // Add TLS 1.3 cipher suites
        policy.cipher_suites.push(TLS_AES_256_GCM_SHA384);
        policy.cipher_suites.push(TLS_CHACHA20_POLY1305_SHA256);
        
        // Add named groups
        policy.named_groups.push(NamedGroup::X25519);
        policy.named_groups.push(NamedGroup::Secp384r1);
        
        // Set TLS version range
        policy.min_tls_version = TlsVersion::Tls13;
        policy.max_tls_version = TlsVersion::Tls13;
        
        policy
    }
}

/// Security policy builder
#[derive(Debug)]
pub struct SecurityPolicyBuilder {
    /// Policy name
    name: String,
    /// Allowed cipher suites
    cipher_suites: Vec<CipherSuite>,
    /// Allowed named groups
    named_groups: Vec<NamedGroup>,
    /// Minimum TLS version
    min_tls_version: TlsVersion,
    /// Maximum TLS version
    max_tls_version: TlsVersion,
    /// Require client certificate
    require_client_cert: bool,
}

impl SecurityPolicyBuilder {
    /// Create a new security policy builder
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            cipher_suites: Vec::new(),
            named_groups: Vec::new(),
            min_tls_version: TlsVersion::Tls13, // Default to TLS 1.3 only
            max_tls_version: TlsVersion::Tls13,
            require_client_cert: false,
        }
    }
    
    /// Add a cipher suite
    pub fn with_cipher_suite(mut self, cipher_suite: CipherSuite) -> Self {
        self.cipher_suites.push(cipher_suite);
        self
    }
    
    /// Add a named group
    pub fn with_named_group(mut self, named_group: NamedGroup) -> Self {
        self.named_groups.push(named_group);
        self
    }
    
    /// Set the minimum TLS version
    pub fn with_min_tls_version(mut self, version: TlsVersion) -> Self {
        self.min_tls_version = version;
        self
    }
    
    /// Set the maximum TLS version
    pub fn with_max_tls_version(mut self, version: TlsVersion) -> Self {
        self.max_tls_version = version;
        self
    }
    
    /// Require client certificate
    pub fn with_client_cert_required(mut self, required: bool) -> Self {
        self.require_client_cert = required;
        self
    }
    
    /// Build the security policy
    pub fn build(self) -> Result<SecurityPolicy, Error> {
        // Validate the policy
        if self.cipher_suites.is_empty() {
            return Err(Error::config(ConfigError::Other("No cipher suites specified".into())));
        }
        
        if self.named_groups.is_empty() {
            return Err(Error::config(ConfigError::Other("No named groups specified".into())));
        }
        
        if self.min_tls_version > self.max_tls_version {
            return Err(Error::config(ConfigError::Other("Minimum TLS version is greater than maximum TLS version".into())));
        }
        
        Ok(SecurityPolicy {
            name: self.name,
            cipher_suites: self.cipher_suites,
            named_groups: self.named_groups,
            min_tls_version: self.min_tls_version,
            max_tls_version: self.max_tls_version,
            require_client_cert: self.require_client_cert,
        })
    }
}

/// Security policy registry
#[derive(Debug)]
pub struct SecurityPolicyRegistry {
    /// Registered policies
    policies: Vec<SecurityPolicy>,
}

impl SecurityPolicyRegistry {
    /// Create a new security policy registry
    pub fn new() -> Self {
        let mut registry = Self {
            policies: Vec::new(),
        };
        
        // Register default policies
        registry.register(SecurityPolicy::tls13_default());
        registry.register(SecurityPolicy::tls13_strict());
        
        registry
    }
    
    /// Register a security policy
    pub fn register(&mut self, policy: SecurityPolicy) {
        self.policies.push(policy);
    }
    
    /// Get a security policy by name
    pub fn get(&self, name: &str) -> Option<&SecurityPolicy> {
        self.policies.iter().find(|p| p.name() == name)
    }
    
    /// Get the default security policy
    pub fn default(&self) -> &SecurityPolicy {
        // The default policy is always the first one
        &self.policies[0]
    }
}

/// Get the global security policy registry
pub fn get_registry() -> &'static SecurityPolicyRegistry {
    // In a real implementation, this would be a lazy_static or similar
    // For now, we'll just return a new registry each time
    static mut REGISTRY: Option<SecurityPolicyRegistry> = None;
    
    unsafe {
        if REGISTRY.is_none() {
            REGISTRY = Some(SecurityPolicyRegistry::new());
        }
        
        REGISTRY.as_ref().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_security_policy_default() {
        let policy = SecurityPolicy::default();
        
        assert_eq!(policy.name(), "default");
        assert_eq!(policy.cipher_suites().len(), 3);
        assert_eq!(policy.named_groups().len(), 3);
        assert_eq!(policy.min_tls_version(), TlsVersion::Tls13);
        assert_eq!(policy.max_tls_version(), TlsVersion::Tls13);
        assert_eq!(policy.require_client_cert(), false);
    }
    
    #[test]
    fn test_security_policy_tls13_strict() {
        let policy = SecurityPolicy::tls13_strict();
        
        assert_eq!(policy.name(), "tls13_strict");
        assert_eq!(policy.cipher_suites().len(), 2);
        assert_eq!(policy.named_groups().len(), 2);
        assert_eq!(policy.min_tls_version(), TlsVersion::Tls13);
        assert_eq!(policy.max_tls_version(), TlsVersion::Tls13);
        assert_eq!(policy.require_client_cert(), false);
    }
    
    #[test]
    fn test_security_policy_builder() {
        let policy = SecurityPolicyBuilder::new("custom")
            .with_cipher_suite(TLS_AES_256_GCM_SHA384)
            .with_named_group(NamedGroup::X25519)
            .with_min_tls_version(TlsVersion::Tls13)
            .with_max_tls_version(TlsVersion::Tls13)
            .with_client_cert_required(true)
            .build()
            .unwrap();
        
        assert_eq!(policy.name(), "custom");
        assert_eq!(policy.cipher_suites().len(), 1);
        assert_eq!(policy.named_groups().len(), 1);
        assert_eq!(policy.min_tls_version(), TlsVersion::Tls13);
        assert_eq!(policy.max_tls_version(), TlsVersion::Tls13);
        assert_eq!(policy.require_client_cert(), true);
    }
    
    #[test]
    fn test_security_policy_builder_validation() {
        // No cipher suites
        let result = SecurityPolicyBuilder::new("invalid")
            .with_named_group(NamedGroup::X25519)
            .build();
        
        assert!(result.is_err());
        
        // No named groups
        let result = SecurityPolicyBuilder::new("invalid")
            .with_cipher_suite(TLS_AES_256_GCM_SHA384)
            .build();
        
        assert!(result.is_err());
        
        // Invalid TLS version range
        let result = SecurityPolicyBuilder::new("invalid")
            .with_cipher_suite(TLS_AES_256_GCM_SHA384)
            .with_named_group(NamedGroup::X25519)
            .with_min_tls_version(TlsVersion::Tls13)
            .with_max_tls_version(TlsVersion::Tls12)
            .build();
        
        assert!(result.is_err());
    }
    
    #[test]
    fn test_security_policy_registry() {
        let registry = SecurityPolicyRegistry::new();
        
        // Get default policy
        let default = registry.default();
        assert_eq!(default.name(), "default");
        
        // Get policy by name
        let strict = registry.get("tls13_strict").unwrap();
        assert_eq!(strict.name(), "tls13_strict");
        
        // Get non-existent policy
        let nonexistent = registry.get("nonexistent");
        assert!(nonexistent.is_none());
    }
    
    #[test]
    fn test_get_registry() {
        let registry = get_registry();
        
        // Get default policy
        let default = registry.default();
        assert_eq!(default.name(), "default");
    }
}
