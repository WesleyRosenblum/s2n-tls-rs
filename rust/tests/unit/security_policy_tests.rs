//! Unit tests for the security policy framework

use s2n_tls_rs::testing::security_policy::{
    SecurityPolicy, SecurityPolicyBuilder, SecurityPolicyRegistry, TlsVersion,
    get_registry,
};
use s2n_tls_rs::testing::crypto::cipher_suites::{
    TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256,
};
use s2n_tls_rs::testing::handshake::NamedGroup;

#[test]
fn test_security_policy_default() {
    let policy = SecurityPolicy::default();
    
    assert_eq!(policy.name(), "default");
    assert_eq!(policy.cipher_suites().len(), 3);
    assert!(policy.cipher_suites().contains(&TLS_AES_128_GCM_SHA256));
    assert!(policy.cipher_suites().contains(&TLS_AES_256_GCM_SHA384));
    assert!(policy.cipher_suites().contains(&TLS_CHACHA20_POLY1305_SHA256));
    
    assert_eq!(policy.named_groups().len(), 3);
    assert!(policy.named_groups().contains(&NamedGroup::X25519));
    assert!(policy.named_groups().contains(&NamedGroup::SECP256R1));
    assert!(policy.named_groups().contains(&NamedGroup::SECP384R1));
    
    assert_eq!(policy.min_tls_version(), TlsVersion::Tls13);
    assert_eq!(policy.max_tls_version(), TlsVersion::Tls13);
    assert_eq!(policy.require_client_cert(), false);
}

#[test]
fn test_security_policy_tls13_strict() {
    let policy = SecurityPolicy::tls13_strict();
    
    assert_eq!(policy.name(), "tls13_strict");
    assert_eq!(policy.cipher_suites().len(), 2);
    assert!(!policy.cipher_suites().contains(&TLS_AES_128_GCM_SHA256));
    assert!(policy.cipher_suites().contains(&TLS_AES_256_GCM_SHA384));
    assert!(policy.cipher_suites().contains(&TLS_CHACHA20_POLY1305_SHA256));
    
    assert_eq!(policy.named_groups().len(), 2);
    assert!(policy.named_groups().contains(&NamedGroup::X25519));
    assert!(!policy.named_groups().contains(&NamedGroup::SECP256R1));
    assert!(policy.named_groups().contains(&NamedGroup::SECP384R1));
    
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
    assert!(policy.cipher_suites().contains(&TLS_AES_256_GCM_SHA384));
    
    assert_eq!(policy.named_groups().len(), 1);
    assert!(policy.named_groups().contains(&NamedGroup::X25519));
    
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
    
    // Get policy by name
    let strict = registry.get("tls13_strict").unwrap();
    assert_eq!(strict.name(), "tls13_strict");
}
