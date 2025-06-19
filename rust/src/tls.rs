//! TLS protocol implementation
//!
//! This module implements the TLS protocol as specified in RFC 8446.
//! It ties together the record layer, handshake layer, and state machine.

use crate::error::Error;

/// TLS cipher suite
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CipherSuite {
    /// TLS_AES_128_GCM_SHA256
    TLS_AES_128_GCM_SHA256 = 0x1301,
    /// TLS_AES_256_GCM_SHA384
    TLS_AES_256_GCM_SHA384 = 0x1302,
    /// TLS_CHACHA20_POLY1305_SHA256
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
}

/// TLS security policy
#[derive(Debug)]
pub(crate) struct SecurityPolicy {
    /// Cipher suites
    pub cipher_suites: Vec<CipherSuite>,
    /// Minimum protocol version
    pub min_protocol_version: crate::record::ProtocolVersion,
    /// Maximum protocol version
    pub max_protocol_version: crate::record::ProtocolVersion,
    /// FIPS compliance
    pub is_fips_compliant: bool,
}

/// TLS security policy builder
#[derive(Debug)]
pub(crate) struct SecurityPolicyBuilder {
    /// Minimum protocol version
    min_protocol_version: Option<crate::record::ProtocolVersion>,
    /// Maximum protocol version
    max_protocol_version: Option<crate::record::ProtocolVersion>,
    /// FIPS compliance
    is_fips_compliant: bool,
}

impl SecurityPolicyBuilder {
    /// Create a new security policy builder
    pub fn new() -> Self {
        Self {
            min_protocol_version: None,
            max_protocol_version: None,
            is_fips_compliant: false,
        }
    }
    
    /// Set the minimum protocol version
    pub fn min_protocol_version(mut self, version: crate::record::ProtocolVersion) -> Self {
        self.min_protocol_version = Some(version);
        self
    }
    
    /// Set the maximum protocol version
    pub fn max_protocol_version(mut self, version: crate::record::ProtocolVersion) -> Self {
        self.max_protocol_version = Some(version);
        self
    }
    
    /// Set FIPS compliance
    pub fn fips_compliant(mut self, is_fips_compliant: bool) -> Self {
        self.is_fips_compliant = is_fips_compliant;
        self
    }
    
    /// Build the security policy
    pub fn build(self) -> Result<SecurityPolicy, Error> {
        let min_version = self.min_protocol_version.unwrap_or(crate::record::ProtocolVersion { major: 3, minor: 3 });
        let max_version = self.max_protocol_version.unwrap_or(crate::record::ProtocolVersion { major: 3, minor: 4 });
        
        let cipher_suites = vec![
            CipherSuite::TLS_AES_128_GCM_SHA256,
            CipherSuite::TLS_AES_256_GCM_SHA384,
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
        ];
        
        Ok(SecurityPolicy {
            cipher_suites,
            min_protocol_version: min_version,
            max_protocol_version: max_version,
            is_fips_compliant: self.is_fips_compliant,
        })
    }
}