//! TLS configuration API
//!
//! This module provides the public API for TLS configuration. The [`Config`] struct
//! allows you to configure various aspects of TLS connections, such as certificates,
//! cipher suites, and named groups.
//!
//! ## Examples
//!
//! ### Creating a client configuration
//!
//! ```rust
//! use s2n_tls_rs::{Config, Error};
//! use s2n_tls_rs::crypto::cipher_suites::TLS_AES_128_GCM_SHA256;
//! use s2n_tls_rs::handshake::NamedGroup;
//!
//! fn create_client_config() -> Result<Config, Error> {
//!     let mut config = Config::new_client();
//!     
//!     // Set the server name for SNI
//!     config.set_server_name("example.com".to_string())?;
//!     
//!     // Add trusted CA certificates
//!     // config.add_trusted_ca(ca_cert_data)?;
//!     
//!     // Configure cipher suites
//!     config.add_cipher_suite(TLS_AES_128_GCM_SHA256)?;
//!     
//!     // Configure named groups
//!     config.add_named_group(NamedGroup::X25519)?;
//!     
//!     Ok(config)
//! }
//! ```
//!
//! ### Creating a server configuration
//!
//! ```rust
//! use s2n_tls_rs::{Config, Error};
//! use s2n_tls_rs::crypto::cipher_suites::TLS_AES_128_GCM_SHA256;
//! use s2n_tls_rs::handshake::NamedGroup;
//!
//! fn create_server_config(
//!     cert_data: Vec<u8>,
//!     key_data: Vec<u8>
//! ) -> Result<Config, Error> {
//!     let mut config = Config::new_server();
//!     
//!     // Set the server certificate and private key
//!     config.set_server_certificate(cert_data)?;
//!     config.set_server_private_key(key_data)?;
//!     
//!     // Configure cipher suites
//!     config.add_cipher_suite(TLS_AES_128_GCM_SHA256)?;
//!     
//!     // Configure named groups
//!     config.add_named_group(NamedGroup::X25519)?;
//!     
//!     Ok(config)
//! }
//! ```

use crate::error::Error;
use crate::state::{ConnectionConfig, ConnectionMode};
use crate::crypto::CipherSuite;
use crate::handshake::NamedGroup;

/// TLS configuration
#[derive(Debug, Clone)]
pub struct Config {
    /// Connection mode
    mode: ConnectionMode,
    /// Server name
    server_name: Option<String>,
    /// Trusted CA certificates
    trusted_cas: Vec<Vec<u8>>,
    /// Client certificate
    client_certificate: Option<Vec<u8>>,
    /// Client private key
    client_private_key: Option<Vec<u8>>,
    /// Server certificate
    server_certificate: Option<Vec<u8>>,
    /// Server private key
    server_private_key: Option<Vec<u8>>,
    /// Supported cipher suites
    cipher_suites: Vec<CipherSuite>,
    /// Supported named groups
    named_groups: Vec<NamedGroup>,
    /// OCSP stapling enabled
    ocsp_stapling_enabled: bool,
}

impl Config {
    /// Create a new client configuration
    pub fn new_client() -> Self {
        Self {
            mode: ConnectionMode::Client,
            server_name: None,
            trusted_cas: Vec::new(),
            client_certificate: None,
            client_private_key: None,
            server_certificate: None,
            server_private_key: None,
            cipher_suites: Vec::new(),
            named_groups: Vec::new(),
            ocsp_stapling_enabled: false,
        }
    }
    
    /// Create a new server configuration
    pub fn new_server() -> Self {
        Self {
            mode: ConnectionMode::Server,
            server_name: None,
            trusted_cas: Vec::new(),
            client_certificate: None,
            client_private_key: None,
            server_certificate: None,
            server_private_key: None,
            cipher_suites: Vec::new(),
            named_groups: Vec::new(),
            ocsp_stapling_enabled: false,
        }
    }
    
    /// Set the server name
    pub fn set_server_name(&mut self, server_name: String) -> Result<&mut Self, Error> {
        self.server_name = Some(server_name);
        Ok(self)
    }
    
    /// Add a trusted CA certificate
    pub fn add_trusted_ca(&mut self, cert_data: Vec<u8>) -> Result<&mut Self, Error> {
        self.trusted_cas.push(cert_data);
        Ok(self)
    }
    
    /// Set the client certificate
    pub fn set_client_certificate(&mut self, cert_data: Vec<u8>) -> Result<&mut Self, Error> {
        self.client_certificate = Some(cert_data);
        Ok(self)
    }
    
    /// Set the client private key
    pub fn set_client_private_key(&mut self, key_data: Vec<u8>) -> Result<&mut Self, Error> {
        self.client_private_key = Some(key_data);
        Ok(self)
    }
    
    /// Set the server certificate
    pub fn set_server_certificate(&mut self, cert_data: Vec<u8>) -> Result<&mut Self, Error> {
        self.server_certificate = Some(cert_data);
        Ok(self)
    }
    
    /// Set the server private key
    pub fn set_server_private_key(&mut self, key_data: Vec<u8>) -> Result<&mut Self, Error> {
        self.server_private_key = Some(key_data);
        Ok(self)
    }
    
    /// Add a cipher suite
    pub fn add_cipher_suite(&mut self, cipher_suite: CipherSuite) -> Result<&mut Self, Error> {
        self.cipher_suites.push(cipher_suite);
        Ok(self)
    }
    
    /// Add a named group
    pub fn add_named_group(&mut self, named_group: NamedGroup) -> Result<&mut Self, Error> {
        self.named_groups.push(named_group);
        Ok(self)
    }
    
    /// Enable OCSP stapling
    pub fn enable_ocsp_stapling(&mut self) -> Result<&mut Self, Error> {
        self.ocsp_stapling_enabled = true;
        Ok(self)
    }
    
    /// Disable OCSP stapling
    pub fn disable_ocsp_stapling(&mut self) -> Result<&mut Self, Error> {
        self.ocsp_stapling_enabled = false;
        Ok(self)
    }
    
    /// Get the connection mode
    pub fn mode(&self) -> ConnectionMode {
        self.mode
    }
    
    /// Get the server name
    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }
    
    /// Get the trusted CA certificates
    pub fn trusted_cas(&self) -> &[Vec<u8>] {
        &self.trusted_cas
    }
    
    /// Get the client certificate
    pub fn client_certificate(&self) -> Option<&[u8]> {
        self.client_certificate.as_deref()
    }
    
    /// Get the client private key
    pub fn client_private_key(&self) -> Option<&[u8]> {
        self.client_private_key.as_deref()
    }
    
    /// Get the server certificate
    pub fn server_certificate(&self) -> Option<&[u8]> {
        self.server_certificate.as_deref()
    }
    
    /// Get the server private key
    pub fn server_private_key(&self) -> Option<&[u8]> {
        self.server_private_key.as_deref()
    }
    
    /// Get the supported cipher suites
    pub fn cipher_suites(&self) -> &[CipherSuite] {
        &self.cipher_suites
    }
    
    /// Get the supported named groups
    pub fn named_groups(&self) -> &[NamedGroup] {
        &self.named_groups
    }
    
    /// Check if OCSP stapling is enabled
    pub fn is_ocsp_stapling_enabled(&self) -> bool {
        self.ocsp_stapling_enabled
    }
    
    /// Convert to a connection configuration
    pub(crate) fn to_connection_config(&self) -> ConnectionConfig {
        let mut config = ConnectionConfig::new(self.mode);
        
        if let Some(server_name) = &self.server_name {
            config.set_server_name(server_name.clone());
        }
        
        for cert_data in &self.trusted_cas {
            config.add_trusted_ca(cert_data.clone());
        }
        
        if let Some(cert_data) = &self.client_certificate {
            config.set_client_certificate(cert_data.clone());
        }
        
        if let Some(key_data) = &self.client_private_key {
            config.set_client_private_key(key_data.clone());
        }
        
        if let Some(cert_data) = &self.server_certificate {
            config.set_server_certificate(cert_data.clone());
        }
        
        if let Some(key_data) = &self.server_private_key {
            config.set_server_private_key(key_data.clone());
        }
        
        for cipher_suite in &self.cipher_suites {
            config.add_cipher_suite(*cipher_suite);
        }
        
        for named_group in &self.named_groups {
            config.add_named_group(*named_group);
        }
        
        if self.ocsp_stapling_enabled {
            config.enable_ocsp_stapling();
        }
        
        config
    }
}
