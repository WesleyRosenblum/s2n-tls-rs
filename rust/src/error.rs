//! Error types for the s2n-tls-rs library
//!
//! This module provides error types for the s2n-tls-rs library.
//! It uses the thiserror crate to define error types.

use thiserror::Error;

/// Error type for the s2n-tls-rs library
#[derive(Debug, Error)]
pub enum Error {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    
    /// TLS protocol error
    #[error("TLS protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    
    /// Crypto error
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
    
    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),
    
    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

/// TLS protocol error
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// Unexpected message
    #[error("Unexpected message: expected {expected}, got {actual}")]
    UnexpectedMessage {
        expected: String,
        actual: String,
    },
    
    /// Invalid record type
    #[error("Invalid record type: {0}")]
    InvalidRecordType(u8),
    
    /// Protocol version not supported
    #[error("Protocol version not supported: {major}.{minor}")]
    UnsupportedVersion {
        major: u8,
        minor: u8,
    },
    
    /// Handshake failure
    #[error("Handshake failure: {0}")]
    HandshakeFailure(String),
    
    /// Alert received
    #[error("Alert received: {level} {description}")]
    AlertReceived {
        level: u8,
        description: u8,
    },
}

/// Crypto error
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Key generation error
    #[error("Key generation error: {0}")]
    KeyGeneration(String),
    
    /// Encryption error
    #[error("Encryption error: {0}")]
    Encryption(String),
    
    /// Decryption error
    #[error("Decryption error: {0}")]
    Decryption(String),
    
    /// Signature error
    #[error("Signature error: {0}")]
    Signature(String),
    
    /// Verification error
    #[error("Verification error: {0}")]
    Verification(String),
    
    /// Certificate error
    #[error("Certificate error: {0}")]
    Certificate(String),
}

/// Configuration error
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Missing configuration
    #[error("Missing configuration: {0}")]
    Missing(String),
    
    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    Invalid(String),
    
    /// Incompatible configuration
    #[error("Incompatible configuration: {0}")]
    Incompatible(String),
}