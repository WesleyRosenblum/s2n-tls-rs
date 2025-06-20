// Unit tests for the error module

use s2n_tls_rs::{
    Error, ErrorType, BlockedError, ProtocolError, CryptoError, ConfigError, InternalError, UsageError,
};
use std::io;

#[test]
fn test_error_creation() {
    // Test creating different types of errors
    let io_err = Error::Io(io::Error::new(io::ErrorKind::Other, "test io error"));
    let protocol_err = Error::protocol(ProtocolError::BadMessage);
    let crypto_err = Error::crypto(CryptoError::KeyInit);
    let config_err = Error::config(ConfigError::InvalidCipherPreferences);
    let internal_err = Error::internal(InternalError::Alloc);
    let usage_err = Error::usage(UsageError::ServerMode);
    let closed_err = Error::Closed;
    let blocked_err = Error::Blocked(BlockedError::Io);
    let alert_err = Error::Alert(10);
    
    // Verify error types
    assert_eq!(io_err.error_type(), ErrorType::Io);
    assert_eq!(protocol_err.error_type(), ErrorType::Protocol);
    assert_eq!(crypto_err.error_type(), ErrorType::Protocol); // Crypto errors are mapped to Protocol type
    assert_eq!(config_err.error_type(), ErrorType::Usage);
    assert_eq!(internal_err.error_type(), ErrorType::Internal);
    assert_eq!(usage_err.error_type(), ErrorType::Usage);
    assert_eq!(closed_err.error_type(), ErrorType::Closed);
    assert_eq!(blocked_err.error_type(), ErrorType::Blocked);
    assert_eq!(alert_err.error_type(), ErrorType::Alert);
}

#[test]
fn test_error_with_source() {
    // Test creating errors with source
    let protocol_err = Error::protocol_with_source(
        ProtocolError::BadMessage,
        io::Error::new(io::ErrorKind::Other, "source error"),
    );
    
    let crypto_err = Error::crypto_with_source(
        CryptoError::KeyInit,
        io::Error::new(io::ErrorKind::Other, "source error"),
    );
    
    let config_err = Error::config_with_source(
        ConfigError::InvalidCipherPreferences,
        io::Error::new(io::ErrorKind::Other, "source error"),
    );
    
    let internal_err = Error::internal_with_source(
        InternalError::Alloc,
        io::Error::new(io::ErrorKind::Other, "source error"),
    );
    
    let usage_err = Error::usage_with_source(
        UsageError::ServerMode,
        io::Error::new(io::ErrorKind::Other, "source error"),
    );
    
    // Verify error types
    assert_eq!(protocol_err.error_type(), ErrorType::Protocol);
    assert_eq!(crypto_err.error_type(), ErrorType::Protocol);
    assert_eq!(config_err.error_type(), ErrorType::Usage);
    assert_eq!(internal_err.error_type(), ErrorType::Internal);
    assert_eq!(usage_err.error_type(), ErrorType::Usage);
}

#[test]
fn test_error_display() {
    // Test error display formatting
    let io_err = Error::Io(io::Error::new(io::ErrorKind::Other, "test io error"));
    let protocol_err = Error::protocol(ProtocolError::BadMessage);
    let crypto_err = Error::crypto(CryptoError::KeyInit);
    let config_err = Error::config(ConfigError::InvalidCipherPreferences);
    let internal_err = Error::internal(InternalError::Alloc);
    let usage_err = Error::usage(UsageError::ServerMode);
    let closed_err = Error::Closed;
    let blocked_err = Error::Blocked(BlockedError::Io);
    let alert_err = Error::Alert(10);
    
    // Verify display strings
    assert!(io_err.to_string().contains("test io error"));
    assert_eq!(protocol_err.to_string(), "TLS protocol error: bad message encountered");
    assert_eq!(crypto_err.to_string(), "Crypto error: error initializing encryption key");
    assert_eq!(config_err.to_string(), "Configuration error: invalid cipher preferences");
    assert_eq!(internal_err.to_string(), "Internal error: error allocating memory");
    assert_eq!(usage_err.to_string(), "Usage error: operation not allowed in server mode");
    assert_eq!(closed_err.to_string(), "Connection closed");
    assert_eq!(blocked_err.to_string(), "Operation would block: underlying I/O operation would block");
    assert_eq!(alert_err.to_string(), "TLS alert received: 10");
}

#[test]
fn test_error_conversion() {
    // Test converting from std::io::Error
    let io_err = io::Error::new(io::ErrorKind::Other, "test io error");
    let s2n_err: Error = io_err.into();
    
    match s2n_err {
        Error::Io(err) => {
            assert_eq!(err.kind(), io::ErrorKind::Other);
            assert_eq!(err.to_string(), "test io error");
        }
        _ => panic!("Expected Io error"),
    }
}

#[test]
fn test_blocked_error() {
    // Test blocked errors
    let io_blocked = Error::Blocked(BlockedError::Io);
    let async_blocked = Error::Blocked(BlockedError::Async);
    let early_data_blocked = Error::Blocked(BlockedError::EarlyData);
    let app_data_blocked = Error::Blocked(BlockedError::AppData);
    
    // Verify is_blocked
    assert!(io_blocked.is_blocked());
    assert!(async_blocked.is_blocked());
    assert!(early_data_blocked.is_blocked());
    assert!(app_data_blocked.is_blocked());
    
    // Verify error types
    assert_eq!(io_blocked.error_type(), ErrorType::Blocked);
    assert_eq!(async_blocked.error_type(), ErrorType::Blocked);
    assert_eq!(early_data_blocked.error_type(), ErrorType::Blocked);
    assert_eq!(app_data_blocked.error_type(), ErrorType::Blocked);
    
    // Verify display strings
    assert_eq!(io_blocked.to_string(), "Operation would block: underlying I/O operation would block");
    assert_eq!(async_blocked.to_string(), "Operation would block: blocked on external async function invocation");
    assert_eq!(early_data_blocked.to_string(), "Operation would block: blocked on early data");
    assert_eq!(app_data_blocked.to_string(), "Operation would block: blocked on application data during handshake");
}

#[test]
fn test_protocol_errors() {
    // Test protocol errors
    let encrypt_err = Error::protocol(ProtocolError::Encrypt);
    let decrypt_err = Error::protocol(ProtocolError::Decrypt);
    let bad_message_err = Error::protocol(ProtocolError::BadMessage);
    let cipher_not_supported_err = Error::protocol(ProtocolError::CipherNotSupported);
    let no_app_protocol_err = Error::protocol(ProtocolError::NoApplicationProtocol);
    
    // Verify error types
    assert_eq!(encrypt_err.error_type(), ErrorType::Protocol);
    assert_eq!(decrypt_err.error_type(), ErrorType::Protocol);
    assert_eq!(bad_message_err.error_type(), ErrorType::Protocol);
    assert_eq!(cipher_not_supported_err.error_type(), ErrorType::Protocol);
    assert_eq!(no_app_protocol_err.error_type(), ErrorType::Protocol);
    
    // Verify display strings
    assert_eq!(encrypt_err.to_string(), "TLS protocol error: error encrypting data");
    assert_eq!(decrypt_err.to_string(), "TLS protocol error: error decrypting data");
    assert_eq!(bad_message_err.to_string(), "TLS protocol error: bad message encountered");
    assert_eq!(cipher_not_supported_err.to_string(), "TLS protocol error: cipher not supported");
    assert_eq!(no_app_protocol_err.to_string(), "TLS protocol error: no supported application protocol to negotiate");
}

#[test]
fn test_crypto_errors() {
    // Test crypto errors
    let key_init_err = Error::crypto(CryptoError::KeyInit);
    let key_destroy_err = Error::crypto(CryptoError::KeyDestroy);
    let hash_err = Error::crypto(CryptoError::Hash(s2n_tls_rs::HashError::DigestFailed));
    let hmac_err = Error::crypto(CryptoError::Hmac("test hmac error".to_string()));
    
    // Verify error types
    assert_eq!(key_init_err.error_type(), ErrorType::Protocol);
    assert_eq!(key_destroy_err.error_type(), ErrorType::Protocol);
    assert_eq!(hash_err.error_type(), ErrorType::Protocol);
    assert_eq!(hmac_err.error_type(), ErrorType::Protocol);
    
    // Verify display strings
    assert_eq!(key_init_err.to_string(), "Crypto error: error initializing encryption key");
    assert_eq!(key_destroy_err.to_string(), "Crypto error: error destroying encryption key");
    assert_eq!(hash_err.to_string(), "Crypto error: hash error: failed to create hash digest");
    assert_eq!(hmac_err.to_string(), "Crypto error: HMAC error: test hmac error");
}

#[test]
fn test_s2n_errno_conversion() {
    // Test converting to/from s2n_errno
    let err = Error::protocol(ProtocolError::BadMessage);
    let errno = err.to_s2n_errno();
    assert!(errno > 0); // Should be a valid error code
    
    let err2 = Error::from_s2n_errno(errno);
    assert_eq!(err.error_type(), err2.error_type());
}
