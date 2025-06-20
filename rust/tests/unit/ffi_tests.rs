// Unit tests for the FFI module

use s2n_tls_rs::{
    Error, ErrorType, BlockedError, ProtocolError, CryptoError, ConfigError, InternalError, UsageError,
};
use std::io;
use std::ffi::CString;

// Import the FFI functions for testing
use s2n_tls_rs::ffi::{error_to_s2n_errno, s2n_errno_to_error, s2n_error_get_type, c_str_to_string};

#[test]
fn test_error_to_s2n_errno() {
    // Test converting Rust errors to C s2n_errno values
    let io_err = Error::Io(io::Error::new(io::ErrorKind::Other, "test io error"));
    let protocol_err = Error::protocol(ProtocolError::BadMessage);
    let crypto_err = Error::crypto(CryptoError::KeyInit);
    let config_err = Error::config(ConfigError::InvalidCipherPreferences);
    let internal_err = Error::internal(InternalError::Alloc);
    let usage_err = Error::usage(UsageError::ServerMode);
    let closed_err = Error::Closed;
    let blocked_err = Error::Blocked(BlockedError::Io);
    let alert_err = Error::Alert(10);
    
    // Verify errno values are valid
    assert!(error_to_s2n_errno(&io_err) > 0);
    assert!(error_to_s2n_errno(&protocol_err) > 0);
    assert!(error_to_s2n_errno(&crypto_err) > 0);
    assert!(error_to_s2n_errno(&config_err) > 0);
    assert!(error_to_s2n_errno(&internal_err) > 0);
    assert!(error_to_s2n_errno(&usage_err) > 0);
    assert!(error_to_s2n_errno(&closed_err) > 0);
    assert!(error_to_s2n_errno(&blocked_err) > 0);
    assert!(error_to_s2n_errno(&alert_err) > 0);
}

#[test]
fn test_s2n_errno_to_error() {
    // Test converting C s2n_errno values to Rust errors
    let err1 = s2n_errno_to_error(1); // S2N_ERR_IO
    let err2 = s2n_errno_to_error(2); // S2N_ERR_CLOSED
    let err3 = s2n_errno_to_error(3); // S2N_ERR_IO_BLOCKED
    let err4 = s2n_errno_to_error(7); // S2N_ERR_ALERT
    let err5 = s2n_errno_to_error(10); // S2N_ERR_BAD_MESSAGE
    
    // Verify error types
    assert_eq!(err1.error_type(), ErrorType::Io);
    assert_eq!(err2.error_type(), ErrorType::Closed);
    assert_eq!(err3.error_type(), ErrorType::Blocked);
    assert_eq!(err4.error_type(), ErrorType::Alert);
    
    // Verify specific error variants
    match err5 {
        Error::Protocol { kind, .. } => {
            assert!(matches!(kind, ProtocolError::BadMessage));
        }
        _ => panic!("Expected Protocol error"),
    }
}

#[test]
fn test_error_roundtrip() {
    // Test round-trip conversion from Rust error to C errno and back
    let original_err = Error::protocol(ProtocolError::BadMessage);
    let errno = error_to_s2n_errno(&original_err);
    let roundtrip_err = s2n_errno_to_error(errno);
    
    // Verify error types match after round-trip
    assert_eq!(original_err.error_type(), roundtrip_err.error_type());
    
    // Verify specific error variants for protocol errors
    match roundtrip_err {
        Error::Protocol { kind, .. } => {
            assert!(matches!(kind, ProtocolError::BadMessage));
        }
        _ => panic!("Expected Protocol error after round-trip"),
    }
}

#[test]
fn test_s2n_error_get_type() {
    // Test getting error type from C s2n_errno values
    let type1 = s2n_error_get_type(1); // S2N_ERR_IO
    let type2 = s2n_error_get_type(2); // S2N_ERR_CLOSED
    let type3 = s2n_error_get_type(3); // S2N_ERR_IO_BLOCKED
    let type4 = s2n_error_get_type(7); // S2N_ERR_ALERT
    let type5 = s2n_error_get_type(10); // S2N_ERR_BAD_MESSAGE
    
    // Verify error types
    assert_eq!(type1, ErrorType::Io);
    assert_eq!(type2, ErrorType::Closed);
    assert_eq!(type3, ErrorType::Blocked);
    assert_eq!(type4, ErrorType::Alert);
    assert_eq!(type5, ErrorType::Protocol);
}

#[test]
fn test_c_str_to_string() {
    // Test converting C strings to Rust strings
    let rust_str = "Hello, world!";
    let c_str = CString::new(rust_str).unwrap();
    let ptr = c_str.as_ptr();
    
    // Convert C string to Rust string
    let result = unsafe { c_str_to_string(ptr) };
    
    // Verify conversion
    assert_eq!(result, rust_str);
    
    // Test null pointer
    let null_result = unsafe { c_str_to_string(std::ptr::null()) };
    assert_eq!(null_result, "");
}
