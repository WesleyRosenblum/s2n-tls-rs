// FFI module
// Contains FFI compatibility code for interacting with the C implementation

use crate::error::{Error, ErrorType, BlockedError, ProtocolError, CryptoError, InternalError, UsageError};
use std::ffi::CStr;
use std::os::raw::{c_char, c_int};

/// Convert a Rust Error to a C s2n_errno value
pub fn error_to_s2n_errno(err: &Error) -> c_int {
    // This is a more detailed implementation of the to_s2n_errno method
    // It maps specific Rust error variants to their C counterparts
    match err {
        Error::Io(_) => 1, // S2N_ERR_IO
        Error::Closed => 2, // S2N_ERR_CLOSED
        Error::Blocked(BlockedError::Io) => 3, // S2N_ERR_IO_BLOCKED
        Error::Blocked(BlockedError::Async) => 4, // S2N_ERR_ASYNC_BLOCKED
        Error::Blocked(BlockedError::EarlyData) => 5, // S2N_ERR_EARLY_DATA_BLOCKED
        Error::Blocked(BlockedError::AppData) => 6, // S2N_ERR_APP_DATA_BLOCKED
        Error::Alert(_) => 7, // S2N_ERR_ALERT
        Error::Protocol { kind, .. } => match kind {
            ProtocolError::Encrypt => 8, // S2N_ERR_ENCRYPT
            ProtocolError::Decrypt => 9, // S2N_ERR_DECRYPT
            ProtocolError::BadMessage => 10, // S2N_ERR_BAD_MESSAGE
            ProtocolError::CipherNotSupported => 11, // S2N_ERR_CIPHER_NOT_SUPPORTED
            ProtocolError::NoApplicationProtocol => 12, // S2N_ERR_NO_APPLICATION_PROTOCOL
            ProtocolError::FallbackDetected => 13, // S2N_ERR_FALLBACK_DETECTED
            ProtocolError::ProtocolVersionUnsupported => 14, // S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED
            ProtocolError::BadKeyShare => 15, // S2N_ERR_BAD_KEY_SHARE
            ProtocolError::Cancelled => 16, // S2N_ERR_CANCELLED
            ProtocolError::ProtocolDowngradeDetected => 17, // S2N_ERR_PROTOCOL_DOWNGRADE_DETECTED
            ProtocolError::RecordLimit => 18, // S2N_ERR_RECORD_LIMIT
            _ => 19, // Generic protocol error
        },
        Error::Crypto { kind, .. } => match kind {
            CryptoError::KeyInit => 20, // S2N_ERR_KEY_INIT
            CryptoError::KeyDestroy => 21, // S2N_ERR_KEY_DESTROY
            _ => 22, // Generic crypto error
        },
        Error::Internal { kind, .. } => match kind {
            InternalError::Alloc => 23, // S2N_ERR_ALLOC
            InternalError::NoMem => 24, // S2N_ERR_NOMEM
            InternalError::Null => 25, // S2N_ERR_NULL
            InternalError::Safety => 26, // S2N_ERR_SAFETY
            InternalError::Initialized => 27, // S2N_ERR_INITIALIZED
            InternalError::NotInitialized => 28, // S2N_ERR_NOT_INITIALIZED
            InternalError::SizeMismatch => 29, // S2N_ERR_SIZE_MISMATCH
            InternalError::Unimplemented => 30, // S2N_ERR_UNIMPLEMENTED
            _ => 31, // Generic internal error
        },
        Error::Usage { kind, .. } => match kind {
            UsageError::ServerMode => 32, // S2N_ERR_SERVER_MODE
            UsageError::ClientMode => 33, // S2N_ERR_CLIENT_MODE
            UsageError::ClientModeDisabled => 34, // S2N_ERR_CLIENT_MODE_DISABLED
            UsageError::InvalidArgument => 35, // S2N_ERR_INVALID_ARGUMENT
            _ => 36, // Generic usage error
        },
        Error::Config { .. } => 37, // Generic config error
    }
}

/// Convert a C s2n_errno value to a Rust Error
pub fn s2n_errno_to_error(errno: c_int) -> Error {
    // This is a more detailed implementation of the from_s2n_errno method
    // It maps specific C error codes to their Rust counterparts
    match errno {
        0 => unreachable!("S2N_ERR_OK should not be converted to an error"),
        1 => Error::Io(std::io::Error::new(std::io::ErrorKind::Other, "I/O error")),
        2 => Error::Closed,
        3 => Error::Blocked(BlockedError::Io),
        4 => Error::Blocked(BlockedError::Async),
        5 => Error::Blocked(BlockedError::EarlyData),
        6 => Error::Blocked(BlockedError::AppData),
        7 => Error::Alert(0),
        8 => Error::protocol(ProtocolError::Encrypt),
        9 => Error::protocol(ProtocolError::Decrypt),
        10 => Error::protocol(ProtocolError::BadMessage),
        11 => Error::protocol(ProtocolError::CipherNotSupported),
        12 => Error::protocol(ProtocolError::NoApplicationProtocol),
        13 => Error::protocol(ProtocolError::FallbackDetected),
        14 => Error::protocol(ProtocolError::ProtocolVersionUnsupported),
        15 => Error::protocol(ProtocolError::BadKeyShare),
        16 => Error::protocol(ProtocolError::Cancelled),
        17 => Error::protocol(ProtocolError::ProtocolDowngradeDetected),
        18 => Error::protocol(ProtocolError::RecordLimit),
        19 => Error::protocol(ProtocolError::Other("Unknown protocol error".to_string())),
        20 => Error::crypto(CryptoError::KeyInit),
        21 => Error::crypto(CryptoError::KeyDestroy),
        22 => Error::crypto(CryptoError::Other("Unknown crypto error".to_string())),
        23 => Error::internal(InternalError::Alloc),
        24 => Error::internal(InternalError::NoMem),
        25 => Error::internal(InternalError::Null),
        26 => Error::internal(InternalError::Safety),
        27 => Error::internal(InternalError::Initialized),
        28 => Error::internal(InternalError::NotInitialized),
        29 => Error::internal(InternalError::SizeMismatch),
        30 => Error::internal(InternalError::Unimplemented),
        31 => Error::internal(InternalError::Other("Unknown internal error".to_string())),
        32 => Error::usage(UsageError::ServerMode),
        33 => Error::usage(UsageError::ClientMode),
        34 => Error::usage(UsageError::ClientModeDisabled),
        35 => Error::usage(UsageError::InvalidArgument),
        36 => Error::usage(UsageError::Other("Unknown usage error".to_string())),
        37 => Error::config(crate::error::ConfigError::Other("Unknown config error".to_string())),
        _ => Error::internal(InternalError::Other(format!("Unknown error code: {}", errno))),
    }
}

/// Get the error type from a C s2n_errno value
pub fn s2n_error_get_type(errno: c_int) -> ErrorType {
    let err = s2n_errno_to_error(errno);
    err.error_type()
}

/// Convert a C string to a Rust string
pub unsafe fn c_str_to_string(s: *const c_char) -> String {
    if s.is_null() {
        return String::new();
    }
    
    CStr::from_ptr(s)
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{Error, BlockedError, ProtocolError};
    
    #[test]
    fn test_error_conversion() {
        let err = Error::protocol(ProtocolError::BadMessage);
        let errno = error_to_s2n_errno(&err);
        let err2 = s2n_errno_to_error(errno);
        
        match err2 {
            Error::Protocol { kind, .. } => {
                assert!(matches!(kind, ProtocolError::BadMessage));
            }
            _ => panic!("Expected Protocol error"),
        }
    }
    
    #[test]
    fn test_blocked_error_conversion() {
        let err = Error::Blocked(BlockedError::Io);
        let errno = error_to_s2n_errno(&err);
        let err2 = s2n_errno_to_error(errno);
        
        assert!(matches!(err2, Error::Blocked(BlockedError::Io)));
    }
    
    #[test]
    fn test_error_type_conversion() {
        let errno = 10; // S2N_ERR_BAD_MESSAGE
        let error_type = s2n_error_get_type(errno);
        assert_eq!(error_type, ErrorType::Protocol);
    }
}
