// Error module
// Contains error types for the library

use thiserror::Error;

/// Error categories, matching s2n-tls C implementation's error types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorType {
    /// No error
    Ok,
    /// I/O error
    Io,
    /// Connection closed
    Closed,
    /// Operation would block
    Blocked,
    /// TLS alert received
    Alert,
    /// Protocol error
    Protocol,
    /// Internal error
    Internal,
    /// Usage error
    Usage,
}

/// Main error type for s2n-tls-rs
#[derive(Error, Debug)]
pub enum Error {
    /// I/O errors
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    
    /// Protocol errors
    #[error("TLS protocol error: {kind}")]
    Protocol {
        /// Specific kind of protocol error
        kind: ProtocolError,
        /// Source file where the error occurred
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
    
    /// Cryptographic errors
    #[error("Crypto error: {kind}")]
    Crypto {
        /// Specific kind of crypto error
        kind: CryptoError,
        /// Source file where the error occurred
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
    
    /// Configuration errors
    #[error("Configuration error: {kind}")]
    Config {
        /// Specific kind of configuration error
        kind: ConfigError,
        /// Source file where the error occurred
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
    
    /// Internal errors
    #[error("Internal error: {kind}")]
    Internal {
        /// Specific kind of internal error
        kind: InternalError,
        /// Source file where the error occurred
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
    
    /// Usage errors
    #[error("Usage error: {kind}")]
    Usage {
        /// Specific kind of usage error
        kind: UsageError,
        /// Source file where the error occurred
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
    
    /// Connection closed
    #[error("Connection closed")]
    Closed,
    
    /// Operation would block
    #[error("Operation would block: {0}")]
    Blocked(BlockedError),
    
    /// TLS alert received
    #[error("TLS alert received: {0}")]
    Alert(u8),
}

/// Protocol-specific errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// Error encrypting data
    #[error("error encrypting data")]
    Encrypt,
    
    /// Error decrypting data
    #[error("error decrypting data")]
    Decrypt,
    
    /// Bad message encountered
    #[error("bad message encountered")]
    BadMessage,
    
    /// Cipher not supported
    #[error("cipher not supported")]
    CipherNotSupported,
    
    /// No application protocol
    #[error("no supported application protocol to negotiate")]
    NoApplicationProtocol,
    
    /// Fallback detected
    #[error("TLS fallback detected")]
    FallbackDetected,
    
    /// Certificate validation errors
    #[error("certificate validation error: {0}")]
    CertificateValidation(CertificateError),
    
    /// Protocol version unsupported
    #[error("TLS protocol version is not supported by configuration")]
    ProtocolVersionUnsupported,
    
    /// Bad key share
    #[error("bad key share received")]
    BadKeyShare,
    
    /// Handshake cancelled
    #[error("handshake was cancelled")]
    Cancelled,
    
    /// Protocol downgrade detected
    #[error("protocol downgrade detected")]
    ProtocolDowngradeDetected,
    
    /// Record limit reached
    #[error("TLS record limit reached")]
    RecordLimit,
    
    /// Extension errors
    #[error("extension error: {0}")]
    Extension(ExtensionError),
    
    /// Other protocol error
    #[error("{0}")]
    Other(String),
}

/// Certificate-specific errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CertificateError {
    /// Certificate is untrusted
    #[error("certificate is untrusted")]
    Untrusted,
    
    /// Certificate has been revoked
    #[error("certificate has been revoked")]
    Revoked,
    
    /// Certificate is not yet valid
    #[error("certificate is not yet valid")]
    NotYetValid,
    
    /// Certificate has expired
    #[error("certificate has expired")]
    Expired,
    
    /// Certificate type is unsupported
    #[error("certificate type is unsupported")]
    TypeUnsupported,
    
    /// Certificate is invalid
    #[error("certificate is invalid")]
    Invalid,
    
    /// Maximum certificate chain depth exceeded
    #[error("maximum certificate chain depth exceeded")]
    MaxChainDepthExceeded,
    
    /// Certificate rejected by application
    #[error("certificate failed custom application validation")]
    Rejected,
    
    /// Unhandled critical extension
    #[error("unhandled critical certificate extension")]
    UnhandledCriticalExtension,
    
    /// Other certificate error
    #[error("{0}")]
    Other(String),
}

/// Extension-specific errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ExtensionError {
    /// Missing extension
    #[error("mandatory extension not received")]
    Missing,
    
    /// Unsupported extension
    #[error("unsupported extension")]
    Unsupported,
    
    /// Duplicate extension
    #[error("duplicate extension")]
    Duplicate,
    
    /// Invalid extension data
    #[error("invalid extension data")]
    InvalidData,
    
    /// Other extension error
    #[error("{0}")]
    Other(String),
}

/// Cryptographic errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Key initialization error
    #[error("error initializing encryption key")]
    KeyInit,
    
    /// Key destruction error
    #[error("error destroying encryption key")]
    KeyDestroy,
    
    /// Hash errors
    #[error("hash error: {0}")]
    Hash(HashError),
    
    /// HMAC errors
    #[error("HMAC error: {0}")]
    Hmac(String),
    
    /// HKDF errors
    #[error("HKDF error")]
    HkdfError,
    
    /// Key exchange errors
    #[error("key exchange error: {0}")]
    KeyExchange(KeyExchangeError),
    
    /// Signature errors
    #[error("signature error: {0}")]
    Signature(String),
    
    /// Invalid key size
    #[error("invalid key size")]
    InvalidKeySize,
    
    /// Invalid nonce size
    #[error("invalid nonce size")]
    InvalidNonceSize,
    
    /// Invalid secret size
    #[error("invalid secret size")]
    InvalidSecretSize,
    
    /// Encryption failed
    #[error("encryption operation failed")]
    EncryptionFailed,
    
    /// Decryption failed
    #[error("decryption operation failed")]
    DecryptionFailed,
    
    /// Random generation failed
    #[error("random number generation failed")]
    RandomGenerationFailed,
    
    /// Other crypto error
    #[error("{0}")]
    Other(String),
}

/// Hash-specific errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum HashError {
    /// Hash digest failed
    #[error("failed to create hash digest")]
    DigestFailed,
    
    /// Hash initialization failed
    #[error("error initializing hash")]
    InitFailed,
    
    /// Hash update failed
    #[error("error updating hash")]
    UpdateFailed,
    
    /// Hash copy failed
    #[error("error copying hash")]
    CopyFailed,
    
    /// Hash wipe failed
    #[error("error wiping hash")]
    WipeFailed,
    
    /// Hash not ready
    #[error("hash not in a valid state for the attempted operation")]
    NotReady,
    
    /// Invalid hash algorithm
    #[error("invalid hash algorithm")]
    InvalidAlgorithm,
    
    /// Other hash error
    #[error("{0}")]
    Other(String),
}

/// Key exchange errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum KeyExchangeError {
    /// DH serializing error
    #[error("error serializing Diffie-Hellman parameters")]
    DhSerializing,
    
    /// DH shared secret error
    #[error("error computing Diffie-Hellman shared secret")]
    DhSharedSecret,
    
    /// DH writing public key error
    #[error("error writing Diffie-Hellman public key")]
    DhWritingPublicKey,
    
    /// DH failed signing error
    #[error("error signing Diffie-Hellman values")]
    DhFailedSigning,
    
    /// DH copying parameters error
    #[error("error copying Diffie-Hellman parameters")]
    DhCopyingParameters,
    
    /// DH generating parameters error
    #[error("error generating Diffie-Hellman parameters")]
    DhGeneratingParameters,
    
    /// ECDHE key generation error
    #[error("failed to generate an ECDHE key")]
    EcdheGenKey,
    
    /// ECDHE shared secret error
    #[error("error computing ECDHE shared secret")]
    EcdheSharedSecret,
    
    /// ECDHE unsupported curve error
    #[error("unsupported EC curve was presented during an ECDHE handshake")]
    EcdheUnsupportedCurve,
    
    /// ECDHE invalid public key error
    #[error("failed to validate the peer's point on the elliptic curve")]
    EcdheInvalidPublicKey,
    
    /// ECDHE serializing error
    #[error("error serializing ECDHE public")]
    EcdheSerializing,
    
    /// Other key exchange error
    #[error("{0}")]
    Other(String),
}

/// Configuration errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// Invalid cipher preferences
    #[error("invalid cipher preferences")]
    InvalidCipherPreferences,
    
    /// Invalid application protocol
    #[error("invalid application protocol")]
    InvalidApplicationProtocol,
    
    /// Invalid signature algorithms preferences
    #[error("invalid signature algorithms preferences")]
    InvalidSignatureAlgorithmsPreferences,
    
    /// Invalid ECC preferences
    #[error("invalid ECC preferences")]
    InvalidEccPreferences,
    
    /// Invalid security policy
    #[error("invalid security policy")]
    InvalidSecurityPolicy,
    
    /// Deprecated security policy
    #[error("deprecated security policy")]
    DeprecatedSecurityPolicy,
    
    /// Other configuration error
    #[error("{0}")]
    Other(String),
}

/// Internal errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum InternalError {
    /// Memory allocation error
    #[error("error allocating memory")]
    Alloc,
    
    /// No memory
    #[error("no memory")]
    NoMem,
    
    /// NULL pointer encountered
    #[error("NULL pointer encountered")]
    Null,
    
    /// Safety check failed
    #[error("a safety check failed")]
    Safety,
    
    /// Library not initialized
    #[error("library not initialized")]
    NotInitialized,
    
    /// Library already initialized
    #[error("library already initialized")]
    Initialized,
    
    /// Size mismatch
    #[error("size mismatch")]
    SizeMismatch,
    
    /// Unimplemented feature
    #[error("unimplemented feature")]
    Unimplemented,
    
    /// Invalid state
    #[error("invalid state")]
    InvalidState,
    
    /// Other internal error
    #[error("{0}")]
    Other(String),
}

/// Usage errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum UsageError {
    /// Operation not allowed in server mode
    #[error("operation not allowed in server mode")]
    ServerMode,
    
    /// Operation not allowed in client mode
    #[error("operation not allowed in client mode")]
    ClientMode,
    
    /// Client mode disabled
    #[error("client connections not allowed")]
    ClientModeDisabled,
    
    /// Invalid argument
    #[error("invalid argument provided")]
    InvalidArgument,
    
    /// Key mismatch
    #[error("public and private key do not match")]
    KeyMismatch,
    
    /// Invalid PEM
    #[error("invalid PEM encountered")]
    InvalidPem,
    
    /// No certificate in PEM
    #[error("no certificate in PEM")]
    NoCertificateInPem,
    
    /// Other usage error
    #[error("{0}")]
    Other(String),
}

/// Blocked operation errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum BlockedError {
    /// I/O would block
    #[error("underlying I/O operation would block")]
    Io,
    
    /// Async operation would block
    #[error("blocked on external async function invocation")]
    Async,
    
    /// Early data would block
    #[error("blocked on early data")]
    EarlyData,
    
    /// Application data would block
    #[error("blocked on application data during handshake")]
    AppData,
}

impl Error {
    /// Create a new protocol error
    pub fn protocol(kind: ProtocolError) -> Self {
        Self::Protocol {
            kind,
            source: None,
        }
    }
    
    /// Create a new protocol error with source
    pub fn protocol_with_source<E>(kind: ProtocolError, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Protocol {
            kind,
            source: Some(Box::new(source)),
        }
    }
    
    /// Create a new crypto error
    pub fn crypto(kind: CryptoError) -> Self {
        Self::Crypto {
            kind,
            source: None,
        }
    }
    
    /// Create a new crypto error with source
    pub fn crypto_with_source<E>(kind: CryptoError, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Crypto {
            kind,
            source: Some(Box::new(source)),
        }
    }
    
    /// Create a new config error
    pub fn config(kind: ConfigError) -> Self {
        Self::Config {
            kind,
            source: None,
        }
    }
    
    /// Create a new config error with source
    pub fn config_with_source<E>(kind: ConfigError, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Config {
            kind,
            source: Some(Box::new(source)),
        }
    }
    
    /// Create a new internal error
    pub fn internal(kind: InternalError) -> Self {
        Self::Internal {
            kind,
            source: None,
        }
    }
    
    /// Create a new internal error with source
    pub fn internal_with_source<E>(kind: InternalError, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Internal {
            kind,
            source: Some(Box::new(source)),
        }
    }
    
    /// Create a new usage error
    pub fn usage(kind: UsageError) -> Self {
        Self::Usage {
            kind,
            source: None,
        }
    }
    
    /// Create a new usage error with source
    pub fn usage_with_source<E>(kind: UsageError, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Usage {
            kind,
            source: Some(Box::new(source)),
        }
    }
    
    /// Get the error type
    pub fn error_type(&self) -> ErrorType {
        match self {
            Self::Io(_) => ErrorType::Io,
            Self::Protocol { .. } => ErrorType::Protocol,
            Self::Crypto { .. } => ErrorType::Protocol,
            Self::Config { .. } => ErrorType::Usage,
            Self::Internal { .. } => ErrorType::Internal,
            Self::Usage { .. } => ErrorType::Usage,
            Self::Closed => ErrorType::Closed,
            Self::Blocked(_) => ErrorType::Blocked,
            Self::Alert(_) => ErrorType::Alert,
        }
    }
    
    /// Check if the error is a blocking error
    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Blocked(_))
    }
    
    /// Convert to a C s2n_errno value (for FFI compatibility)
    pub fn to_s2n_errno(&self) -> i32 {
        // This would map Rust errors to C s2n_errno values
        // Implementation would depend on the specific mapping needed
        // For now, return a placeholder value
        match self {
            Self::Io(_) => 1, // S2N_ERR_IO
            Self::Protocol { .. } => 5, // S2N_ERR_T_PROTO_START
            Self::Crypto { .. } => 5, // S2N_ERR_T_PROTO_START (crypto errors are in protocol category in C)
            Self::Config { .. } => 7, // S2N_ERR_T_USAGE_START
            Self::Internal { .. } => 6, // S2N_ERR_T_INTERNAL_START
            Self::Usage { .. } => 7, // S2N_ERR_T_USAGE_START
            Self::Closed => 2, // S2N_ERR_CLOSED
            Self::Blocked(_) => 3, // S2N_ERR_T_BLOCKED_START
            Self::Alert(_) => 4, // S2N_ERR_T_ALERT_START
        }
    }
    
    /// Create an error from a C s2n_errno value (for FFI compatibility)
    pub fn from_s2n_errno(errno: i32) -> Self {
        // This would create a Rust error from a C s2n_errno value
        // Implementation would depend on the specific mapping needed
        // For now, return a placeholder error
        match errno {
            0 => unreachable!("S2N_ERR_OK should not be converted to an error"),
            1 => Self::Io(std::io::Error::new(std::io::ErrorKind::Other, "I/O error")),
            2 => Self::Closed,
            3 => Self::Blocked(BlockedError::Io),
            4 => Self::Alert(0),
            5 => Self::protocol(ProtocolError::Other("Unknown protocol error".to_string())),
            6 => Self::internal(InternalError::Other("Unknown internal error".to_string())),
            7 => Self::usage(UsageError::Other("Unknown usage error".to_string())),
            _ => Self::internal(InternalError::Other(format!("Unknown error code: {}", errno))),
        }
    }
}

// The From<std::io::Error> implementation is provided by the #[from] attribute in the derive macro

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_type() {
        let io_err = Error::Io(std::io::Error::new(std::io::ErrorKind::Other, "test"));
        assert_eq!(io_err.error_type(), ErrorType::Io);
        
        let protocol_err = Error::protocol(ProtocolError::BadMessage);
        assert_eq!(protocol_err.error_type(), ErrorType::Protocol);
        
        let blocked_err = Error::Blocked(BlockedError::Io);
        assert_eq!(blocked_err.error_type(), ErrorType::Blocked);
        assert!(blocked_err.is_blocked());
    }
    
    #[test]
    fn test_error_display() {
        let err = Error::protocol(ProtocolError::BadMessage);
        assert_eq!(err.to_string(), "TLS protocol error: bad message encountered");
        
        let err = Error::crypto(CryptoError::KeyInit);
        assert_eq!(err.to_string(), "Crypto error: error initializing encryption key");
        
        let err = Error::Blocked(BlockedError::Io);
        assert_eq!(err.to_string(), "Operation would block: underlying I/O operation would block");
    }
    
    #[test]
    fn test_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::Other, "test");
        let err: Error = io_err.into();
        assert!(matches!(err, Error::Io(_)));
    }
    
    #[test]
    fn test_s2n_errno_conversion() {
        let err = Error::protocol(ProtocolError::BadMessage);
        let errno = err.to_s2n_errno();
        let err2 = Error::from_s2n_errno(errno);
        assert_eq!(err.error_type(), err2.error_type());
    }
}
