//! # s2n-tls-rs
//!
//! A memory-safe TLS implementation in Rust compatible with s2n-tls.
//!
//! This library implements the TLS 1.3 protocol as specified in RFC 8446.
//! It is designed to be compatible with the s2n-tls C implementation while
//! leveraging Rust's safety guarantees.
//!
//! ## Features
//!
//! - Memory-safe TLS implementation in Rust
//! - Compatible with s2n-tls C implementation
//! - Uses aws-lc-rs for cryptographic operations
//! - Supports TLS 1.3 protocol (RFC 8446)
//! - Provides both client and server functionality
//! - Zero-copy parsing with the zerocopy crate
//!
//! ## Getting Started
//!
//! To use s2n-tls-rs in your project, add it as a dependency in your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! s2n-tls-rs = "0.1.0"
//! ```
//!
//! ## Basic Usage
//!
//! Here's a simple example of using s2n-tls-rs as a client:
//!
//! ```rust
//! use s2n_tls_rs::{init, Config, Connection};
//! use s2n_tls_rs::crypto::cipher_suites::TLS_AES_128_GCM_SHA256;
//! use s2n_tls_rs::handshake::NamedGroup;
//! use std::io::{Read, Write};
//! use std::net::TcpStream;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Initialize the library
//!     init()?;
//!
//!     // Create a client configuration
//!     let mut config = Config::new_client();
//!     config.set_server_name("example.com".to_string())?;
//!     config.add_cipher_suite(TLS_AES_128_GCM_SHA256)?;
//!     config.add_named_group(NamedGroup::X25519)?;
//!
//!     // Create a client connection
//!     let mut connection = Connection::new(config);
//!     connection.initialize()?;
//!
//!     // Connect to the server
//!     let mut stream = TcpStream::connect("example.com:443")?;
//!
//!     // Perform the TLS handshake
//!     connection.negotiate()?;
//!
//!     // Send data
//!     connection.send(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")?;
//!
//!     // Process the output
//!     let mut output_buffer = [0; 16384];
//!     let len = connection.process_output(&mut output_buffer)?;
//!     stream.write_all(&output_buffer[..len])?;
//!
//!     // Receive data
//!     let mut response_buffer = [0; 16384];
//!     let bytes_read = stream.read(&mut response_buffer)?;
//!     connection.process_input(&response_buffer[..bytes_read])?;
//!
//!     // Get the decrypted data
//!     let mut decrypted_buffer = [0; 16384];
//!     let decrypted_bytes = connection.recv(&mut decrypted_buffer)?;
//!     println!("{}", String::from_utf8_lossy(&decrypted_buffer[..decrypted_bytes]));
//!
//!     // Close the connection
//!     connection.close()?;
//!
//!     Ok(())
//! }
//! ```
//!
//! For more examples, see the `examples` directory.

// Re-export public API
pub mod api;
pub use api::{Config, Connection, BlockedStatus, ConnectionMode};

// Internal modules
mod buffer;
mod crypto;
mod error;
#[cfg(any(test, feature = "testing"))]
pub mod ffi;
#[cfg(not(any(test, feature = "testing")))]
mod ffi;
mod io;
mod security_policy;
mod state;
mod tls;
mod utils;

// Re-export modules for testing
#[cfg(any(test, feature = "testing"))]
pub mod buffer_pub {
    pub use crate::buffer::*;
}
#[cfg(any(test, feature = "testing"))]
pub mod handshake;
#[cfg(any(test, feature = "testing"))]
pub mod record;
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    pub mod io {
        pub use crate::io::{IoProvider, FdIoProvider, RwIoProvider};
    }
    
    pub mod security_policy {
        pub use crate::security_policy::{SecurityPolicy, SecurityPolicyBuilder, SecurityPolicyRegistry, TlsVersion, get_registry};
    }
    
    pub mod crypto {
        pub use crate::crypto::cipher_suites;
    }
    
    pub mod handshake {
        pub use crate::handshake::NamedGroup;
    }
}
#[cfg(not(any(test, feature = "testing")))]
mod handshake;
#[cfg(not(any(test, feature = "testing")))]
mod record;

// Re-export error types
pub use error::{Error, ErrorType, BlockedError, ProtocolError, CryptoError, ConfigError, InternalError, UsageError, HashError, CertificateError, ExtensionError, KeyExchangeError};


/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialize the library
///
/// This function must be called before using any other functionality.
/// It initializes the cryptographic library and other internal state.
///
/// # Returns
///
/// `Ok(())` if initialization was successful, or an error otherwise.
///
/// # Examples
///
/// ```
/// use s2n_tls_rs::init;
///
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     init()?;
///     // Now you can use the library
///     Ok(())
/// }
/// ```
pub fn init() -> Result<(), Error> {
    // Initialize aws-lc-rs
    crypto::init()?;
    
    Ok(())
}

/// Clean up the library
///
/// This function should be called when the library is no longer needed.
/// It cleans up any resources allocated by the library.
pub fn cleanup() -> Result<(), Error> {
    // Clean up aws-lc-rs
    crypto::cleanup()?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_cleanup() {
        assert!(init().is_ok());
        assert!(cleanup().is_ok());
    }
}
