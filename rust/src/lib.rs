//! # s2n-tls-rs
//!
//! A memory-safe TLS implementation in Rust compatible with s2n-tls.
//!
//! This library implements the TLS 1.3 protocol as specified in RFC 8446.
//! It is designed to be compatible with the s2n-tls C implementation while
//! leveraging Rust's safety guarantees.

// Re-export public API
pub mod api;
pub use api::{Config, Connection, BlockedStatus, ConnectionMode};

// Internal modules
mod crypto;
mod error;
mod io;
mod state;
mod tls;
mod utils;

// Re-export modules for testing
#[cfg(any(test, feature = "testing"))]
pub mod handshake;
#[cfg(any(test, feature = "testing"))]
pub mod record;
#[cfg(not(any(test, feature = "testing")))]
mod handshake;
#[cfg(not(any(test, feature = "testing")))]
mod record;

// Re-export error types
pub use error::Error;

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
