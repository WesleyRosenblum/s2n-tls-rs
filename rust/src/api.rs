//! Public API for the s2n-tls-rs library
//!
//! This module provides the public API for the s2n-tls-rs library.
//! It includes the Connection and Config types, which are the main
//! entry points for using the library.

use std::os::fd::RawFd;
use std::sync::Arc;

use crate::error::Error;
use crate::io::IoProvider;
use crate::state::StateMachine;

/// Connection mode (client or server)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionMode {
    /// Client mode
    Client,
    /// Server mode
    Server,
}

/// Blocked status for non-blocking I/O
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockedStatus {
    /// Not blocked
    NotBlocked,
    /// Blocked on read
    BlockedOnRead,
    /// Blocked on write
    BlockedOnWrite,
}

/// TLS connection configuration
#[derive(Debug, Clone)]
pub struct Config {
    // Internal fields will be added as needed
}

impl Config {
    /// Create a new TLS configuration
    pub fn new() -> Result<Self, Error> {
        // Implementation will be added
        Ok(Self {})
    }
    
    /// Set the certificate chain
    pub fn set_certificate_chain(&mut self, chain: &[u8]) -> Result<(), Error> {
        // Implementation will be added
        Ok(())
    }
    
    /// Set the private key
    pub fn set_private_key(&mut self, key: &[u8]) -> Result<(), Error> {
        // Implementation will be added
        Ok(())
    }
    
    /// Add a trusted certificate authority
    pub fn add_trusted_ca(&mut self, ca: &[u8]) -> Result<(), Error> {
        // Implementation will be added
        Ok(())
    }
}

/// TLS connection
#[derive(Debug)]
pub struct Connection {
    config: Option<Arc<Config>>,
    mode: ConnectionMode,
    blocked_status: BlockedStatus,
    // Other fields will be added as needed
}

impl Connection {
    /// Create a new TLS connection in client mode
    pub fn new_client() -> Result<Self, Error> {
        Ok(Self {
            config: None,
            mode: ConnectionMode::Client,
            blocked_status: BlockedStatus::NotBlocked,
        })
    }
    
    /// Create a new TLS connection in server mode
    pub fn new_server() -> Result<Self, Error> {
        Ok(Self {
            config: None,
            mode: ConnectionMode::Server,
            blocked_status: BlockedStatus::NotBlocked,
        })
    }
    
    /// Set the configuration for this connection
    pub fn set_config(&mut self, config: Arc<Config>) -> Result<(), Error> {
        self.config = Some(config);
        Ok(())
    }
    
    /// Set the file descriptor for I/O operations
    pub fn set_fd(&mut self, fd: RawFd) -> Result<(), Error> {
        // Implementation will be added
        Ok(())
    }
    
    /// Negotiate the TLS handshake
    pub fn negotiate(&mut self) -> Result<BlockedStatus, Error> {
        // Implementation will be added
        Ok(BlockedStatus::NotBlocked)
    }
    
    /// Send data over the TLS connection
    pub fn send(&mut self, data: &[u8]) -> Result<usize, Error> {
        // Implementation will be added
        Ok(0)
    }
    
    /// Receive data from the TLS connection
    pub fn recv(&mut self, data: &mut [u8]) -> Result<usize, Error> {
        // Implementation will be added
        Ok(0)
    }
    
    /// Close the TLS connection
    pub fn shutdown(&mut self) -> Result<BlockedStatus, Error> {
        // Implementation will be added
        Ok(BlockedStatus::NotBlocked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_new() {
        let client = Connection::new_client().unwrap();
        assert_eq!(client.mode, ConnectionMode::Client);
        
        let server = Connection::new_server().unwrap();
        assert_eq!(server.mode, ConnectionMode::Server);
    }
}