//! TLS connection API
//!
//! This module provides the public API for TLS connections. The [`Connection`] struct
//! represents a TLS connection and provides methods for performing TLS operations such
//! as handshaking, sending, and receiving data.
//!
//! ## Connection Lifecycle
//!
//! 1. Create a connection with [`Connection::new`]
//! 2. Initialize the connection with [`Connection::initialize`]
//! 3. Perform the TLS handshake with [`Connection::negotiate`]
//! 4. Send and receive data with [`Connection::send`] and [`Connection::recv`]
//! 5. Close the connection with [`Connection::close`]
//!
//! ## Handling I/O
//!
//! The connection doesn't perform I/O operations directly. Instead, it provides methods
//! to process input and output data:
//!
//! - [`Connection::process_input`]: Process data received from the peer
//! - [`Connection::process_output`]: Get data to send to the peer
//!
//! ## Example
//!
//! ```rust
//! use s2n_tls_rs::{Config, Connection, Error};
//! use std::io::{Read, Write};
//! use std::net::TcpStream;
//!
//! fn handle_connection(stream: &mut TcpStream, config: Config) -> Result<(), Error> {
//!     // Create and initialize the connection
//!     let mut connection = Connection::new(config);
//!     connection.initialize()?;
//!
//!     // Perform the TLS handshake
//!     connection.negotiate()?;
//!
//!     // Send data
//!     connection.send(b"Hello, world!")?;
//!
//!     // Process the output
//!     let mut output_buffer = [0; 16384];
//!     let len = connection.process_output(&mut output_buffer)?;
//!     stream.write_all(&output_buffer[..len])?;
//!
//!     // Receive data
//!     let mut input_buffer = [0; 16384];
//!     let bytes_read = stream.read(&mut input_buffer)?;
//!     connection.process_input(&input_buffer[..bytes_read])?;
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

use crate::error::Error;
use crate::state::{ConnectionConfig, ConnectionMode, ConnectionState, StateMachine};
use crate::record::Record;

/// TLS connection status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionStatus {
    /// Connection is in handshake
    Handshaking,
    /// Connection is established
    Established,
    /// Connection is closed
    Closed,
    /// Connection is in error state
    Error,
}

/// TLS blocked status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockedStatus {
    /// Not blocked
    NotBlocked,
    /// Blocked on reading
    ReadBlocked,
    /// Blocked on writing
    WriteBlocked,
    /// Blocked on application data
    ApplicationDataBlocked,
}

/// TLS connection
#[derive(Debug)]
pub struct Connection {
    /// State machine
    state_machine: StateMachine,
    /// Connection status
    status: ConnectionStatus,
    /// Blocked status
    blocked_status: BlockedStatus,
    /// Input buffer
    input_buffer: Vec<u8>,
    /// Output buffer
    output_buffer: Vec<u8>,
}

impl Connection {
/// Create a new connection
pub fn new(config: super::Config) -> Self {
    Self {
        state_machine: StateMachine::new(config.to_connection_config()),
        status: ConnectionStatus::Handshaking,
        blocked_status: BlockedStatus::NotBlocked,
        input_buffer: Vec::new(),
        output_buffer: Vec::new(),
    }
}
    
    /// Initialize the connection
    pub fn initialize(&mut self) -> Result<(), Error> {
        self.state_machine.initialize()?;
        Ok(())
    }
    
    /// Get the connection status
    pub fn status(&self) -> ConnectionStatus {
        self.status
    }
    
    /// Get the blocked status
    pub fn blocked_status(&self) -> BlockedStatus {
        self.blocked_status
    }
    
    /// Get the connection mode
    pub fn mode(&self) -> ConnectionMode {
        self.state_machine.connection.config.mode
    }
    
    /// Check if the connection is established
    pub fn is_established(&self) -> bool {
        self.status == ConnectionStatus::Established
    }
    
    /// Check if the connection is closed
    pub fn is_closed(&self) -> bool {
        self.status == ConnectionStatus::Closed
    }
    
    /// Check if the connection is in error state
    pub fn is_error(&self) -> bool {
        self.status == ConnectionStatus::Error
    }
    
    /// Check if the connection is handshaking
    pub fn is_handshaking(&self) -> bool {
        self.status == ConnectionStatus::Handshaking
    }
    
    /// Check if the connection is blocked
    pub fn is_blocked(&self) -> bool {
        self.blocked_status != BlockedStatus::NotBlocked
    }
    
    /// Check if the connection is blocked on reading
    pub fn is_read_blocked(&self) -> bool {
        self.blocked_status == BlockedStatus::ReadBlocked
    }
    
    /// Check if the connection is blocked on writing
    pub fn is_write_blocked(&self) -> bool {
        self.blocked_status == BlockedStatus::WriteBlocked
    }
    
    /// Check if the connection is blocked on application data
    pub fn is_application_data_blocked(&self) -> bool {
        self.blocked_status == BlockedStatus::ApplicationDataBlocked
    }
    
    /// Send data
    pub fn send(&mut self, data: &[u8]) -> Result<usize, Error> {
        // If the connection is not established, return an error
        if !self.is_established() {
            return Err(Error::usage(crate::error::UsageError::Other("Connection not established".to_string())));
        }
        
        // If the connection is blocked on writing, return an error
        if self.is_write_blocked() {
            return Err(Error::Blocked(crate::error::BlockedError::Io));
        }
        
        // Add the data to the output buffer
        self.output_buffer.extend_from_slice(data);
        
        // Return the number of bytes sent
        Ok(data.len())
    }
    
    /// Receive data
    pub fn recv(&mut self, data: &mut [u8]) -> Result<usize, Error> {
        // If the connection is not established, return an error
        if !self.is_established() {
            return Err(Error::usage(crate::error::UsageError::Other("Connection not established".to_string())));
        }
        
        // If the connection is blocked on reading, return an error
        if self.is_read_blocked() {
            return Err(Error::Blocked(crate::error::BlockedError::Io));
        }
        
        // If the input buffer is empty, return 0
        if self.input_buffer.is_empty() {
            return Ok(0);
        }
        
        // Copy data from the input buffer to the output buffer
        let len = std::cmp::min(data.len(), self.input_buffer.len());
        data[..len].copy_from_slice(&self.input_buffer[..len]);
        
        // Remove the copied data from the input buffer
        self.input_buffer.drain(..len);
        
        // Return the number of bytes received
        Ok(len)
    }
    
    /// Negotiate the connection
    pub fn negotiate(&mut self) -> Result<(), Error> {
        // If the connection is already established, return
        if self.is_established() {
            return Ok(());
        }
        
        // If the connection is closed or in error state, return an error
        if self.is_closed() || self.is_error() {
            return Err(Error::usage(crate::error::UsageError::Other("Connection closed or in error state".to_string())));
        }
        
        // Create a dummy record to start the handshake
        let dummy_record = Record::new(
            crate::record::RecordType::Handshake,
            crate::record::ProtocolVersion::TLS_1_2,
            Vec::new(),
        );
        
        // Process the record
        let records = self.state_machine.process_record(&dummy_record)?;
        
        // Update the connection status based on the state machine state
        match self.state_machine.state() {
            ConnectionState::HandshakeCompleted => {
                self.status = ConnectionStatus::Established;
            }
            ConnectionState::Closed => {
                self.status = ConnectionStatus::Closed;
            }
            ConnectionState::Error => {
                self.status = ConnectionStatus::Error;
            }
            _ => {
                self.status = ConnectionStatus::Handshaking;
            }
        }
        
        Ok(())
    }
    
    /// Process incoming data
    pub fn process_input(&mut self, data: &[u8]) -> Result<usize, Error> {
        // Add the data to the input buffer
        self.input_buffer.extend_from_slice(data);
        
        // Return the number of bytes processed
        Ok(data.len())
    }
    
    /// Process outgoing data
    pub fn process_output(&mut self, data: &mut [u8]) -> Result<usize, Error> {
        // If the output buffer is empty, return 0
        if self.output_buffer.is_empty() {
            return Ok(0);
        }
        
        // Copy data from the output buffer to the output buffer
        let len = std::cmp::min(data.len(), self.output_buffer.len());
        data[..len].copy_from_slice(&self.output_buffer[..len]);
        
        // Remove the copied data from the output buffer
        self.output_buffer.drain(..len);
        
        // Return the number of bytes processed
        Ok(len)
    }
    
    /// Close the connection
    pub fn close(&mut self) -> Result<(), Error> {
        // If the connection is already closed, return
        if self.is_closed() {
            return Ok(());
        }
        
        // Process a close requested event
        self.state_machine.process_event(crate::state::Event::CloseRequested)?;
        
        // Update the connection status
        self.status = ConnectionStatus::Closed;
        
        Ok(())
    }
    
    /// Wipe the connection
    pub fn wipe(&mut self) {
        // Clear the input buffer
        self.input_buffer.clear();
        
        // Clear the output buffer
        self.output_buffer.clear();
        
        // Update the connection status
        self.status = ConnectionStatus::Closed;
        
        // Update the blocked status
        self.blocked_status = BlockedStatus::NotBlocked;
    }
}
