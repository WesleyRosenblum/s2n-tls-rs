//! Handshake module
//!
//! Contains the TLS handshake protocol implementation as specified in RFC 8446.

pub mod client_hello;
pub mod server_hello;
pub mod key_exchange;
pub mod key_schedule;

pub use client_hello::{ClientHello, Extension, ExtensionType, HandshakeType};
pub use server_hello::ServerHello;
pub use key_exchange::{NamedGroup, KeyShareEntry, ClientKeyShare, ServerKeyShare, KeyPair};
pub use key_schedule::KeySchedule;

use crate::buffer::Buffer;
use crate::error::Error;

/// TLS handshake message
#[derive(Debug, Clone, PartialEq)]
pub enum HandshakeMessage {
    /// ClientHello message
    ClientHello(ClientHello),
    /// ServerHello message
    ServerHello(ServerHello),
    // Other message types will be added as needed
}

impl HandshakeMessage {
    /// Encode the handshake message into a buffer
    pub fn encode(&self, buffer: &mut Buffer) -> Result<(), Error> {
        match self {
            HandshakeMessage::ClientHello(client_hello) => {
                client_hello.encode(buffer)?;
            }
            HandshakeMessage::ServerHello(server_hello) => {
                server_hello.encode(buffer)?;
            }
        }
        Ok(())
    }
    
    /// Decode a handshake message from a buffer
    pub fn decode(buffer: &[u8], offset: &mut usize) -> Result<Self, Error> {
        if *offset >= buffer.len() {
            return Err(Error::protocol(crate::error::ProtocolError::Other("Empty buffer".into())));
        }
        
        // Peek at the message type
        let message_type = buffer[*offset];
        
        match message_type {
            1 => {
                // Parse ClientHello
                let client_hello = ClientHello::decode(buffer, offset)?;
                Ok(HandshakeMessage::ClientHello(client_hello))
            }
            2 => {
                // Parse ServerHello
                let server_hello = ServerHello::decode(buffer, offset)?;
                Ok(HandshakeMessage::ServerHello(server_hello))
            }
            _ => Err(Error::protocol(crate::error::ProtocolError::Other(format!("Unknown handshake message type: {}", message_type)))),
        }
    }
}
