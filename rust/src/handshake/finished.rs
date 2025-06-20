//! Finished message handling for TLS 1.3
//!
//! This module implements the Finished message handling for TLS 1.3 as specified in RFC 8446 section 4.4.4.

use crate::buffer::Buffer;
use crate::crypto;
use crate::error::{Error, ProtocolError, CryptoError};
use crate::handshake::client_hello::HandshakeType;

//= https://www.rfc-editor.org/rfc/rfc8446#section-4.4.4
//# struct {
//#     opaque verify_data[Hash.length];
//# } Finished;
#[derive(Debug, Clone, PartialEq)]
pub struct Finished {
    /// Verify data
    pub verify_data: Vec<u8>,
}

impl Finished {
    /// Create a new Finished message
    pub fn new(verify_data: Vec<u8>) -> Self {
        Self {
            verify_data,
        }
    }
    
    /// Encode the Finished message into a buffer
    pub fn encode(&self, buffer: &mut Buffer) -> Result<(), Error> {
        // Message type (1 byte)
        buffer.write_u8(HandshakeType::Finished as u8);
        
        // Message length (3 bytes) - placeholder, will be filled in later
        let length_offset = buffer.len();
        buffer.write_u24(0);
        
        // Start of the Finished message
        let start_offset = buffer.len();
        
        // Verify data
        buffer.append(&self.verify_data);
        
        // Fill in the message length
        let message_length = buffer.len() - start_offset;
        buffer[length_offset] = ((message_length >> 16) & 0xFF) as u8;
        buffer[length_offset + 1] = ((message_length >> 8) & 0xFF) as u8;
        buffer[length_offset + 2] = (message_length & 0xFF) as u8;
        
        Ok(())
    }
    
    /// Decode a Finished message from a buffer
    pub fn decode(buffer: &[u8], offset: &mut usize) -> Result<Self, Error> {
        // Check if the buffer is large enough for the message type and length
        if *offset + 4 > buffer.len() {
            return Err(Error::protocol(ProtocolError::Other("Buffer too small for Finished header".into())));
        }
        
        // Message type (1 byte)
        let message_type = buffer[*offset];
        *offset += 1;
        
        if message_type != HandshakeType::Finished as u8 {
            return Err(Error::protocol(ProtocolError::Other(format!("Expected Finished message type, got {}", message_type))));
        }
        
        // Message length (3 bytes)
        let message_length = ((buffer[*offset] as usize) << 16) |
                             ((buffer[*offset + 1] as usize) << 8) |
                             (buffer[*offset + 2] as usize);
        *offset += 3;
        
        if *offset + message_length > buffer.len() {
            return Err(Error::protocol(ProtocolError::Other("Buffer too small for Finished message".into())));
        }
        
        // Verify data
        let verify_data = buffer[*offset..*offset + message_length].to_vec();
        *offset += message_length;
        
        Ok(Self {
            verify_data,
        })
    }
}

/// Compute the verify data for a Finished message
pub fn compute_verify_data(
    finished_key: &[u8],
    transcript_hash: &[u8],
) -> Result<Vec<u8>, Error> {
    // Compute the HMAC of the transcript hash using the finished key
    crypto::hmac(crypto::HashAlgorithm::Sha256, finished_key, transcript_hash)
}

/// Verify the verify data in a Finished message
pub fn verify_finished_data(
    finished_key: &[u8],
    transcript_hash: &[u8],
    verify_data: &[u8],
) -> Result<(), Error> {
    // Compute the expected verify data
    let expected_verify_data = compute_verify_data(finished_key, transcript_hash)?;
    
    // Compare the expected verify data with the received verify data
    if expected_verify_data != verify_data {
        return Err(Error::protocol(ProtocolError::Other("Finished verify data mismatch".into())));
    }
    
    Ok(())
}

/// Transcript hash context
#[derive(Debug, Clone)]
pub struct TranscriptHashContext {
    /// Hash algorithm
    pub hash_algorithm: crypto::HashAlgorithm,
    /// Running hash state
    running_hash: Vec<u8>,
}

impl TranscriptHashContext {
    /// Create a new transcript hash context
    pub fn new(hash_algorithm: crypto::HashAlgorithm) -> Self {
        Self {
            hash_algorithm,
            running_hash: Vec::new(),
        }
    }
    
    /// Update the transcript hash with a message
    pub fn update(&mut self, message: &[u8]) -> Result<(), Error> {
        // In a real implementation, we would maintain a running hash state
        // For now, we'll just append the message to the running hash
        self.running_hash.extend_from_slice(message);
        Ok(())
    }
    
    /// Get the current transcript hash
    pub fn get_hash(&self) -> Result<Vec<u8>, Error> {
        // In a real implementation, we would finalize the hash
        // For now, we'll just hash the running hash
        crypto::hash(self.hash_algorithm, &self.running_hash)
    }
}

/// Handshake verification context
#[derive(Debug, Clone)]
pub struct HandshakeVerificationContext {
    /// Transcript hash context
    pub transcript_hash_context: TranscriptHashContext,
    /// Client finished key
    pub client_finished_key: Option<Vec<u8>>,
    /// Server finished key
    pub server_finished_key: Option<Vec<u8>>,
}

impl HandshakeVerificationContext {
    /// Create a new handshake verification context
    pub fn new(hash_algorithm: crypto::HashAlgorithm) -> Self {
        Self {
            transcript_hash_context: TranscriptHashContext::new(hash_algorithm),
            client_finished_key: None,
            server_finished_key: None,
        }
    }
    
    /// Set the client finished key
    pub fn set_client_finished_key(&mut self, key: Vec<u8>) {
        self.client_finished_key = Some(key);
    }
    
    /// Set the server finished key
    pub fn set_server_finished_key(&mut self, key: Vec<u8>) {
        self.server_finished_key = Some(key);
    }
    
    /// Update the transcript hash with a message
    pub fn update_transcript(&mut self, message: &[u8]) -> Result<(), Error> {
        self.transcript_hash_context.update(message)
    }
    
    /// Get the current transcript hash
    pub fn get_transcript_hash(&self) -> Result<Vec<u8>, Error> {
        self.transcript_hash_context.get_hash()
    }
    
    /// Verify a client Finished message
    pub fn verify_client_finished(&self, finished: &Finished) -> Result<(), Error> {
        // Check if the client finished key is set
        let client_finished_key = self.client_finished_key.as_ref().ok_or_else(|| {
            Error::protocol(ProtocolError::Other("Client finished key not set".into()))
        })?;
        
        // Get the transcript hash
        let transcript_hash = self.get_transcript_hash()?;
        
        // Verify the finished data
        verify_finished_data(client_finished_key, &transcript_hash, &finished.verify_data)
    }
    
    /// Verify a server Finished message
    pub fn verify_server_finished(&self, finished: &Finished) -> Result<(), Error> {
        // Check if the server finished key is set
        let server_finished_key = self.server_finished_key.as_ref().ok_or_else(|| {
            Error::protocol(ProtocolError::Other("Server finished key not set".into()))
        })?;
        
        // Get the transcript hash
        let transcript_hash = self.get_transcript_hash()?;
        
        // Verify the finished data
        verify_finished_data(server_finished_key, &transcript_hash, &finished.verify_data)
    }
    
    /// Create a client Finished message
    pub fn create_client_finished(&self) -> Result<Finished, Error> {
        // Check if the client finished key is set
        let client_finished_key = self.client_finished_key.as_ref().ok_or_else(|| {
            Error::protocol(ProtocolError::Other("Client finished key not set".into()))
        })?;
        
        // Get the transcript hash
        let transcript_hash = self.get_transcript_hash()?;
        
        // Compute the verify data
        let verify_data = compute_verify_data(client_finished_key, &transcript_hash)?;
        
        Ok(Finished::new(verify_data))
    }
    
    /// Create a server Finished message
    pub fn create_server_finished(&self) -> Result<Finished, Error> {
        // Check if the server finished key is set
        let server_finished_key = self.server_finished_key.as_ref().ok_or_else(|| {
            Error::protocol(ProtocolError::Other("Server finished key not set".into()))
        })?;
        
        // Get the transcript hash
        let transcript_hash = self.get_transcript_hash()?;
        
        // Compute the verify data
        let verify_data = compute_verify_data(server_finished_key, &transcript_hash)?;
        
        Ok(Finished::new(verify_data))
    }
}
