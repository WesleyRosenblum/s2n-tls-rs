//! ServerHello message implementation
//!
//! This module implements the ServerHello message as specified in RFC 8446.

use crate::buffer::Buffer;
use crate::crypto::{CipherSuite, cipher_suites};
use crate::error::{Error, ProtocolError};
use crate::handshake::client_hello::{Extension, ExtensionType, HandshakeType, MAX_SESSION_ID_LEN};
use crate::record::ProtocolVersion;
use std::convert::TryFrom;

//= https://www.rfc-editor.org/rfc/rfc8446#section-4.1.3
//# struct {
//#   ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
//#   Random random;
//#   opaque legacy_session_id_echo<0..32>;
//#   CipherSuite cipher_suite;
//#   uint8 legacy_compression_method = 0;
//#   Extension extensions<6..2^16-1>;
//# } ServerHello;
#[derive(Debug, Clone, PartialEq)]
pub struct ServerHello {
    /// Legacy version (should be TLS 1.2 for TLS 1.3)
    pub legacy_version: ProtocolVersion,
    /// Random value (32 bytes)
    pub random: [u8; 32],
    /// Legacy session ID echo
    pub legacy_session_id_echo: Vec<u8>,
    /// Selected cipher suite
    pub cipher_suite: CipherSuite,
    /// Legacy compression method (should be 0 for TLS 1.3)
    pub legacy_compression_method: u8,
    /// Extensions
    pub extensions: Vec<Extension>,
}

impl ServerHello {
    /// Create a new ServerHello message
    pub fn new() -> Self {
        Self {
            legacy_version: ProtocolVersion::TLS_1_2, // TLS 1.2 for TLS 1.3 compatibility
            random: [0; 32],
            legacy_session_id_echo: Vec::new(),
            cipher_suite: cipher_suites::TLS_AES_128_GCM_SHA256, // Default cipher suite
            legacy_compression_method: 0, // No compression
            extensions: Vec::new(),
        }
    }
    
    /// Set the legacy version
    pub fn set_legacy_version(&mut self, version: ProtocolVersion) {
        self.legacy_version = version;
    }
    
    /// Set the random value
    pub fn set_random(&mut self, random: [u8; 32]) {
        self.random = random;
    }
    
    /// Generate a random value
    pub fn generate_random(&mut self) -> Result<(), Error> {
        self.random = crate::crypto::random_bytes(32)?.try_into().map_err(|_| {
            Error::internal(crate::error::InternalError::Other("Failed to convert random bytes to array".into()))
        })?;
        Ok(())
    }
    
    /// Set the legacy session ID echo
    pub fn set_legacy_session_id_echo(&mut self, session_id: Vec<u8>) -> Result<(), Error> {
        if session_id.len() > MAX_SESSION_ID_LEN {
            return Err(Error::protocol(ProtocolError::Other("Session ID too long".into())));
        }
        self.legacy_session_id_echo = session_id;
        Ok(())
    }
    
    /// Set the cipher suite
    pub fn set_cipher_suite(&mut self, cipher_suite: CipherSuite) {
        self.cipher_suite = cipher_suite;
    }
    
    /// Add an extension
    pub fn add_extension(&mut self, extension: Extension) {
        self.extensions.push(extension);
    }
    
    /// Add the supported versions extension for TLS 1.3
    pub fn add_supported_versions_extension(&mut self) {
        // Format: 03 04 (value = 0x0304 for TLS 1.3)
        let data = vec![3, 4];
        
        self.extensions.push(Extension::new(
            ExtensionType::SupportedVersions,
            data,
        ));
    }
    
    /// Encode the ServerHello message into a buffer
    pub fn encode(&self, buffer: &mut Buffer) -> Result<(), Error> {
        // Message type (1 byte)
        buffer.write_u8(HandshakeType::ServerHello as u8);
        
        // Message length (3 bytes) - placeholder, will be filled in later
        let length_offset = buffer.len();
        buffer.write_u24(0);
        
        // Start of the ServerHello message
        let start_offset = buffer.len();
        
        // Legacy version (2 bytes)
        buffer.write_u8(self.legacy_version.major);
        buffer.write_u8(self.legacy_version.minor);
        
        // Random (32 bytes)
        buffer.append(&self.random);
        
        // Legacy session ID echo length (1 byte)
        buffer.write_u8(self.legacy_session_id_echo.len() as u8);
        
        // Legacy session ID echo (0-32 bytes)
        if !self.legacy_session_id_echo.is_empty() {
            buffer.append(&self.legacy_session_id_echo);
        }
        
        // Cipher suite (2 bytes)
        buffer.write_u8(self.cipher_suite.value[0]);
        buffer.write_u8(self.cipher_suite.value[1]);
        
        // Legacy compression method (1 byte)
        buffer.write_u8(self.legacy_compression_method);
        
        // Extensions length (2 bytes) - placeholder, will be filled in later
        let extensions_length_offset = buffer.len();
        buffer.write_u16(0);
        
        // Start of extensions
        let extensions_start_offset = buffer.len();
        
        // Extensions
        for extension in &self.extensions {
            extension.encode(buffer)?;
        }
        
        // Fill in the extensions length
        let extensions_length = buffer.len() - extensions_start_offset;
        buffer[extensions_length_offset] = ((extensions_length >> 8) & 0xFF) as u8;
        buffer[extensions_length_offset + 1] = (extensions_length & 0xFF) as u8;
        
        // Fill in the message length
        let message_length = buffer.len() - start_offset;
        buffer[length_offset] = ((message_length >> 16) & 0xFF) as u8;
        buffer[length_offset + 1] = ((message_length >> 8) & 0xFF) as u8;
        buffer[length_offset + 2] = (message_length & 0xFF) as u8;
        
        Ok(())
    }
    
    /// Decode a ServerHello message from a buffer
    pub fn decode(buffer: &[u8], offset: &mut usize) -> Result<Self, Error> {
        // Check if the buffer is large enough for the message type and length
        if *offset + 4 > buffer.len() {
            return Err(Error::protocol(ProtocolError::Other("Buffer too small for ServerHello header".into())));
        }
        
        // Message type (1 byte)
        let message_type = buffer[*offset];
        *offset += 1;
        
        if message_type != HandshakeType::ServerHello as u8 {
            return Err(Error::protocol(ProtocolError::Other(format!("Expected ServerHello message type, got {}", message_type))));
        }
        
        // Message length (3 bytes)
        let message_length = ((buffer[*offset] as usize) << 16) |
                             ((buffer[*offset + 1] as usize) << 8) |
                             (buffer[*offset + 2] as usize);
        *offset += 3;
        
        if *offset + message_length > buffer.len() {
            return Err(Error::protocol(ProtocolError::Other("Buffer too small for ServerHello message".into())));
        }
        
        // Legacy version (2 bytes)
        let legacy_version = ProtocolVersion {
            major: buffer[*offset],
            minor: buffer[*offset + 1],
        };
        *offset += 2;
        
        // Random (32 bytes)
        let mut random = [0u8; 32];
        random.copy_from_slice(&buffer[*offset..*offset + 32]);
        *offset += 32;
        
        // Legacy session ID echo length (1 byte)
        let session_id_length = buffer[*offset] as usize;
        *offset += 1;
        
        if session_id_length > MAX_SESSION_ID_LEN {
            return Err(Error::protocol(ProtocolError::Other("Session ID too long".into())));
        }
        
        // Legacy session ID echo (0-32 bytes)
        let legacy_session_id_echo = if session_id_length > 0 {
            buffer[*offset..*offset + session_id_length].to_vec()
        } else {
            Vec::new()
        };
        *offset += session_id_length;
        
        // Cipher suite (2 bytes)
        if *offset + 2 > buffer.len() {
            return Err(Error::protocol(ProtocolError::Other("Buffer too small for cipher suite".into())));
        }
        
        let cipher_suite_value = [buffer[*offset], buffer[*offset + 1]];
        *offset += 2;
        
        let cipher_suite = cipher_suites::from_value(&cipher_suite_value)
            .ok_or_else(|| Error::protocol(ProtocolError::CipherNotSupported))?;
        
        // Legacy compression method (1 byte)
        if *offset >= buffer.len() {
            return Err(Error::protocol(ProtocolError::Other("Buffer too small for compression method".into())));
        }
        
        let legacy_compression_method = buffer[*offset];
        *offset += 1;
        
        // Extensions length (2 bytes)
        if *offset + 2 > buffer.len() {
            return Err(Error::protocol(ProtocolError::Other("Buffer too small for extensions length".into())));
        }
        
        let extensions_length = ((buffer[*offset] as usize) << 8) | (buffer[*offset + 1] as usize);
        *offset += 2;
        
        if *offset + extensions_length > buffer.len() {
            return Err(Error::protocol(ProtocolError::Other("Buffer too small for extensions".into())));
        }
        
        // Extensions
        let extensions_end = *offset + extensions_length;
        let mut extensions = Vec::new();
        
        while *offset < extensions_end {
            let extension = Extension::decode(buffer, offset)?;
            extensions.push(extension);
        }
        
        Ok(Self {
            legacy_version,
            random,
            legacy_session_id_echo,
            cipher_suite,
            legacy_compression_method,
            extensions,
        })
    }
    
    /// Check if this is a TLS 1.3 ServerHello
    pub fn is_tls13(&self) -> bool {
        // Check for the supported_versions extension with TLS 1.3
        for extension in &self.extensions {
            if extension.extension_type == ExtensionType::SupportedVersions {
                if extension.extension_data.len() == 2 &&
                   extension.extension_data[0] == 3 &&
                   extension.extension_data[1] == 4 {
                    return true;
                }
            }
        }
        
        false
    }
}
