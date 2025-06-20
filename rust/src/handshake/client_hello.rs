//! ClientHello message implementation
//!
//! This module implements the ClientHello message as specified in RFC 8446.

use crate::buffer::Buffer;
use crate::crypto::{self, CipherSuite, cipher_suites};
use crate::error::{Error, ProtocolError};
use crate::record::ProtocolVersion;
use std::convert::TryFrom;

/// Maximum length of the session ID (32 bytes)
pub const MAX_SESSION_ID_LEN: usize = 32;

/// TLS handshake message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeType {
    /// ClientHello message
    ClientHello = 1,
    /// ServerHello message
    ServerHello = 2,
    /// NewSessionTicket message
    NewSessionTicket = 4,
    /// EndOfEarlyData message
    EndOfEarlyData = 5,
    /// EncryptedExtensions message
    EncryptedExtensions = 8,
    /// Certificate message
    Certificate = 11,
    /// CertificateRequest message
    CertificateRequest = 13,
    /// CertificateVerify message
    CertificateVerify = 15,
    /// Finished message
    Finished = 20,
    /// KeyUpdate message
    KeyUpdate = 24,
    /// MessageHash message
    MessageHash = 254,
}

impl TryFrom<u8> for HandshakeType {
    type Error = Error;
    
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(HandshakeType::ClientHello),
            2 => Ok(HandshakeType::ServerHello),
            4 => Ok(HandshakeType::NewSessionTicket),
            5 => Ok(HandshakeType::EndOfEarlyData),
            8 => Ok(HandshakeType::EncryptedExtensions),
            11 => Ok(HandshakeType::Certificate),
            13 => Ok(HandshakeType::CertificateRequest),
            15 => Ok(HandshakeType::CertificateVerify),
            20 => Ok(HandshakeType::Finished),
            24 => Ok(HandshakeType::KeyUpdate),
            254 => Ok(HandshakeType::MessageHash),
            _ => Err(Error::protocol(ProtocolError::Other(format!("Invalid handshake type: {}", value)))),
        }
    }
}

/// TLS extension types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ExtensionType {
    /// ServerName extension
    ServerName = 0,
    /// MaxFragmentLength extension
    MaxFragmentLength = 1,
    /// StatusRequest extension
    StatusRequest = 5,
    /// SupportedGroups extension
    SupportedGroups = 10,
    /// SignatureAlgorithms extension
    SignatureAlgorithms = 13,
    /// UseExtendedMasterSecret extension
    UseExtendedMasterSecret = 23,
    /// SessionTicket extension
    SessionTicket = 35,
    /// PreSharedKey extension
    PreSharedKey = 41,
    /// EarlyData extension
    EarlyData = 42,
    /// SupportedVersions extension
    SupportedVersions = 43,
    /// Cookie extension
    Cookie = 44,
    /// PskKeyExchangeModes extension
    PskKeyExchangeModes = 45,
    /// CertificateAuthorities extension
    CertificateAuthorities = 47,
    /// OidFilters extension
    OidFilters = 48,
    /// PostHandshakeAuth extension
    PostHandshakeAuth = 49,
    /// SignatureAlgorithmsCert extension
    SignatureAlgorithmsCert = 50,
    /// KeyShare extension
    KeyShare = 51,
}

impl TryFrom<u16> for ExtensionType {
    type Error = Error;
    
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ExtensionType::ServerName),
            1 => Ok(ExtensionType::MaxFragmentLength),
            5 => Ok(ExtensionType::StatusRequest),
            10 => Ok(ExtensionType::SupportedGroups),
            13 => Ok(ExtensionType::SignatureAlgorithms),
            23 => Ok(ExtensionType::UseExtendedMasterSecret),
            35 => Ok(ExtensionType::SessionTicket),
            41 => Ok(ExtensionType::PreSharedKey),
            42 => Ok(ExtensionType::EarlyData),
            43 => Ok(ExtensionType::SupportedVersions),
            44 => Ok(ExtensionType::Cookie),
            45 => Ok(ExtensionType::PskKeyExchangeModes),
            47 => Ok(ExtensionType::CertificateAuthorities),
            48 => Ok(ExtensionType::OidFilters),
            49 => Ok(ExtensionType::PostHandshakeAuth),
            50 => Ok(ExtensionType::SignatureAlgorithmsCert),
            51 => Ok(ExtensionType::KeyShare),
            _ => Err(Error::protocol(ProtocolError::Other(format!("Unknown extension type: {}", value)))),
        }
    }
}

/// TLS extension
#[derive(Debug, Clone, PartialEq)]
pub struct Extension {
    /// Extension type
    pub extension_type: ExtensionType,
    /// Extension data
    pub extension_data: Vec<u8>,
}

impl Extension {
    /// Create a new extension
    pub fn new(extension_type: ExtensionType, extension_data: Vec<u8>) -> Self {
        Self {
            extension_type,
            extension_data,
        }
    }
    
    /// Encode the extension into a buffer
    pub fn encode(&self, buffer: &mut Buffer) -> Result<(), Error> {
        // Extension type (2 bytes)
        buffer.write_u16(self.extension_type as u16);
        
        // Extension data length (2 bytes)
        buffer.write_u16(self.extension_data.len() as u16);
        
        // Extension data
        buffer.append(&self.extension_data);
        
        Ok(())
    }
    
    /// Decode an extension from a buffer
    pub fn decode(buffer: &[u8], offset: &mut usize) -> Result<Self, Error> {
        if *offset + 4 > buffer.len() {
            return Err(Error::protocol(ProtocolError::Other("Buffer too small for extension".into())));
        }
        
        // Extension type (2 bytes)
        let extension_type = ((buffer[*offset] as u16) << 8) | (buffer[*offset + 1] as u16);
        *offset += 2;
        
        // Extension data length (2 bytes)
        let extension_data_len = ((buffer[*offset] as usize) << 8) | (buffer[*offset + 1] as usize);
        *offset += 2;
        
        if *offset + extension_data_len > buffer.len() {
            return Err(Error::protocol(ProtocolError::Other("Buffer too small for extension data".into())));
        }
        
        // Extension data
        let extension_data = buffer[*offset..*offset + extension_data_len].to_vec();
        *offset += extension_data_len;
        
        Ok(Self {
            extension_type: ExtensionType::try_from(extension_type)?,
            extension_data,
        })
    }
}

//= https://www.rfc-editor.org/rfc/rfc8446#section-4.1.2
//# struct {
//#   ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
//#   Random random;
//#   opaque legacy_session_id<0..32>;
//#   CipherSuite cipher_suites<2..2^16-2>;
//#   opaque legacy_compression_methods<1..2^8-1>;
//#   Extension extensions<8..2^16-1>;
//# } ClientHello;
#[derive(Debug, Clone, PartialEq)]
pub struct ClientHello {
    /// Legacy version (should be TLS 1.2 for TLS 1.3)
    pub legacy_version: ProtocolVersion,
    /// Random value (32 bytes)
    pub random: [u8; 32],
    /// Legacy session ID
    pub legacy_session_id: Vec<u8>,
    /// Cipher suites
    pub cipher_suites: Vec<CipherSuite>,
    /// Legacy compression methods
    pub legacy_compression_methods: Vec<u8>,
    /// Extensions
    pub extensions: Vec<Extension>,
}

impl ClientHello {
    //= https://www.rfc-editor.org/rfc/rfc8446#section-4.1.2
    //# When a client first connects to a server, it is REQUIRED to send the
    //# ClientHello as its first TLS message.
    /// Create a new ClientHello message
    pub fn new() -> Self {
        Self {
            legacy_version: ProtocolVersion::TLS_1_2, // TLS 1.2 for TLS 1.3 compatibility
            random: [0; 32],
            legacy_session_id: Vec::new(),
            cipher_suites: Vec::new(),
            legacy_compression_methods: vec![0], // no compression
            extensions: Vec::new(),
        }
    }
    
    //= https://www.rfc-editor.org/rfc/rfc8446#section-4.1.2
    //# legacy_version:  In previous versions of TLS, this field was used for
    //# version negotiation and represented the highest version number
    //# supported by the client.  Experience has shown that many servers
    //# do not properly implement version negotiation, leading to "version
    //# intolerance" in which the server rejects an otherwise acceptable
    //# ClientHello with a version number higher than it supports.  In
    //# TLS 1.3, the client indicates its version preferences in the
    //# "supported_versions" extension (Section 4.2.1) and the
    //# legacy_version field MUST be set to 0x0303, which is the version
    //# number for TLS 1.2.  TLS 1.3 ClientHellos are identified as having
    //# a legacy_version of 0x0303 and a supported_versions extension
    //# present with 0x0304 as the highest version indicated therein.
    //# (See Appendix D for details about backward compatibility.)
    /// Set the legacy version
    pub fn set_legacy_version(&mut self, version: ProtocolVersion) {
        self.legacy_version = version;
    }
    
    //= https://www.rfc-editor.org/rfc/rfc8446#section-4.1.2
    //# random:  32 bytes generated by a secure random number generator.  See
    //# Appendix C for additional information.
    /// Set the random value
    pub fn set_random(&mut self, random: [u8; 32]) {
        self.random = random;
    }
    
    /// Generate a random value
    pub fn generate_random(&mut self) -> Result<(), Error> {
        self.random = crypto::random_bytes(32)?.try_into().map_err(|_| {
            Error::internal(crate::error::InternalError::Other("Failed to convert random bytes to array".into()))
        })?;
        Ok(())
    }
    
    //= https://www.rfc-editor.org/rfc/rfc8446#section-4.1.2
    //# legacy_session_id:  Versions of TLS before TLS 1.3 supported a
    //# "session resumption" feature which has been merged with pre-shared
    //# keys in this version (see Section 2.2).  A client which has a
    //# cached session ID set by a pre-TLS 1.3 server SHOULD set this
    //# field to that value.  In compatibility mode (see Appendix D.4),
    //# this field MUST be non-empty, so a client not offering a
    //# pre-TLS 1.3 session MUST generate a new 32-byte value.  This value
    //# need not be random but SHOULD be unpredictable to avoid
    //# implementations fixating on a specific value (also known as
    //# ossification).  Otherwise, it MUST be set as a zero-length vector
    //# (i.e., a zero-valued single byte length field).
    /// Set the legacy session ID
    pub fn set_legacy_session_id(&mut self, session_id: Vec<u8>) -> Result<(), Error> {
        if session_id.len() > MAX_SESSION_ID_LEN {
            return Err(Error::protocol(ProtocolError::Other("Session ID too long".into())));
        }
        self.legacy_session_id = session_id;
        Ok(())
    }
    
    /// Generate a new session ID for compatibility mode
    pub fn generate_session_id(&mut self) -> Result<(), Error> {
        self.legacy_session_id = crypto::random_bytes(32)?;
        Ok(())
    }
    
    /// Add a cipher suite
    pub fn add_cipher_suite(&mut self, cipher_suite: CipherSuite) {
        self.cipher_suites.push(cipher_suite);
    }
    
    /// Add default TLS 1.3 cipher suites
    pub fn add_default_cipher_suites(&mut self) {
        self.cipher_suites.push(cipher_suites::TLS_AES_128_GCM_SHA256);
        self.cipher_suites.push(cipher_suites::TLS_AES_256_GCM_SHA384);
        self.cipher_suites.push(cipher_suites::TLS_CHACHA20_POLY1305_SHA256);
    }
    
    /// Add an extension
    pub fn add_extension(&mut self, extension: Extension) {
        self.extensions.push(extension);
    }
    
    /// Add the supported versions extension for TLS 1.3
    pub fn add_supported_versions_extension(&mut self) {
        // Format: 02 03 04 (length = 2 bytes, value = 0x0304 for TLS 1.3)
        let mut data = Vec::with_capacity(3);
        data.push(2); // Length of the list in bytes
        data.push(3); // Major version
        data.push(4); // Minor version
        
        self.extensions.push(Extension::new(
            ExtensionType::SupportedVersions,
            data,
        ));
    }
    
    /// Encode the ClientHello message into a buffer
    pub fn encode(&self, buffer: &mut Buffer) -> Result<(), Error> {
        // Message type (1 byte)
        buffer.write_u8(HandshakeType::ClientHello as u8);
        
        // Message length (3 bytes) - placeholder, will be filled in later
        let length_offset = buffer.len();
        buffer.write_u24(0);
        
        // Start of the ClientHello message
        let start_offset = buffer.len();
        
        // Legacy version (2 bytes)
        buffer.write_u8(self.legacy_version.major);
        buffer.write_u8(self.legacy_version.minor);
        
        // Random (32 bytes)
        buffer.append(&self.random);
        
        // Legacy session ID length (1 byte)
        buffer.write_u8(self.legacy_session_id.len() as u8);
        
        // Legacy session ID (0-32 bytes)
        if !self.legacy_session_id.is_empty() {
            buffer.append(&self.legacy_session_id);
        }
        
        // Cipher suites length (2 bytes)
        buffer.write_u16((self.cipher_suites.len() * 2) as u16);
        
        // Cipher suites (2 bytes each)
        for cipher_suite in &self.cipher_suites {
            buffer.write_u8(cipher_suite.value[0]);
            buffer.write_u8(cipher_suite.value[1]);
        }
        
        // Legacy compression methods length (1 byte)
        buffer.write_u8(self.legacy_compression_methods.len() as u8);
        
        // Legacy compression methods (1 byte each)
        buffer.append(&self.legacy_compression_methods);
        
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
    
    /// Decode a ClientHello message from a buffer
    pub fn decode(buffer: &[u8], offset: &mut usize) -> Result<Self, Error> {
        // Check if the buffer is large enough for the message type and length
        if *offset + 4 > buffer.len() {
            return Err(Error::protocol(ProtocolError::Other("Buffer too small for ClientHello header".into())));
        }
        
        // Message type (1 byte)
        let message_type = buffer[*offset];
        *offset += 1;
        
        if message_type != HandshakeType::ClientHello as u8 {
            return Err(Error::protocol(ProtocolError::Other(format!("Expected ClientHello message type, got {}", message_type))));
        }
        
        // Message length (3 bytes)
        let message_length = ((buffer[*offset] as usize) << 16) |
                             ((buffer[*offset + 1] as usize) << 8) |
                             (buffer[*offset + 2] as usize);
        *offset += 3;
        
        if *offset + message_length > buffer.len() {
            return Err(Error::protocol(ProtocolError::Other("Buffer too small for ClientHello message".into())));
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
        
        // Legacy session ID length (1 byte)
        let session_id_length = buffer[*offset] as usize;
        *offset += 1;
        
        if session_id_length > MAX_SESSION_ID_LEN {
            return Err(Error::protocol(ProtocolError::Other("Session ID too long".into())));
        }
        
        // Legacy session ID (0-32 bytes)
        let legacy_session_id = if session_id_length > 0 {
            buffer[*offset..*offset + session_id_length].to_vec()
        } else {
            Vec::new()
        };
        *offset += session_id_length;
        
        // Cipher suites length (2 bytes)
        let cipher_suites_length = ((buffer[*offset] as usize) << 8) | (buffer[*offset + 1] as usize);
        *offset += 2;
        
        if cipher_suites_length % 2 != 0 {
            return Err(Error::protocol(ProtocolError::Other("Cipher suites length must be even".into())));
        }
        
        // Cipher suites (2 bytes each)
        let mut cipher_suites = Vec::with_capacity(cipher_suites_length / 2);
        for _ in 0..cipher_suites_length / 2 {
            let value = [buffer[*offset], buffer[*offset + 1]];
            *offset += 2;
            
            if let Some(cipher_suite) = cipher_suites::from_value(&value) {
                cipher_suites.push(cipher_suite);
            } else {
                // Skip unknown cipher suites
            }
        }
        
        // Legacy compression methods length (1 byte)
        let compression_methods_length = buffer[*offset] as usize;
        *offset += 1;
        
        // Legacy compression methods (1 byte each)
        let legacy_compression_methods = buffer[*offset..*offset + compression_methods_length].to_vec();
        *offset += compression_methods_length;
        
        // Extensions length (2 bytes)
        let extensions_length = ((buffer[*offset] as usize) << 8) | (buffer[*offset + 1] as usize);
        *offset += 2;
        
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
            legacy_session_id,
            cipher_suites,
            legacy_compression_methods,
            extensions,
        })
    }
}
