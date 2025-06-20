//! Record module
//! 
//! Contains the TLS record protocol implementation as specified in RFC 8446.
//! The record layer fragments information blocks into TLSPlaintext records
//! carrying data in chunks of 2^14 bytes or less. These records are then
//! protected using the current traffic keys and algorithms.

use crate::error::{Error, ProtocolError};
use zerocopy::{AsBytes, FromBytes, Unaligned};
use std::convert::{TryFrom, TryInto};
use std::fmt;

/// Maximum TLS plaintext fragment length (2^14 bytes)
pub const MAX_FRAGMENT_LEN: usize = 16384;

/// Maximum TLS record size (2^14 + 256 bytes for encryption overhead)
pub const MAX_RECORD_SIZE: usize = MAX_FRAGMENT_LEN + 256;

/// TLS record header size (1 byte type + 2 bytes version + 2 bytes length)
pub const RECORD_HEADER_SIZE: usize = 5;

/// TLS record types as defined in RFC 8446
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordType {
    /// Change Cipher Spec protocol
    ChangeCipherSpec = 20,
    /// Alert protocol
    Alert = 21,
    /// Handshake protocol
    Handshake = 22,
    /// Application data protocol
    ApplicationData = 23,
}

impl RecordType {
    /// Convert a u8 value to a RecordType
    pub fn from_u8(value: u8) -> Result<Self, Error> {
        match value {
            20 => Ok(RecordType::ChangeCipherSpec),
            21 => Ok(RecordType::Alert),
            22 => Ok(RecordType::Handshake),
            23 => Ok(RecordType::ApplicationData),
            _ => Err(Error::protocol(ProtocolError::Other(format!("Invalid record type: {}", value)))),
        }
    }
    
    /// Convert RecordType to u8
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

impl TryFrom<u8> for RecordType {
    type Error = Error;
    
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::from_u8(value)
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordType::ChangeCipherSpec => write!(f, "ChangeCipherSpec"),
            RecordType::Alert => write!(f, "Alert"),
            RecordType::Handshake => write!(f, "Handshake"),
            RecordType::ApplicationData => write!(f, "ApplicationData"),
        }
    }
}

/// TLS protocol version
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsBytes, FromBytes, Unaligned)]
#[repr(C)]
pub struct ProtocolVersion {
    /// Major version number
    pub major: u8,
    /// Minor version number
    pub minor: u8,
}

impl ProtocolVersion {
    /// TLS 1.0 version
    pub const TLS_1_0: Self = Self { major: 3, minor: 1 };
    /// TLS 1.1 version
    pub const TLS_1_1: Self = Self { major: 3, minor: 2 };
    /// TLS 1.2 version
    pub const TLS_1_2: Self = Self { major: 3, minor: 3 };
    /// TLS 1.3 version
    pub const TLS_1_3: Self = Self { major: 3, minor: 4 };
    
    /// Create a new ProtocolVersion
    pub fn new(major: u8, minor: u8) -> Self {
        Self { major, minor }
    }
    
    /// Check if this version is TLS 1.3 or later
    pub fn is_tls_1_3_or_later(&self) -> bool {
        self.major > 3 || (self.major == 3 && self.minor >= 4)
    }
    
    /// Check if this version is TLS 1.2 or later
    pub fn is_tls_1_2_or_later(&self) -> bool {
        self.major > 3 || (self.major == 3 && self.minor >= 3)
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.major, self.minor) {
            (3, 1) => write!(f, "TLS 1.0"),
            (3, 2) => write!(f, "TLS 1.1"),
            (3, 3) => write!(f, "TLS 1.2"),
            (3, 4) => write!(f, "TLS 1.3"),
            _ => write!(f, "Unknown({}.{})", self.major, self.minor),
        }
    }
}

/// TLS record header
#[derive(Debug, Clone, Copy, AsBytes, FromBytes, Unaligned)]
#[repr(C)]
pub struct RecordHeader {
    /// Record type
    pub record_type: u8,
    /// Protocol version
    pub version: ProtocolVersion,
    /// Length of the record payload (big-endian)
    pub length: [u8; 2],
}

impl RecordHeader {
    /// Create a new RecordHeader
    pub fn new(record_type: RecordType, version: ProtocolVersion, length: u16) -> Self {
        Self {
            record_type: record_type as u8,
            version,
            length: [(length >> 8) as u8, length as u8],
        }
    }
    
    /// Get the length as a u16
    pub fn get_length(&self) -> u16 {
        ((self.length[0] as u16) << 8) | (self.length[1] as u16)
    }
    
    /// Get the record type
    pub fn get_record_type(&self) -> Result<RecordType, Error> {
        RecordType::from_u8(self.record_type)
    }
}

/// TLS record
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    /// Record type
    pub record_type: RecordType,
    /// Protocol version
    pub version: ProtocolVersion,
    /// Record payload
    pub payload: Vec<u8>,
}

impl Record {
    /// Create a new Record
    pub fn new(record_type: RecordType, version: ProtocolVersion, payload: Vec<u8>) -> Self {
        Self {
            record_type,
            version,
            payload,
        }
    }
    
    /// Create a new TLS 1.3 record
    pub fn new_tls13(record_type: RecordType, payload: Vec<u8>) -> Self {
        Self::new(record_type, ProtocolVersion::TLS_1_2, payload)
    }
    
    /// Encode the record into a buffer
    pub fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), Error> {
        if self.payload.len() > MAX_FRAGMENT_LEN {
            return Err(Error::protocol(ProtocolError::Other(format!(
                "Record payload too large: {} bytes (max {})",
                self.payload.len(),
                MAX_FRAGMENT_LEN
            ))));
        }
        
        // Record type
        buffer.push(self.record_type as u8);
        
        // Protocol version
        buffer.push(self.version.major);
        buffer.push(self.version.minor);
        
        // Length (2 bytes, big-endian)
        let length = self.payload.len() as u16;
        buffer.push((length >> 8) as u8);
        buffer.push(length as u8);
        
        // Payload
        buffer.extend_from_slice(&self.payload);
        
        Ok(())
    }
    
    /// Decode a record from a buffer
    pub fn decode(buffer: &[u8]) -> Result<(Self, usize), Error> {
        if buffer.len() < RECORD_HEADER_SIZE {
            return Err(Error::protocol(ProtocolError::Other("Record too short".into())));
        }
        
        let record_type = RecordType::from_u8(buffer[0])?;
        let version = ProtocolVersion {
            major: buffer[1],
            minor: buffer[2],
        };
        
        let length = ((buffer[3] as usize) << 8) | (buffer[4] as usize);
        if buffer.len() < RECORD_HEADER_SIZE + length {
            return Err(Error::protocol(ProtocolError::Other("Record payload too short".into())));
        }
        
        if length > MAX_FRAGMENT_LEN {
            return Err(Error::protocol(ProtocolError::Other(format!(
                "Record payload too large: {} bytes (max {})",
                length,
                MAX_FRAGMENT_LEN
            ))));
        }
        
        let payload = buffer[RECORD_HEADER_SIZE..RECORD_HEADER_SIZE + length].to_vec();
        
        Ok((
            Self {
                record_type,
                version,
                payload,
            },
            RECORD_HEADER_SIZE + length,
        ))
    }
    
    /// Get the total size of the record (header + payload)
    pub fn total_size(&self) -> usize {
        RECORD_HEADER_SIZE + self.payload.len()
    }
}

/// TLS plaintext record
#[derive(Debug, Clone, PartialEq)]
pub struct TLSPlaintext {
    /// Record type
    pub record_type: RecordType,
    /// Protocol version
    pub legacy_record_version: ProtocolVersion,
    /// Record fragment
    pub fragment: Vec<u8>,
}

impl TLSPlaintext {
    /// Create a new TLSPlaintext
    pub fn new(record_type: RecordType, legacy_record_version: ProtocolVersion, fragment: Vec<u8>) -> Self {
        Self {
            record_type,
            legacy_record_version,
            fragment,
        }
    }
    
    /// Convert to a Record
    pub fn to_record(&self) -> Record {
        Record::new(self.record_type, self.legacy_record_version, self.fragment.clone())
    }
    
    /// Create from a Record
    pub fn from_record(record: &Record) -> Self {
        Self {
            record_type: record.record_type,
            legacy_record_version: record.version,
            fragment: record.payload.clone(),
        }
    }
}

/// TLS ciphertext record
#[derive(Debug, Clone, PartialEq)]
pub struct TLSCiphertext {
    /// Opaque record type
    pub opaque_type: RecordType,
    /// Legacy record version
    pub legacy_record_version: ProtocolVersion,
    /// Encrypted record
    pub encrypted_record: Vec<u8>,
}

impl TLSCiphertext {
    /// Create a new TLSCiphertext
    pub fn new(opaque_type: RecordType, legacy_record_version: ProtocolVersion, encrypted_record: Vec<u8>) -> Self {
        Self {
            opaque_type,
            legacy_record_version,
            encrypted_record,
        }
    }
    
    /// Convert to a Record
    pub fn to_record(&self) -> Record {
        Record::new(self.opaque_type, self.legacy_record_version, self.encrypted_record.clone())
    }
    
    /// Create from a Record
    pub fn from_record(record: &Record) -> Self {
        Self {
            opaque_type: record.record_type,
            legacy_record_version: record.version,
            encrypted_record: record.payload.clone(),
        }
    }
}

/// TLS inner plaintext record (used in TLS 1.3)
#[derive(Debug, Clone, PartialEq)]
pub struct TLSInnerPlaintext {
    /// Content type
    pub content_type: RecordType,
    /// Plaintext content
    pub content: Vec<u8>,
    /// Padding (zeros)
    pub zeros: Vec<u8>,
}

impl TLSInnerPlaintext {
    /// Create a new TLSInnerPlaintext
    pub fn new(content_type: RecordType, content: Vec<u8>, padding_length: usize) -> Self {
        Self {
            content_type,
            content,
            zeros: vec![0; padding_length],
        }
    }
    
    /// Encode the inner plaintext
    pub fn encode(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.content.len() + self.zeros.len() + 1);
        result.extend_from_slice(&self.content);
        result.push(self.content_type as u8);
        result.extend_from_slice(&self.zeros);
        result
    }
    
    /// Decode an inner plaintext
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        if data.is_empty() {
            return Err(Error::protocol(ProtocolError::Other("Empty inner plaintext".into())));
        }
        
        // Find the content type byte by scanning backwards from the end
        let mut i = data.len() - 1;
        while i > 0 && data[i] == 0 {
            i -= 1;
        }
        
        if i == 0 && data[0] == 0 {
            return Err(Error::protocol(ProtocolError::Other("No content type found in inner plaintext".into())));
        }
        
        let content_type = RecordType::from_u8(data[i])?;
        let content = data[0..i].to_vec();
        let zeros = data[i+1..].to_vec();
        
        Ok(Self {
            content_type,
            content,
            zeros,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_type_conversion() {
        assert_eq!(RecordType::from_u8(20).unwrap(), RecordType::ChangeCipherSpec);
        assert_eq!(RecordType::from_u8(21).unwrap(), RecordType::Alert);
        assert_eq!(RecordType::from_u8(22).unwrap(), RecordType::Handshake);
        assert_eq!(RecordType::from_u8(23).unwrap(), RecordType::ApplicationData);
        assert!(RecordType::from_u8(0).is_err());
        assert!(RecordType::from_u8(255).is_err());
    }

    #[test]
    fn test_protocol_version() {
        assert_eq!(ProtocolVersion::TLS_1_0, ProtocolVersion { major: 3, minor: 1 });
        assert_eq!(ProtocolVersion::TLS_1_1, ProtocolVersion { major: 3, minor: 2 });
        assert_eq!(ProtocolVersion::TLS_1_2, ProtocolVersion { major: 3, minor: 3 });
        assert_eq!(ProtocolVersion::TLS_1_3, ProtocolVersion { major: 3, minor: 4 });
        
        assert!(ProtocolVersion::TLS_1_3.is_tls_1_3_or_later());
        assert!(!ProtocolVersion::TLS_1_2.is_tls_1_3_or_later());
        assert!(ProtocolVersion::TLS_1_2.is_tls_1_2_or_later());
        assert!(!ProtocolVersion::TLS_1_1.is_tls_1_2_or_later());
    }

    #[test]
    fn test_record_header() {
        let header = RecordHeader::new(RecordType::Handshake, ProtocolVersion::TLS_1_2, 123);
        assert_eq!(header.record_type, 22);
        assert_eq!(header.version.major, 3);
        assert_eq!(header.version.minor, 3);
        assert_eq!(header.length, [0, 123]);
        assert_eq!(header.get_length(), 123);
        assert_eq!(header.get_record_type().unwrap(), RecordType::Handshake);
    }

    #[test]
    fn test_record_encode_decode() {
        let record = Record::new(
            RecordType::Handshake,
            ProtocolVersion::TLS_1_2,
            vec![1, 2, 3, 4, 5],
        );
        
        let mut buffer = Vec::new();
        record.encode(&mut buffer).unwrap();
        
        assert_eq!(buffer.len(), RECORD_HEADER_SIZE + 5);
        assert_eq!(buffer[0], 22); // Handshake
        assert_eq!(buffer[1], 3);  // Major version
        assert_eq!(buffer[2], 3);  // Minor version
        assert_eq!(buffer[3], 0);  // Length high byte
        assert_eq!(buffer[4], 5);  // Length low byte
        assert_eq!(&buffer[5..], &[1, 2, 3, 4, 5]);
        
        let (decoded, consumed) = Record::decode(&buffer).unwrap();
        assert_eq!(consumed, buffer.len());
        assert_eq!(decoded.record_type, RecordType::Handshake);
        assert_eq!(decoded.version, ProtocolVersion::TLS_1_2);
        assert_eq!(decoded.payload, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_record_decode_error() {
        // Too short
        let buffer = vec![22, 3, 3, 0, 5, 1, 2];
        assert!(Record::decode(&buffer).is_err());
        
        // Invalid record type
        let buffer = vec![99, 3, 3, 0, 5, 1, 2, 3, 4, 5];
        assert!(Record::decode(&buffer).is_err());
        
        // Too large payload
        let mut buffer = Vec::with_capacity(RECORD_HEADER_SIZE + MAX_FRAGMENT_LEN + 1);
        buffer.push(22); // Handshake
        buffer.push(3);  // Major version
        buffer.push(3);  // Minor version
        buffer.push(((MAX_FRAGMENT_LEN + 1) >> 8) as u8); // Length high byte
        buffer.push((MAX_FRAGMENT_LEN + 1) as u8);       // Length low byte
        buffer.extend(vec![0; MAX_FRAGMENT_LEN + 1]);
        assert!(Record::decode(&buffer).is_err());
    }

    #[test]
    fn test_tls_inner_plaintext() {
        let inner = TLSInnerPlaintext::new(
            RecordType::ApplicationData,
            vec![1, 2, 3, 4, 5],
            3,
        );
        
        let encoded = inner.encode();
        assert_eq!(encoded, vec![1, 2, 3, 4, 5, 23, 0, 0, 0]);
        
        let decoded = TLSInnerPlaintext::decode(&encoded).unwrap();
        assert_eq!(decoded.content_type, RecordType::ApplicationData);
        assert_eq!(decoded.content, vec![1, 2, 3, 4, 5]);
        assert_eq!(decoded.zeros, vec![0, 0, 0]);
    }
}
