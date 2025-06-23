//! Key exchange implementation
//!
//! This module implements the key exchange functionality for TLS 1.3 as specified in RFC 8446.

use crate::buffer::Buffer;
use crate::crypto;
use crate::error::{Error, ProtocolError, CryptoError};
use crate::handshake::client_hello::{Extension, ExtensionType};
use std::convert::TryFrom;

/// Named groups for key exchange
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum NamedGroup {
    /// secp256r1 (NIST P-256)
    Secp256r1 = 0x0017,
    /// secp384r1 (NIST P-384)
    Secp384r1 = 0x0018,
    /// secp521r1 (NIST P-521)
    Secp521r1 = 0x0019,
    /// x25519
    X25519 = 0x001D,
    /// x448
    X448 = 0x001E,
}

impl TryFrom<u16> for NamedGroup {
    type Error = Error;
    
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0017 => Ok(NamedGroup::Secp256r1),
            0x0018 => Ok(NamedGroup::Secp384r1),
            0x0019 => Ok(NamedGroup::Secp521r1),
            0x001D => Ok(NamedGroup::X25519),
            0x001E => Ok(NamedGroup::X448),
            _ => Err(Error::protocol(ProtocolError::Other(format!("Unknown named group: {:#06x}", value)))),
        }
    }
}

/// Key share entry
#[derive(Debug, Clone, PartialEq)]
pub struct KeyShareEntry {
    /// Named group
    pub group: NamedGroup,
    /// Key exchange data
    pub key_exchange: Vec<u8>,
}

impl KeyShareEntry {
    /// Create a new key share entry
    pub fn new(group: NamedGroup, key_exchange: Vec<u8>) -> Self {
        Self {
            group,
            key_exchange,
        }
    }
    
    /// Encode the key share entry into a buffer
    pub fn encode(&self, buffer: &mut Buffer) -> Result<(), Error> {
        // Named group (2 bytes)
        buffer.write_u16(self.group as u16);
        
        // Key exchange length (2 bytes)
        buffer.write_u16(self.key_exchange.len() as u16);
        
        // Key exchange data
        buffer.append(&self.key_exchange);
        
        Ok(())
    }
    
    /// Decode a key share entry from a buffer
    pub fn decode(buffer: &[u8], offset: &mut usize) -> Result<Self, Error> {
        if *offset + 4 > buffer.len() {
            return Err(Error::protocol(ProtocolError::Other("Buffer too small for key share entry".into())));
        }
        
        // Named group (2 bytes)
        let group_value = ((buffer[*offset] as u16) << 8) | (buffer[*offset + 1] as u16);
        *offset += 2;
        
        let group = NamedGroup::try_from(group_value)?;
        
        // Key exchange length (2 bytes)
        let key_exchange_len = ((buffer[*offset] as usize) << 8) | (buffer[*offset + 1] as usize);
        *offset += 2;
        
        if *offset + key_exchange_len > buffer.len() {
            return Err(Error::protocol(ProtocolError::Other("Buffer too small for key exchange data".into())));
        }
        
        // Key exchange data
        let key_exchange = buffer[*offset..*offset + key_exchange_len].to_vec();
        *offset += key_exchange_len;
        
        Ok(Self {
            group,
            key_exchange,
        })
    }
}

/// Key share extension for ClientHello
#[derive(Debug, Clone, PartialEq)]
pub struct ClientKeyShare {
    /// Key share entries
    pub entries: Vec<KeyShareEntry>,
}

impl ClientKeyShare {
    /// Create a new client key share extension
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
    
    /// Add a key share entry
    pub fn add_entry(&mut self, entry: KeyShareEntry) {
        self.entries.push(entry);
    }
    
    /// Encode the client key share extension into a buffer
    pub fn encode(&self) -> Result<Extension, Error> {
        let mut data = Buffer::new();
        
        // Key share entries length (2 bytes) - placeholder, will be filled in later
        let entries_length_offset = data.len();
        data.write_u16(0);
        
        // Start of key share entries
        let entries_start_offset = data.len();
        
        // Key share entries
        for entry in &self.entries {
            entry.encode(&mut data)?;
        }
        
        // Fill in the entries length
        let entries_length = data.len() - entries_start_offset;
        data[entries_length_offset] = ((entries_length >> 8) & 0xFF) as u8;
        data[entries_length_offset + 1] = (entries_length & 0xFF) as u8;
        
        Ok(Extension::new(ExtensionType::KeyShare, data.into_vec()))
    }
    
    /// Decode a client key share extension from a buffer
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        if data.len() < 2 {
            return Err(Error::protocol(ProtocolError::Other("Buffer too small for client key share extension".into())));
        }
        
        let mut offset = 0;
        
        // Key share entries length (2 bytes)
        let entries_length = ((data[offset] as usize) << 8) | (data[offset + 1] as usize);
        offset += 2;
        
        if offset + entries_length > data.len() {
            return Err(Error::protocol(ProtocolError::Other("Buffer too small for key share entries".into())));
        }
        
        // Key share entries
        let entries_end = offset + entries_length;
        let mut entries = Vec::new();
        
        while offset < entries_end {
            let entry = KeyShareEntry::decode(data, &mut offset)?;
            entries.push(entry);
        }
        
        Ok(Self {
            entries,
        })
    }
}

/// Key share extension for ServerHello
#[derive(Debug, Clone, PartialEq)]
pub struct ServerKeyShare {
    /// Key share entry
    pub entry: KeyShareEntry,
}

impl ServerKeyShare {
    /// Create a new server key share extension
    pub fn new(entry: KeyShareEntry) -> Self {
        Self {
            entry,
        }
    }
    
    /// Encode the server key share extension into a buffer
    pub fn encode(&self) -> Result<Extension, Error> {
        let mut data = Buffer::new();
        
        // Key share entry
        self.entry.encode(&mut data)?;
        
        Ok(Extension::new(ExtensionType::KeyShare, data.into_vec()))
    }
    
    /// Decode a server key share extension from a buffer
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut offset = 0;
        
        // Key share entry
        let entry = KeyShareEntry::decode(data, &mut offset)?;
        
        Ok(Self {
            entry,
        })
    }
}

/// Key pair for key exchange
#[derive(Debug, Clone)]
pub struct KeyPair {
    /// Named group
    pub group: NamedGroup,
    /// Private key
    pub private_key: Vec<u8>,
    /// Public key
    pub public_key: Vec<u8>,
}

/// Generate a key pair for the specified named group
pub fn generate_key_pair(group: NamedGroup) -> Result<KeyPair, Error> {
    match group {
        NamedGroup::X25519 => {
            // Generate a random private key
            let mut private_key = crypto::random_bytes(32)?;
            
            // Ensure the private key meets the X25519 requirements
            // Clear the lowest 3 bits, set the second highest bit, clear the highest bit
            private_key[0] &= 0xF8;
            private_key[31] &= 0x7F;
            private_key[31] |= 0x40;
            
            // For now, we'll just use a placeholder for the public key
            // In a real implementation, we would use aws-lc-rs to generate the public key
            // This is just to make the demo work
            let public_key = crypto::random_bytes(32)?;
            
            Ok(KeyPair {
                group,
                private_key,
                public_key,
            })
        },
        NamedGroup::Secp256r1 => {
            // For now, we'll just implement X25519
            // In a full implementation, we would implement all supported groups
            Err(Error::protocol(ProtocolError::Other("Secp256r1 key generation not implemented yet".into())))
        },
        NamedGroup::Secp384r1 => {
            Err(Error::protocol(ProtocolError::Other("Secp384r1 key generation not implemented yet".into())))
        },
        NamedGroup::Secp521r1 => {
            Err(Error::protocol(ProtocolError::Other("Secp521r1 key generation not implemented yet".into())))
        },
        NamedGroup::X448 => {
            Err(Error::protocol(ProtocolError::Other("X448 key generation not implemented yet".into())))
        },
    }
}

/// Compute the shared secret using the private key and peer's public key
pub fn compute_shared_secret(
    group: NamedGroup,
    private_key: &[u8],
    peer_public_key: &[u8],
) -> Result<Vec<u8>, Error> {
    match group {
        NamedGroup::X25519 => {
            // Validate key sizes
            if private_key.len() != 32 {
                return Err(Error::crypto(CryptoError::InvalidKeySize));
            }
            if peer_public_key.len() != 32 {
                return Err(Error::crypto(CryptoError::InvalidKeySize));
            }
            
            // For now, we'll just use a placeholder for the shared secret
            // In a real implementation, we would use aws-lc-rs to compute the shared secret
            // This is just to make the demo work
            
            // Use a hash of the private key and peer's public key as the shared secret
            let mut data = Vec::with_capacity(private_key.len() + peer_public_key.len());
            data.extend_from_slice(private_key);
            data.extend_from_slice(peer_public_key);
            
            // Use SHA-256 as a placeholder
            crypto::hash(crypto::HashAlgorithm::Sha256, &data)
        },
        NamedGroup::Secp256r1 => {
            // For now, we'll just implement X25519
            // In a full implementation, we would implement all supported groups
            Err(Error::protocol(ProtocolError::Other("Secp256r1 key agreement not implemented yet".into())))
        },
        NamedGroup::Secp384r1 => {
            Err(Error::protocol(ProtocolError::Other("Secp384r1 key agreement not implemented yet".into())))
        },
        NamedGroup::Secp521r1 => {
            Err(Error::protocol(ProtocolError::Other("Secp521r1 key agreement not implemented yet".into())))
        },
        NamedGroup::X448 => {
            Err(Error::protocol(ProtocolError::Other("X448 key agreement not implemented yet".into())))
        },
    }
}
