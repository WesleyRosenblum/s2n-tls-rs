// Record module
// Contains the TLS record protocol implementation

use crate::error::Error;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RecordType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

impl RecordType {
    pub fn from_u8(value: u8) -> Result<Self, Error> {
        match value {
            20 => Ok(RecordType::ChangeCipherSpec),
            21 => Ok(RecordType::Alert),
            22 => Ok(RecordType::Handshake),
            23 => Ok(RecordType::ApplicationData),
            _ => Err(Error::protocol(crate::error::ProtocolError::Other(format!("Invalid record type: {}", value)))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ProtocolVersion {
    pub major: u8,
    pub minor: u8,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub record_type: RecordType,
    pub version: ProtocolVersion,
    pub payload: Vec<u8>,
}

impl Record {
    pub fn new(record_type: RecordType, version: ProtocolVersion, payload: Vec<u8>) -> Self {
        Self {
            record_type,
            version,
            payload,
        }
    }
    
    pub fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), Error> {
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
    
    pub fn decode(buffer: &[u8]) -> Result<Self, Error> {
        if buffer.len() < 5 {
            return Err(Error::protocol(crate::error::ProtocolError::Other("Record too short".into())));
        }
        
        let record_type = RecordType::from_u8(buffer[0])?;
        let version = ProtocolVersion {
            major: buffer[1],
            minor: buffer[2],
        };
        
        let length = ((buffer[3] as usize) << 8) | (buffer[4] as usize);
        if buffer.len() < 5 + length {
            return Err(Error::protocol(crate::error::ProtocolError::Other("Record payload too short".into())));
        }
        
        let payload = buffer[5..5 + length].to_vec();
        
        Ok(Self {
            record_type,
            version,
            payload,
        })
    }
}
