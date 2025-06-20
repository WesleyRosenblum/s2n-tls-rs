// Record layer unit tests

use s2n_tls_rs::{init, cleanup};
use s2n_tls_rs::record::{
    Record, RecordType, ProtocolVersion, RecordHeader, TLSPlaintext, 
    TLSCiphertext, TLSInnerPlaintext, MAX_FRAGMENT_LEN, RECORD_HEADER_SIZE
};

#[test]
fn test_record_type() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Test record type conversions
    assert_eq!(RecordType::ChangeCipherSpec as u8, 20);
    assert_eq!(RecordType::Alert as u8, 21);
    assert_eq!(RecordType::Handshake as u8, 22);
    assert_eq!(RecordType::ApplicationData as u8, 23);
    
    assert_eq!(RecordType::from_u8(20).unwrap(), RecordType::ChangeCipherSpec);
    assert_eq!(RecordType::from_u8(21).unwrap(), RecordType::Alert);
    assert_eq!(RecordType::from_u8(22).unwrap(), RecordType::Handshake);
    assert_eq!(RecordType::from_u8(23).unwrap(), RecordType::ApplicationData);
    
    assert!(RecordType::from_u8(0).is_err());
    assert!(RecordType::from_u8(255).is_err());
    
    // Test display implementation
    assert_eq!(format!("{}", RecordType::ChangeCipherSpec), "ChangeCipherSpec");
    assert_eq!(format!("{}", RecordType::Alert), "Alert");
    assert_eq!(format!("{}", RecordType::Handshake), "Handshake");
    assert_eq!(format!("{}", RecordType::ApplicationData), "ApplicationData");
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_protocol_version() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Test protocol version constants
    assert_eq!(ProtocolVersion::TLS_1_0, ProtocolVersion { major: 3, minor: 1 });
    assert_eq!(ProtocolVersion::TLS_1_1, ProtocolVersion { major: 3, minor: 2 });
    assert_eq!(ProtocolVersion::TLS_1_2, ProtocolVersion { major: 3, minor: 3 });
    assert_eq!(ProtocolVersion::TLS_1_3, ProtocolVersion { major: 3, minor: 4 });
    
    // Test version comparison methods
    assert!(ProtocolVersion::TLS_1_3.is_tls_1_3_or_later());
    assert!(!ProtocolVersion::TLS_1_2.is_tls_1_3_or_later());
    assert!(ProtocolVersion::TLS_1_2.is_tls_1_2_or_later());
    assert!(!ProtocolVersion::TLS_1_1.is_tls_1_2_or_later());
    
    // Test display implementation
    assert_eq!(format!("{}", ProtocolVersion::TLS_1_0), "TLS 1.0");
    assert_eq!(format!("{}", ProtocolVersion::TLS_1_1), "TLS 1.1");
    assert_eq!(format!("{}", ProtocolVersion::TLS_1_2), "TLS 1.2");
    assert_eq!(format!("{}", ProtocolVersion::TLS_1_3), "TLS 1.3");
    assert_eq!(format!("{}", ProtocolVersion { major: 4, minor: 0 }), "Unknown(4.0)");
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_record_header() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a record header
    let header = RecordHeader::new(RecordType::Handshake, ProtocolVersion::TLS_1_2, 123);
    
    // Test field values
    assert_eq!(header.record_type, 22);
    assert_eq!(header.version.major, 3);
    assert_eq!(header.version.minor, 3);
    assert_eq!(header.length, [0, 123]);
    
    // Test accessor methods
    assert_eq!(header.get_length(), 123);
    assert_eq!(header.get_record_type().unwrap(), RecordType::Handshake);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_record_encode_decode() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a record
    let record = Record::new(
        RecordType::Handshake,
        ProtocolVersion::TLS_1_2,
        vec![1, 2, 3, 4, 5],
    );
    
    // Encode the record
    let mut buffer = Vec::new();
    assert!(record.encode(&mut buffer).is_ok());
    
    // Verify encoded format
    assert_eq!(buffer.len(), RECORD_HEADER_SIZE + 5);
    assert_eq!(buffer[0], 22); // Handshake
    assert_eq!(buffer[1], 3);  // Major version
    assert_eq!(buffer[2], 3);  // Minor version
    assert_eq!(buffer[3], 0);  // Length high byte
    assert_eq!(buffer[4], 5);  // Length low byte
    assert_eq!(&buffer[5..], &[1, 2, 3, 4, 5]);
    
    // Decode the record
    let (decoded, consumed) = Record::decode(&buffer).unwrap();
    assert_eq!(consumed, buffer.len());
    assert_eq!(decoded.record_type, RecordType::Handshake);
    assert_eq!(decoded.version, ProtocolVersion::TLS_1_2);
    assert_eq!(decoded.payload, vec![1, 2, 3, 4, 5]);
    
    // Test total_size method
    assert_eq!(record.total_size(), RECORD_HEADER_SIZE + 5);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_record_decode_errors() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Test decoding with buffer too short
    let buffer = vec![22, 3, 3, 0, 5, 1, 2];
    assert!(Record::decode(&buffer).is_err());
    
    // Test decoding with invalid record type
    let buffer = vec![99, 3, 3, 0, 5, 1, 2, 3, 4, 5];
    assert!(Record::decode(&buffer).is_err());
    
    // Test decoding with payload too large
    let mut buffer = Vec::with_capacity(RECORD_HEADER_SIZE + MAX_FRAGMENT_LEN + 1);
    buffer.push(22); // Handshake
    buffer.push(3);  // Major version
    buffer.push(3);  // Minor version
    buffer.push(((MAX_FRAGMENT_LEN + 1) >> 8) as u8); // Length high byte
    buffer.push((MAX_FRAGMENT_LEN + 1) as u8);       // Length low byte
    buffer.extend(vec![0; MAX_FRAGMENT_LEN + 1]);
    assert!(Record::decode(&buffer).is_err());
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_tls_plaintext() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a TLSPlaintext
    let plaintext = TLSPlaintext::new(
        RecordType::Handshake,
        ProtocolVersion::TLS_1_2,
        vec![1, 2, 3, 4, 5],
    );
    
    // Test field values
    assert_eq!(plaintext.record_type, RecordType::Handshake);
    assert_eq!(plaintext.legacy_record_version, ProtocolVersion::TLS_1_2);
    assert_eq!(plaintext.fragment, vec![1, 2, 3, 4, 5]);
    
    // Test conversion to Record
    let record = plaintext.to_record();
    assert_eq!(record.record_type, RecordType::Handshake);
    assert_eq!(record.version, ProtocolVersion::TLS_1_2);
    assert_eq!(record.payload, vec![1, 2, 3, 4, 5]);
    
    // Test conversion from Record
    let plaintext2 = TLSPlaintext::from_record(&record);
    assert_eq!(plaintext2.record_type, RecordType::Handshake);
    assert_eq!(plaintext2.legacy_record_version, ProtocolVersion::TLS_1_2);
    assert_eq!(plaintext2.fragment, vec![1, 2, 3, 4, 5]);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_tls_ciphertext() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a TLSCiphertext
    let ciphertext = TLSCiphertext::new(
        RecordType::ApplicationData,
        ProtocolVersion::TLS_1_2,
        vec![10, 20, 30, 40, 50],
    );
    
    // Test field values
    assert_eq!(ciphertext.opaque_type, RecordType::ApplicationData);
    assert_eq!(ciphertext.legacy_record_version, ProtocolVersion::TLS_1_2);
    assert_eq!(ciphertext.encrypted_record, vec![10, 20, 30, 40, 50]);
    
    // Test conversion to Record
    let record = ciphertext.to_record();
    assert_eq!(record.record_type, RecordType::ApplicationData);
    assert_eq!(record.version, ProtocolVersion::TLS_1_2);
    assert_eq!(record.payload, vec![10, 20, 30, 40, 50]);
    
    // Test conversion from Record
    let ciphertext2 = TLSCiphertext::from_record(&record);
    assert_eq!(ciphertext2.opaque_type, RecordType::ApplicationData);
    assert_eq!(ciphertext2.legacy_record_version, ProtocolVersion::TLS_1_2);
    assert_eq!(ciphertext2.encrypted_record, vec![10, 20, 30, 40, 50]);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_tls_inner_plaintext() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a TLSInnerPlaintext
    let inner = TLSInnerPlaintext::new(
        RecordType::ApplicationData,
        vec![1, 2, 3, 4, 5],
        3,
    );
    
    // Test field values
    assert_eq!(inner.content_type, RecordType::ApplicationData);
    assert_eq!(inner.content, vec![1, 2, 3, 4, 5]);
    assert_eq!(inner.zeros, vec![0, 0, 0]);
    
    // Test encoding
    let encoded = inner.encode();
    assert_eq!(encoded, vec![1, 2, 3, 4, 5, 23, 0, 0, 0]);
    
    // Test decoding
    let decoded = TLSInnerPlaintext::decode(&encoded).unwrap();
    assert_eq!(decoded.content_type, RecordType::ApplicationData);
    assert_eq!(decoded.content, vec![1, 2, 3, 4, 5]);
    assert_eq!(decoded.zeros, vec![0, 0, 0]);
    
    // Test decoding errors
    assert!(TLSInnerPlaintext::decode(&[]).is_err()); // Empty buffer
    assert!(TLSInnerPlaintext::decode(&[0]).is_err()); // Only zeros
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_tls13_record_format() {
    // Initialize the library
    assert!(init().is_ok());
    
    // In TLS 1.3, the record version is always TLS 1.2 (3,3) for backward compatibility
    let record = Record::new_tls13(RecordType::ApplicationData, vec![1, 2, 3, 4, 5]);
    
    assert_eq!(record.record_type, RecordType::ApplicationData);
    assert_eq!(record.version, ProtocolVersion::TLS_1_2); // Should be TLS 1.2 for compatibility
    assert_eq!(record.payload, vec![1, 2, 3, 4, 5]);
    
    // Clean up
    assert!(cleanup().is_ok());
}
