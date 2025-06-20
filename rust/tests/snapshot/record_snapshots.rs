// Record layer snapshot tests

use insta::assert_debug_snapshot;
use s2n_tls_rs::{init, cleanup};
use s2n_tls_rs::record::{
    Record, RecordType, ProtocolVersion, RecordHeader, 
    TLSPlaintext, TLSCiphertext, TLSInnerPlaintext
};

#[test]
fn test_record_snapshot() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a record with fixed test data
    let record = Record::new(
        RecordType::Handshake,
        ProtocolVersion::TLS_1_3,
        vec![0x01, 0x02, 0x03, 0x04, 0x05],
    );
    
    // Create a snapshot of the record
    assert_debug_snapshot!("record_snapshot", record);
    
    // Serialize the record
    let mut buffer = Vec::new();
    record.encode(&mut buffer).unwrap();
    
    // Create a snapshot of the serialized record
    assert_debug_snapshot!("record_buffer_snapshot", buffer);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_record_header_snapshot() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a record header
    let header = RecordHeader::new(
        RecordType::Handshake,
        ProtocolVersion::TLS_1_2,
        123,
    );
    
    // Create a snapshot of the header
    assert_debug_snapshot!("record_header_snapshot", header);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_tls_plaintext_snapshot() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a TLSPlaintext
    let plaintext = TLSPlaintext::new(
        RecordType::Handshake,
        ProtocolVersion::TLS_1_2,
        vec![0x01, 0x02, 0x03, 0x04, 0x05],
    );
    
    // Create a snapshot of the plaintext
    assert_debug_snapshot!("tls_plaintext_snapshot", plaintext);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_tls_ciphertext_snapshot() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a TLSCiphertext
    let ciphertext = TLSCiphertext::new(
        RecordType::ApplicationData,
        ProtocolVersion::TLS_1_2,
        vec![0x10, 0x20, 0x30, 0x40, 0x50],
    );
    
    // Create a snapshot of the ciphertext
    assert_debug_snapshot!("tls_ciphertext_snapshot", ciphertext);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_tls_inner_plaintext_snapshot() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a TLSInnerPlaintext
    let inner = TLSInnerPlaintext::new(
        RecordType::ApplicationData,
        vec![0x01, 0x02, 0x03, 0x04, 0x05],
        3,
    );
    
    // Create a snapshot of the inner plaintext
    assert_debug_snapshot!("tls_inner_plaintext_snapshot", inner);
    
    // Create a snapshot of the encoded inner plaintext
    let encoded = inner.encode();
    assert_debug_snapshot!("tls_inner_plaintext_encoded_snapshot", encoded);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_tls13_record_format_snapshot() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a TLS 1.3 record
    let record = Record::new_tls13(
        RecordType::ApplicationData,
        vec![0x01, 0x02, 0x03, 0x04, 0x05],
    );
    
    // Create a snapshot of the record
    assert_debug_snapshot!("tls13_record_snapshot", record);
    
    // Serialize the record
    let mut buffer = Vec::new();
    record.encode(&mut buffer).unwrap();
    
    // Create a snapshot of the serialized record
    assert_debug_snapshot!("tls13_record_buffer_snapshot", buffer);
    
    // Clean up
    assert!(cleanup().is_ok());
}
