// Record layer snapshot tests

use insta::assert_debug_snapshot;
use s2n_tls_rs::{init, cleanup};
use s2n_tls_rs::crypto::{TrafficKeys, cipher_suites::TLS_AES_128_GCM_SHA256};
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

#[test]
fn test_record_encryption_snapshot() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create test keys
    let key = vec![0x3f, 0xce, 0x51, 0x60, 0x09, 0xc2, 0x17, 0x27, 0xd0, 0xf2, 0xe4, 0xe8, 0x6e, 0xe4, 0x03, 0xbc];
    let iv = vec![0x5d, 0x31, 0x3e, 0xb2, 0x67, 0x12, 0x76, 0xee, 0x13, 0x00, 0x0b, 0x30];
    let traffic_keys = TrafficKeys { key, iv };
    
    // Create a plaintext record
    let plaintext = TLSPlaintext::new(
        RecordType::ApplicationData,
        ProtocolVersion::TLS_1_2, // Legacy version for TLS 1.3
        vec![0x01, 0x02, 0x03, 0x04, 0x05],
    );
    
    // Create a snapshot of the plaintext
    assert_debug_snapshot!("encryption_plaintext_snapshot", plaintext);
    
    // Encrypt the record
    let ciphertext = TLSCiphertext::encrypt(
        &plaintext,
        TLS_AES_128_GCM_SHA256,
        &traffic_keys,
        0, // Sequence number
    ).unwrap();
    
    // Create a snapshot of the ciphertext
    assert_debug_snapshot!("encryption_ciphertext_snapshot", ciphertext);
    
    // Decrypt the record
    let decrypted = ciphertext.decrypt(
        TLS_AES_128_GCM_SHA256,
        &traffic_keys,
        0, // Sequence number
    ).unwrap();
    
    // Create a snapshot of the decrypted plaintext
    assert_debug_snapshot!("encryption_decrypted_snapshot", decrypted);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_record_encryption_with_sequence_snapshot() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create test keys
    let key = vec![0x3f, 0xce, 0x51, 0x60, 0x09, 0xc2, 0x17, 0x27, 0xd0, 0xf2, 0xe4, 0xe8, 0x6e, 0xe4, 0x03, 0xbc];
    let iv = vec![0x5d, 0x31, 0x3e, 0xb2, 0x67, 0x12, 0x76, 0xee, 0x13, 0x00, 0x0b, 0x30];
    let traffic_keys = TrafficKeys { key, iv };
    
    // Create a plaintext record
    let plaintext = TLSPlaintext::new(
        RecordType::ApplicationData,
        ProtocolVersion::TLS_1_2, // Legacy version for TLS 1.3
        vec![0x01, 0x02, 0x03, 0x04, 0x05],
    );
    
    // Encrypt with sequence number 1
    let ciphertext1 = TLSCiphertext::encrypt(
        &plaintext,
        TLS_AES_128_GCM_SHA256,
        &traffic_keys,
        1, // Sequence number
    ).unwrap();
    
    // Create a snapshot of the ciphertext with sequence number 1
    assert_debug_snapshot!("encryption_ciphertext_seq1_snapshot", ciphertext1);
    
    // Encrypt with sequence number 2
    let ciphertext2 = TLSCiphertext::encrypt(
        &plaintext,
        TLS_AES_128_GCM_SHA256,
        &traffic_keys,
        2, // Sequence number
    ).unwrap();
    
    // Create a snapshot of the ciphertext with sequence number 2
    assert_debug_snapshot!("encryption_ciphertext_seq2_snapshot", ciphertext2);
    
    // Verify that the ciphertexts are different
    assert_ne!(ciphertext1, ciphertext2);
    
    // Clean up
    assert!(cleanup().is_ok());
}
