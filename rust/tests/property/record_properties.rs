// Record layer property tests

use s2n_tls_rs::{init, cleanup};
use s2n_tls_rs::record::{
    Record, RecordType, ProtocolVersion, TLSPlaintext, 
    TLSCiphertext, TLSInnerPlaintext, MAX_FRAGMENT_LEN
};
use proptest::prelude::*;

/// Generate a valid record type
fn valid_record_type() -> impl Strategy<Value = RecordType> {
    prop_oneof![
        Just(RecordType::ChangeCipherSpec),
        Just(RecordType::Alert),
        Just(RecordType::Handshake),
        Just(RecordType::ApplicationData),
    ]
}

/// Generate a valid protocol version
fn valid_protocol_version() -> impl Strategy<Value = ProtocolVersion> {
    prop_oneof![
        Just(ProtocolVersion::TLS_1_0),
        Just(ProtocolVersion::TLS_1_1),
        Just(ProtocolVersion::TLS_1_2),
        Just(ProtocolVersion::TLS_1_3),
    ]
}

/// Generate a valid payload (not exceeding MAX_FRAGMENT_LEN)
fn valid_payload() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..1024) // Using a smaller max for test efficiency
}

#[test]
fn test_record_serialization_roundtrip() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Property test with fixed data first
    let record_type = RecordType::Handshake;
    let payload = vec![1, 2, 3, 4, 5];
    
    let record = Record::new(
        record_type,
        ProtocolVersion::TLS_1_2,
        payload.clone(),
    );
    
    // Serialize the record
    let mut buffer = Vec::new();
    record.encode(&mut buffer).unwrap();
    
    // Deserialize the record
    let (decoded, _) = Record::decode(&buffer).unwrap();
    
    // Verify the roundtrip
    assert_eq!(record.record_type, decoded.record_type);
    assert_eq!(record.version, decoded.version);
    assert_eq!(record.payload, decoded.payload);
    
    // Clean up
    assert!(cleanup().is_ok());
}

proptest! {
    #[test]
    fn test_record_property_roundtrip(
        record_type in valid_record_type(),
        version in valid_protocol_version(),
        payload in valid_payload()
    ) {
        // Initialize the library
        assert!(init().is_ok());
        
        // Create a record
        let record = Record::new(record_type, version, payload);
        
        // Serialize the record
        let mut buffer = Vec::new();
        record.encode(&mut buffer).unwrap();
        
        // Deserialize the record
        let (decoded, consumed) = Record::decode(&buffer).unwrap();
        
        // Verify the roundtrip
        prop_assert_eq!(record.record_type, decoded.record_type);
        prop_assert_eq!(record.version, decoded.version);
        prop_assert_eq!(record.payload, decoded.payload);
        prop_assert_eq!(consumed, buffer.len());
        
        // Clean up
        assert!(cleanup().is_ok());
    }

    #[test]
    fn test_tls_plaintext_property_roundtrip(
        record_type in valid_record_type(),
        version in valid_protocol_version(),
        fragment in valid_payload()
    ) {
        // Initialize the library
        assert!(init().is_ok());
        
        // Create a TLSPlaintext
        let plaintext = TLSPlaintext::new(record_type, version, fragment);
        
        // Convert to Record
        let record = plaintext.to_record();
        
        // Convert back to TLSPlaintext
        let plaintext2 = TLSPlaintext::from_record(&record);
        
        // Verify the roundtrip
        prop_assert_eq!(plaintext.record_type, plaintext2.record_type);
        prop_assert_eq!(plaintext.legacy_record_version, plaintext2.legacy_record_version);
        prop_assert_eq!(plaintext.fragment, plaintext2.fragment);
        
        // Clean up
        assert!(cleanup().is_ok());
    }

    #[test]
    fn test_tls_ciphertext_property_roundtrip(
        opaque_type in valid_record_type(),
        version in valid_protocol_version(),
        encrypted_record in valid_payload()
    ) {
        // Initialize the library
        assert!(init().is_ok());
        
        // Create a TLSCiphertext
        let ciphertext = TLSCiphertext::new(opaque_type, version, encrypted_record);
        
        // Convert to Record
        let record = ciphertext.to_record();
        
        // Convert back to TLSCiphertext
        let ciphertext2 = TLSCiphertext::from_record(&record);
        
        // Verify the roundtrip
        prop_assert_eq!(ciphertext.opaque_type, ciphertext2.opaque_type);
        prop_assert_eq!(ciphertext.legacy_record_version, ciphertext2.legacy_record_version);
        prop_assert_eq!(ciphertext.encrypted_record, ciphertext2.encrypted_record);
        
        // Clean up
        assert!(cleanup().is_ok());
    }

    #[test]
    fn test_tls_inner_plaintext_property_roundtrip(
        content_type in valid_record_type(),
        content in valid_payload(),
        padding_length in 0..32usize
    ) {
        // Initialize the library
        assert!(init().is_ok());
        
        // Create a TLSInnerPlaintext
        let inner = TLSInnerPlaintext::new(content_type, content, padding_length);
        
        // Encode
        let encoded = inner.encode();
        
        // Decode
        let decoded = TLSInnerPlaintext::decode(&encoded).unwrap();
        
        // Verify the roundtrip
        prop_assert_eq!(inner.content_type, decoded.content_type);
        prop_assert_eq!(inner.content, decoded.content);
        // Note: The decoded zeros might not match exactly if there were trailing zeros in the content
        
        // Clean up
        assert!(cleanup().is_ok());
    }

    #[test]
    fn test_record_max_size_property(
        record_type in valid_record_type(),
        version in valid_protocol_version(),
        payload_size in 0..65535usize
    ) {
        // Initialize the library
        assert!(init().is_ok());
        
        // Create a payload of the specified size
        let payload = vec![0; payload_size];
        
        // Create a record
        let record = Record::new(record_type, version, payload);
        
        // Serialize the record
        let mut buffer = Vec::new();
        let result = record.encode(&mut buffer);
        
        // Verify that encoding succeeds for valid sizes and fails for invalid sizes
        if payload_size <= MAX_FRAGMENT_LEN {
            prop_assert!(result.is_ok());
            
            // Deserialize the record
            let (decoded, _) = Record::decode(&buffer).unwrap();
            
            // Verify the roundtrip
            prop_assert_eq!(record.record_type, decoded.record_type);
            prop_assert_eq!(record.version, decoded.version);
            prop_assert_eq!(record.payload.len(), decoded.payload.len());
        } else {
            prop_assert!(result.is_err());
        }
        
        // Clean up
        assert!(cleanup().is_ok());
    }
}
