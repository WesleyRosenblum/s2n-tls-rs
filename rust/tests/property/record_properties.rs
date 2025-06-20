// Record layer property tests

use s2n_tls_rs::{init, cleanup};
use s2n_tls_rs::record::{Record, RecordType, ProtocolVersion};

#[test]
fn test_record_serialization_roundtrip() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a record with fixed test data
    let record_type = RecordType::Handshake;
    let payload = vec![1, 2, 3, 4, 5];
    
    let record = Record {
        record_type,
        version: ProtocolVersion { major: 3, minor: 3 }, // TLS 1.2
        payload: payload.clone(),
    };
    
    // Serialize the record
    let mut buffer = Vec::new();
    record.encode(&mut buffer).unwrap();
    
    // Deserialize the record
    let decoded = Record::decode(&buffer).unwrap();
    
    // Verify the roundtrip
    assert_eq!(record.record_type, decoded.record_type);
    assert_eq!(record.version, decoded.version);
    assert_eq!(record.payload, decoded.payload);
    
    // Clean up
    assert!(cleanup().is_ok());
}
