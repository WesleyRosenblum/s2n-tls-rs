// Record layer property tests

use bolero::check;
use s2n_tls_rs::{init, cleanup};
use s2n_tls_rs::record::{Record, RecordType, ProtocolVersion};

#[test]
fn test_record_serialization_roundtrip() {
    // Initialize the library
    assert!(init().is_ok());
    
    check!()
        .with_type::<(RecordType, Vec<u8>)>()
        .for_each(|(record_type, payload)| {
            // Limit payload size for testing
            let payload = if payload.len() > 1024 {
                &payload[0..1024]
            } else {
                &payload
            };
            
            // Create a record
            let record = Record {
                record_type: *record_type,
                version: ProtocolVersion { major: 3, minor: 3 }, // TLS 1.2
                payload: payload.to_vec(),
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
        });
    
    // Clean up
    assert!(cleanup().is_ok());
}