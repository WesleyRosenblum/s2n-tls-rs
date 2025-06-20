// Record layer snapshot tests

use insta::assert_debug_snapshot;
use s2n_tls_rs::{init, cleanup};
use s2n_tls_rs::record::{Record, RecordType, ProtocolVersion};

#[test]
fn test_record_snapshot() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a record with fixed test data
    let record = Record {
        record_type: RecordType::Handshake,
        version: ProtocolVersion { major: 3, minor: 4 }, // TLS 1.3
        payload: vec![0x01, 0x02, 0x03, 0x04, 0x05],
    };
    
    // Create a snapshot of the record
    assert_debug_snapshot!(record);
    
    // Serialize the record
    let mut buffer = Vec::new();
    record.encode(&mut buffer).unwrap();
    
    // Create a snapshot of the serialized record
    assert_debug_snapshot!(buffer);
    
    // Clean up
    assert!(cleanup().is_ok());
}