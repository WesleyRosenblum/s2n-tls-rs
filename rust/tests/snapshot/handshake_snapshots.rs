// Handshake snapshot tests

use insta::assert_debug_snapshot;
use s2n_tls_rs::{init, cleanup};
use s2n_tls_rs::handshake::{HandshakeMessage, ClientHello};
use s2n_tls_rs::record::ProtocolVersion;

#[test]
fn test_client_hello_snapshot() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a ClientHello message with fixed test data
    let random = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    
    let session_id = vec![
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    ];
    
    let client_hello = ClientHello {
        legacy_version: ProtocolVersion { major: 3, minor: 3 },
        random,
        legacy_session_id: session_id,
        cipher_suites: vec![0x13, 0x01, 0x13, 0x02, 0x13, 0x03], // TLS 1.3 cipher suites
        legacy_compression_methods: vec![0], // no compression
        extensions: vec![], // no extensions for this test
    };
    
    let message = HandshakeMessage::ClientHello(client_hello);
    
    // Create a snapshot of the message
    assert_debug_snapshot!("client_hello_snapshot", message);
    
    // Serialize the message
    let mut buffer = Vec::new();
    message.encode(&mut buffer).unwrap();
    
    // Create a snapshot of the serialized message
    assert_debug_snapshot!("client_hello_buffer_snapshot", buffer);
    
    // Clean up
    assert!(cleanup().is_ok());
}
