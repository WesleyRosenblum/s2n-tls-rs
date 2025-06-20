// Handshake layer property tests

use bolero::check;
use s2n_tls_rs::{init, cleanup};
use s2n_tls_rs::handshake::{HandshakeMessage, ClientHello, ServerHello};

#[test]
fn test_client_hello_serialization_roundtrip() {
    // Initialize the library
    assert!(init().is_ok());
    
    check!()
        .with_type::<(Vec<u8>, Vec<u8>)>()
        .for_each(|(random_data, session_id)| {
            // Limit sizes for testing
            let random_data = if random_data.len() >= 32 {
                &random_data[0..32]
            } else {
                &random_data
            };
            
            let session_id = if session_id.len() > 32 {
                &session_id[0..32]
            } else {
                &session_id
            };
            
            // Create a ClientHello message
            let mut random = [0u8; 32];
            random.copy_from_slice(random_data);
            
            let client_hello = ClientHello {
                legacy_version: s2n_tls_rs::record::ProtocolVersion { major: 3, minor: 3 },
                random,
                legacy_session_id: session_id.to_vec(),
                cipher_suites: vec![0x13, 0x01], // TLS_AES_128_GCM_SHA256
                legacy_compression_methods: vec![0], // no compression
                extensions: vec![], // no extensions for this test
            };
            
            let message = HandshakeMessage::ClientHello(client_hello);
            
            // Serialize the message
            let mut buffer = Vec::new();
            message.encode(&mut buffer).unwrap();
            
            // Deserialize the message
            let decoded = HandshakeMessage::decode(&buffer).unwrap();
            
            // Verify it's a ClientHello
            match decoded {
                HandshakeMessage::ClientHello(decoded_hello) => {
                    // Verify fields
                    assert_eq!(decoded_hello.legacy_version.major, 3);
                    assert_eq!(decoded_hello.legacy_version.minor, 3);
                    assert_eq!(decoded_hello.random, random);
                    assert_eq!(decoded_hello.legacy_session_id, session_id);
                    assert_eq!(decoded_hello.cipher_suites, vec![0x13, 0x01]);
                    assert_eq!(decoded_hello.legacy_compression_methods, vec![0]);
                },
                _ => panic!("Expected ClientHello, got something else"),
            }
        });
    
    // Clean up
    assert!(cleanup().is_ok());
}