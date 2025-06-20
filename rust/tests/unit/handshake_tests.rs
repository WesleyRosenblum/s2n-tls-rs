// Handshake layer unit tests

use s2n_tls_rs::{init, cleanup};
use s2n_tls_rs::buffer::Buffer;
use s2n_tls_rs::crypto::cipher_suites::TLS_AES_128_GCM_SHA256;
use s2n_tls_rs::handshake::{
    ClientHello, ServerHello, HandshakeMessage, Extension, ExtensionType, HandshakeType
};
use s2n_tls_rs::record::ProtocolVersion;

#[test]
fn test_client_hello_creation() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a ClientHello message
    let mut client_hello = ClientHello::new();
    
    // Set the random value
    let random = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    client_hello.set_random(random);
    
    // Set the legacy session ID
    let session_id = vec![
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    ];
    assert!(client_hello.set_legacy_session_id(session_id.clone()).is_ok());
    
    // Add cipher suites
    client_hello.add_default_cipher_suites();
    
    // Add the supported versions extension for TLS 1.3
    client_hello.add_supported_versions_extension();
    
    // Verify the ClientHello fields
    assert_eq!(client_hello.legacy_version, ProtocolVersion::TLS_1_2);
    assert_eq!(client_hello.random, random);
    assert_eq!(client_hello.legacy_session_id, session_id);
    assert_eq!(client_hello.cipher_suites.len(), 3);
    assert_eq!(client_hello.legacy_compression_methods, vec![0]);
    assert_eq!(client_hello.extensions.len(), 1);
    assert_eq!(client_hello.extensions[0].extension_type, ExtensionType::SupportedVersions);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_client_hello_encode_decode() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a ClientHello message
    let mut client_hello = ClientHello::new();
    
    // Set the random value
    let random = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    client_hello.set_random(random);
    
    // Set the legacy session ID
    let session_id = vec![
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    ];
    assert!(client_hello.set_legacy_session_id(session_id).is_ok());
    
    // Add cipher suites
    client_hello.add_default_cipher_suites();
    
    // Add the supported versions extension for TLS 1.3
    client_hello.add_supported_versions_extension();
    
    // Encode the ClientHello message
    let mut buffer = Buffer::new();
    assert!(client_hello.encode(&mut buffer).is_ok());
    
    // Decode the ClientHello message
    let mut offset = 0;
    let decoded = ClientHello::decode(&buffer, &mut offset).unwrap();
    
    // Verify the decoded ClientHello
    assert_eq!(decoded.legacy_version, ProtocolVersion::TLS_1_2);
    assert_eq!(decoded.random, random);
    assert_eq!(decoded.cipher_suites.len(), 3);
    assert_eq!(decoded.legacy_compression_methods, vec![0]);
    assert_eq!(decoded.extensions.len(), 1);
    assert_eq!(decoded.extensions[0].extension_type, ExtensionType::SupportedVersions);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_server_hello_creation() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a ServerHello message
    let mut server_hello = ServerHello::new();
    
    // Set the random value
    let random = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    server_hello.set_random(random);
    
    // Set the legacy session ID echo
    let session_id = vec![
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    ];
    assert!(server_hello.set_legacy_session_id_echo(session_id.clone()).is_ok());
    
    // Set the cipher suite
    server_hello.set_cipher_suite(TLS_AES_128_GCM_SHA256);
    
    // Add the supported versions extension for TLS 1.3
    server_hello.add_supported_versions_extension();
    
    // Verify the ServerHello fields
    assert_eq!(server_hello.legacy_version, ProtocolVersion::TLS_1_2);
    assert_eq!(server_hello.random, random);
    assert_eq!(server_hello.legacy_session_id_echo, session_id);
    assert_eq!(server_hello.cipher_suite, TLS_AES_128_GCM_SHA256);
    assert_eq!(server_hello.legacy_compression_method, 0);
    assert_eq!(server_hello.extensions.len(), 1);
    assert_eq!(server_hello.extensions[0].extension_type, ExtensionType::SupportedVersions);
    
    // Verify that this is a TLS 1.3 ServerHello
    assert!(server_hello.is_tls13());
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_server_hello_encode_decode() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a ServerHello message
    let mut server_hello = ServerHello::new();
    
    // Set the random value
    let random = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    server_hello.set_random(random);
    
    // Set the legacy session ID echo
    let session_id = vec![
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    ];
    assert!(server_hello.set_legacy_session_id_echo(session_id).is_ok());
    
    // Set the cipher suite
    server_hello.set_cipher_suite(TLS_AES_128_GCM_SHA256);
    
    // Add the supported versions extension for TLS 1.3
    server_hello.add_supported_versions_extension();
    
    // Encode the ServerHello message
    let mut buffer = Buffer::new();
    assert!(server_hello.encode(&mut buffer).is_ok());
    
    // Decode the ServerHello message
    let mut offset = 0;
    let decoded = ServerHello::decode(&buffer, &mut offset).unwrap();
    
    // Verify the decoded ServerHello
    assert_eq!(decoded.legacy_version, ProtocolVersion::TLS_1_2);
    assert_eq!(decoded.random, random);
    assert_eq!(decoded.cipher_suite, TLS_AES_128_GCM_SHA256);
    assert_eq!(decoded.legacy_compression_method, 0);
    assert_eq!(decoded.extensions.len(), 1);
    assert_eq!(decoded.extensions[0].extension_type, ExtensionType::SupportedVersions);
    
    // Verify that this is a TLS 1.3 ServerHello
    assert!(decoded.is_tls13());
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_handshake_message_encode_decode() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a ClientHello message
    let mut client_hello = ClientHello::new();
    client_hello.generate_random().unwrap();
    client_hello.add_default_cipher_suites();
    client_hello.add_supported_versions_extension();
    
    // Create a HandshakeMessage from the ClientHello
    let message = HandshakeMessage::ClientHello(client_hello.clone());
    
    // Encode the HandshakeMessage
    let mut buffer = Buffer::new();
    assert!(message.encode(&mut buffer).is_ok());
    
    // Decode the HandshakeMessage
    let mut offset = 0;
    let decoded = HandshakeMessage::decode(&buffer, &mut offset).unwrap();
    
    // Verify the decoded HandshakeMessage
    match decoded {
        HandshakeMessage::ClientHello(decoded_client_hello) => {
            assert_eq!(decoded_client_hello.legacy_version, client_hello.legacy_version);
            assert_eq!(decoded_client_hello.random, client_hello.random);
            assert_eq!(decoded_client_hello.cipher_suites.len(), client_hello.cipher_suites.len());
            assert_eq!(decoded_client_hello.extensions.len(), client_hello.extensions.len());
        }
        _ => panic!("Expected ClientHello, got something else"),
    }
    
    // Create a ServerHello message
    let mut server_hello = ServerHello::new();
    server_hello.generate_random().unwrap();
    server_hello.add_supported_versions_extension();
    
    // Create a HandshakeMessage from the ServerHello
    let message = HandshakeMessage::ServerHello(server_hello.clone());
    
    // Encode the HandshakeMessage
    let mut buffer = Buffer::new();
    assert!(message.encode(&mut buffer).is_ok());
    
    // Decode the HandshakeMessage
    let mut offset = 0;
    let decoded = HandshakeMessage::decode(&buffer, &mut offset).unwrap();
    
    // Verify the decoded HandshakeMessage
    match decoded {
        HandshakeMessage::ServerHello(decoded_server_hello) => {
            assert_eq!(decoded_server_hello.legacy_version, server_hello.legacy_version);
            assert_eq!(decoded_server_hello.random, server_hello.random);
            assert_eq!(decoded_server_hello.cipher_suite, server_hello.cipher_suite);
            assert_eq!(decoded_server_hello.extensions.len(), server_hello.extensions.len());
        }
        _ => panic!("Expected ServerHello, got something else"),
    }
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_extension_encode_decode() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create an extension
    let extension_type = ExtensionType::SupportedVersions;
    let extension_data = vec![0x03, 0x04]; // TLS 1.3
    let extension = Extension::new(extension_type, extension_data.clone());
    
    // Encode the extension
    let mut buffer = Buffer::new();
    assert!(extension.encode(&mut buffer).is_ok());
    
    // Decode the extension
    let mut offset = 0;
    let decoded = Extension::decode(&buffer, &mut offset).unwrap();
    
    // Verify the decoded extension
    assert_eq!(decoded.extension_type, extension_type);
    assert_eq!(decoded.extension_data, extension_data);
    
    // Clean up
    assert!(cleanup().is_ok());
}
