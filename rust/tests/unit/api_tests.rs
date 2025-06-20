// API unit tests

use s2n_tls_rs::{init, cleanup, Config, Connection, ConnectionMode, BlockedStatus, ConnectionStatus};
use s2n_tls_rs::crypto::cipher_suites::TLS_AES_128_GCM_SHA256;
use s2n_tls_rs::handshake::NamedGroup;

#[test]
fn test_config_creation() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a client configuration
    let mut config = Config::new_client();
    
    // Set the server name
    assert!(config.set_server_name("example.com".to_string()).is_ok());
    
    // Add a trusted CA certificate
    let ca_cert = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    ];
    assert!(config.add_trusted_ca(ca_cert.clone()).is_ok());
    
    // Set the client certificate
    let client_cert = vec![
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    assert!(config.set_client_certificate(client_cert.clone()).is_ok());
    
    // Set the client private key
    let client_key = vec![
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    ];
    assert!(config.set_client_private_key(client_key.clone()).is_ok());
    
    // Add a cipher suite
    assert!(config.add_cipher_suite(TLS_AES_128_GCM_SHA256).is_ok());
    
    // Add a named group
    assert!(config.add_named_group(NamedGroup::X25519).is_ok());
    
    // Enable OCSP stapling
    assert!(config.enable_ocsp_stapling().is_ok());
    
    // Verify the configuration
    assert_eq!(config.mode(), ConnectionMode::Client);
    assert_eq!(config.server_name(), Some("example.com"));
    assert_eq!(config.trusted_cas().len(), 1);
    assert_eq!(config.trusted_cas()[0], ca_cert);
    assert_eq!(config.client_certificate(), Some(client_cert.as_slice()));
    assert_eq!(config.client_private_key(), Some(client_key.as_slice()));
    assert_eq!(config.cipher_suites().len(), 1);
    assert_eq!(config.cipher_suites()[0], TLS_AES_128_GCM_SHA256);
    assert_eq!(config.named_groups().len(), 1);
    assert_eq!(config.named_groups()[0], NamedGroup::X25519);
    assert!(config.is_ocsp_stapling_enabled());
    
    // Disable OCSP stapling
    assert!(config.disable_ocsp_stapling().is_ok());
    
    // Verify the configuration
    assert!(!config.is_ocsp_stapling_enabled());
    
    // Create a server configuration
    let mut config = Config::new_server();
    
    // Set the server certificate
    let server_cert = vec![
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
    ];
    assert!(config.set_server_certificate(server_cert.clone()).is_ok());
    
    // Set the server private key
    let server_key = vec![
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
    ];
    assert!(config.set_server_private_key(server_key.clone()).is_ok());
    
    // Verify the configuration
    assert_eq!(config.mode(), ConnectionMode::Server);
    assert_eq!(config.server_certificate(), Some(server_cert.as_slice()));
    assert_eq!(config.server_private_key(), Some(server_key.as_slice()));
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_connection_creation() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a client configuration
    let config = Config::new_client();
    
    // Create a client connection
    let connection = Connection::new(config);
    
    // Verify the connection
    assert_eq!(connection.status(), ConnectionStatus::Handshaking);
    assert_eq!(connection.blocked_status(), BlockedStatus::NotBlocked);
    assert_eq!(connection.mode(), ConnectionMode::Client);
    assert!(connection.is_handshaking());
    assert!(!connection.is_established());
    assert!(!connection.is_closed());
    assert!(!connection.is_error());
    assert!(!connection.is_blocked());
    assert!(!connection.is_read_blocked());
    assert!(!connection.is_write_blocked());
    assert!(!connection.is_application_data_blocked());
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_connection_initialization() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a client configuration
    let config = Config::new_client();
    
    // Create a client connection
    let mut connection = Connection::new(config);
    
    // Initialize the connection
    assert!(connection.initialize().is_ok());
    
    // Verify the connection
    assert_eq!(connection.status(), ConnectionStatus::Handshaking);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_connection_negotiation() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a client configuration
    let mut config = Config::new_client();
    config.set_server_name("example.com".to_string()).unwrap();
    config.add_cipher_suite(TLS_AES_128_GCM_SHA256).unwrap();
    config.add_named_group(NamedGroup::X25519).unwrap();
    
    // Create a client connection
    let mut connection = Connection::new(config);
    
    // Initialize the connection
    assert!(connection.initialize().is_ok());
    
    // Negotiate the connection
    // This will fail because we don't have a server to connect to
    // But we can verify that the connection is still in handshaking state
    assert!(connection.negotiate().is_err());
    assert!(connection.is_handshaking());
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_connection_send_recv() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a client configuration
    let config = Config::new_client();
    
    // Create a client connection
    let mut connection = Connection::new(config);
    
    // Initialize the connection
    assert!(connection.initialize().is_ok());
    
    // Send data
    // This will fail because the connection is not established
    let data = b"Hello, world!";
    assert!(connection.send(data).is_err());
    
    // Receive data
    // This will fail because the connection is not established
    let mut buffer = [0; 1024];
    assert!(connection.recv(&mut buffer).is_err());
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_connection_close() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a client configuration
    let config = Config::new_client();
    
    // Create a client connection
    let mut connection = Connection::new(config);
    
    // Initialize the connection
    assert!(connection.initialize().is_ok());
    
    // Close the connection
    assert!(connection.close().is_ok());
    
    // Verify the connection
    assert!(connection.is_closed());
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_connection_wipe() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a client configuration
    let config = Config::new_client();
    
    // Create a client connection
    let mut connection = Connection::new(config);
    
    // Initialize the connection
    assert!(connection.initialize().is_ok());
    
    // Wipe the connection
    connection.wipe();
    
    // Verify the connection
    assert!(connection.is_closed());
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_connection_process_input_output() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a client configuration
    let config = Config::new_client();
    
    // Create a client connection
    let mut connection = Connection::new(config);
    
    // Initialize the connection
    assert!(connection.initialize().is_ok());
    
    // Process input
    let data = b"Hello, world!";
    assert!(connection.process_input(data).is_ok());
    
    // Process output
    let mut buffer = [0; 1024];
    assert!(connection.process_output(&mut buffer).is_ok());
    
    // Clean up
    assert!(cleanup().is_ok());
}
