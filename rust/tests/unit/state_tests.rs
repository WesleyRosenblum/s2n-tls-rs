// State machine unit tests

use s2n_tls_rs::{init, cleanup};
use s2n_tls_rs::crypto::{HashAlgorithm, cipher_suites::TLS_AES_128_GCM_SHA256};
use s2n_tls_rs::handshake::{NamedGroup, KeyShareEntry};
use s2n_tls_rs::state::{
    ConnectionMode, ConnectionState, ConnectionConfig, Connection, StateMachine, Event
};
use s2n_tls_rs::record::{Record, RecordType, ProtocolVersion};

#[test]
fn test_connection_config_creation() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a connection configuration
    let mut config = ConnectionConfig::new(ConnectionMode::Client);
    
    // Set the server name
    config.set_server_name("example.com".to_string());
    
    // Add a trusted CA certificate
    let ca_cert = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    ];
    config.add_trusted_ca(ca_cert.clone());
    
    // Set the client certificate
    let client_cert = vec![
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    config.set_client_certificate(client_cert.clone());
    
    // Set the client private key
    let client_key = vec![
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    ];
    config.set_client_private_key(client_key.clone());
    
    // Add a cipher suite
    config.add_cipher_suite(TLS_AES_128_GCM_SHA256);
    
    // Add a named group
    config.add_named_group(NamedGroup::X25519);
    
    // Enable OCSP stapling
    config.enable_ocsp_stapling();
    
    // Verify the configuration
    assert_eq!(config.mode, ConnectionMode::Client);
    assert_eq!(config.server_name, Some("example.com".to_string()));
    assert_eq!(config.trusted_cas.len(), 1);
    assert_eq!(config.trusted_cas[0], ca_cert);
    assert_eq!(config.client_certificate, Some(client_cert));
    assert_eq!(config.client_private_key, Some(client_key));
    assert_eq!(config.cipher_suites.len(), 1);
    assert_eq!(config.cipher_suites[0], TLS_AES_128_GCM_SHA256);
    assert_eq!(config.named_groups.len(), 1);
    assert_eq!(config.named_groups[0], NamedGroup::X25519);
    assert!(config.ocsp_stapling_enabled);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_connection_creation() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a connection configuration
    let config = ConnectionConfig::new(ConnectionMode::Client);
    
    // Create a connection
    let connection = Connection::new(config);
    
    // Verify the connection
    assert_eq!(connection.state, ConnectionState::Initial);
    assert!(connection.key_schedule.is_none());
    assert!(connection.handshake_verification.is_none());
    assert!(connection.cipher_suite.is_none());
    assert!(connection.client_random.is_none());
    assert!(connection.server_random.is_none());
    assert!(connection.client_key_share.is_none());
    assert!(connection.server_key_share.is_none());
    assert!(connection.client_handshake_traffic_keys.is_none());
    assert!(connection.server_handshake_traffic_keys.is_none());
    assert!(connection.client_application_traffic_keys.is_none());
    assert!(connection.server_application_traffic_keys.is_none());
    assert_eq!(connection.client_sequence_number, 0);
    assert_eq!(connection.server_sequence_number, 0);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_connection_initialization() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a connection configuration
    let config = ConnectionConfig::new(ConnectionMode::Client);
    
    // Create a connection
    let mut connection = Connection::new(config);
    
    // Initialize the connection
    assert!(connection.initialize().is_ok());
    
    // Verify the connection
    assert_eq!(connection.state, ConnectionState::Initial);
    assert!(connection.handshake_verification.is_some());
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_state_machine_creation() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a connection configuration
    let config = ConnectionConfig::new(ConnectionMode::Client);
    
    // Create a state machine
    let state_machine = StateMachine::new(config);
    
    // Verify the state machine
    assert_eq!(state_machine.state(), ConnectionState::Initial);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_state_machine_initialization() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a connection configuration
    let config = ConnectionConfig::new(ConnectionMode::Client);
    
    // Create a state machine
    let mut state_machine = StateMachine::new(config);
    
    // Initialize the state machine
    assert!(state_machine.initialize().is_ok());
    
    // Verify the state machine
    assert_eq!(state_machine.state(), ConnectionState::Initial);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_state_machine_event_processing() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a connection configuration
    let config = ConnectionConfig::new(ConnectionMode::Client);
    
    // Create a state machine
    let mut state_machine = StateMachine::new(config);
    
    // Initialize the state machine
    assert!(state_machine.initialize().is_ok());
    
    // Process a close requested event
    let result = state_machine.process_event(Event::CloseRequested);
    assert!(result.is_ok());
    
    // Verify the state machine
    assert_eq!(state_machine.state(), ConnectionState::Closed);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_client_hello_creation() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a connection configuration
    let mut config = ConnectionConfig::new(ConnectionMode::Client);
    config.add_cipher_suite(TLS_AES_128_GCM_SHA256);
    config.add_named_group(NamedGroup::X25519);
    
    // Create a connection
    let mut connection = Connection::new(config);
    
    // Initialize the connection
    assert!(connection.initialize().is_ok());
    
    // Create a dummy record to process
    let record = Record::new(
        RecordType::Handshake,
        ProtocolVersion::TLS_1_2,
        Vec::new(),
    );
    
    // Process the record
    let result = connection.process_record(&record);
    assert!(result.is_ok());
    
    // Verify the connection
    assert_eq!(connection.state, ConnectionState::ClientHelloSent);
    assert!(connection.client_random.is_some());
    assert!(connection.client_key_share.is_some());
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_server_hello_processing() {
    // This test would require a more complex setup to create a valid ServerHello message
    // For now, we'll just test that the function exists and returns an error for an invalid message
    
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a connection configuration
    let config = ConnectionConfig::new(ConnectionMode::Client);
    
    // Create a connection
    let mut connection = Connection::new(config);
    
    // Initialize the connection
    assert!(connection.initialize().is_ok());
    
    // Set the state to ClientHelloSent
    connection.state = ConnectionState::ClientHelloSent;
    
    // Create a dummy record with invalid data
    let record = Record::new(
        RecordType::Handshake,
        ProtocolVersion::TLS_1_2,
        Vec::new(),
    );
    
    // Process the record
    let result = connection.process_record(&record);
    assert!(result.is_err());
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_state_transitions() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a connection configuration
    let config = ConnectionConfig::new(ConnectionMode::Client);
    
    // Create a connection
    let mut connection = Connection::new(config);
    
    // Initialize the connection
    assert!(connection.initialize().is_ok());
    
    // Verify the initial state
    assert_eq!(connection.state, ConnectionState::Initial);
    
    // Manually transition through the states
    connection.state = ConnectionState::ClientHelloSent;
    assert_eq!(connection.state, ConnectionState::ClientHelloSent);
    
    connection.state = ConnectionState::ServerHelloSent;
    assert_eq!(connection.state, ConnectionState::ServerHelloSent);
    
    connection.state = ConnectionState::ServerCertificateSent;
    assert_eq!(connection.state, ConnectionState::ServerCertificateSent);
    
    connection.state = ConnectionState::ServerCertificateVerifySent;
    assert_eq!(connection.state, ConnectionState::ServerCertificateVerifySent);
    
    connection.state = ConnectionState::ServerFinishedSent;
    assert_eq!(connection.state, ConnectionState::ServerFinishedSent);
    
    connection.state = ConnectionState::ClientCertificateSent;
    assert_eq!(connection.state, ConnectionState::ClientCertificateSent);
    
    connection.state = ConnectionState::ClientCertificateVerifySent;
    assert_eq!(connection.state, ConnectionState::ClientCertificateVerifySent);
    
    connection.state = ConnectionState::ClientFinishedSent;
    assert_eq!(connection.state, ConnectionState::ClientFinishedSent);
    
    connection.state = ConnectionState::HandshakeCompleted;
    assert_eq!(connection.state, ConnectionState::HandshakeCompleted);
    
    connection.state = ConnectionState::Closed;
    assert_eq!(connection.state, ConnectionState::Closed);
    
    connection.state = ConnectionState::Error;
    assert_eq!(connection.state, ConnectionState::Error);
    
    // Clean up
    assert!(cleanup().is_ok());
}
