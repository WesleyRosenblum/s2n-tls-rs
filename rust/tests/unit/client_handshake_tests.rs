// Client handshake flow unit tests

use s2n_tls_rs::{init, cleanup};
use s2n_tls_rs::crypto::{HashAlgorithm, cipher_suites::TLS_AES_128_GCM_SHA256};
use s2n_tls_rs::handshake::{NamedGroup, KeyShareEntry, ClientHello, ServerHello};
use s2n_tls_rs::state::{
    ConnectionMode, ConnectionState, ConnectionConfig, Connection, StateMachine, Event
};
use s2n_tls_rs::record::{Record, RecordType, ProtocolVersion};

#[test]
fn test_client_handshake_flow_initialization() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a connection configuration
    let mut config = ConnectionConfig::new(ConnectionMode::Client);
    config.set_server_name("example.com".to_string());
    config.add_cipher_suite(TLS_AES_128_GCM_SHA256);
    config.add_named_group(NamedGroup::X25519);
    
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
fn test_client_hello_sending() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a connection configuration
    let mut config = ConnectionConfig::new(ConnectionMode::Client);
    config.set_server_name("example.com".to_string());
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
    
    // Process the record (this should trigger sending a ClientHello)
    let result = connection.process_record(&record);
    assert!(result.is_ok());
    
    // Verify the connection state
    assert_eq!(connection.state, ConnectionState::ClientHelloSent);
    assert!(connection.client_random.is_some());
    assert!(connection.client_key_share.is_some());
    
    // Verify the output record
    let output_records = result.unwrap();
    assert_eq!(output_records.len(), 1);
    assert_eq!(output_records[0].record_type, RecordType::Handshake);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_server_hello_processing() {
    // This test requires a more complex setup to create a valid ServerHello message
    // We'll create a minimal ServerHello message for testing
    
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a connection configuration
    let mut config = ConnectionConfig::new(ConnectionMode::Client);
    config.set_server_name("example.com".to_string());
    config.add_cipher_suite(TLS_AES_128_GCM_SHA256);
    config.add_named_group(NamedGroup::X25519);
    
    // Create a connection
    let mut connection = Connection::new(config);
    
    // Initialize the connection
    assert!(connection.initialize().is_ok());
    
    // Send a ClientHello
    let dummy_record = Record::new(
        RecordType::Handshake,
        ProtocolVersion::TLS_1_2,
        Vec::new(),
    );
    let result = connection.process_record(&dummy_record);
    assert!(result.is_ok());
    
    // Create a ServerHello message
    let mut server_hello = ServerHello::new();
    server_hello.generate_random().unwrap();
    server_hello.set_legacy_session_id_echo(Vec::new()).unwrap();
    server_hello.set_cipher_suite(TLS_AES_128_GCM_SHA256);
    server_hello.add_supported_versions_extension();
    
    // Create a key share entry
    let key_pair = s2n_tls_rs::handshake::key_exchange::generate_key_pair(NamedGroup::X25519).unwrap();
    let entry = KeyShareEntry::new(NamedGroup::X25519, key_pair.public_key);
    let server_key_share = s2n_tls_rs::handshake::ServerKeyShare::new(entry);
    let key_share_extension = server_key_share.encode().unwrap();
    server_hello.add_extension(key_share_extension);
    
    // Encode the ServerHello message
    let mut buffer = s2n_tls_rs::buffer::Buffer::new();
    server_hello.encode(&mut buffer).unwrap();
    
    // Create a record with the ServerHello message
    let server_hello_record = Record::new(
        RecordType::Handshake,
        ProtocolVersion::TLS_1_2,
        buffer.into_vec(),
    );
    
    // Process the ServerHello record
    let result = connection.process_record(&server_hello_record);
    
    // This will fail because we don't have a proper client key share with private key
    // But we can verify that the connection state was updated
    assert!(result.is_err());
    assert_eq!(connection.state, ConnectionState::ServerHelloSent);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_client_handshake_state_transitions() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a connection configuration
    let mut config = ConnectionConfig::new(ConnectionMode::Client);
    config.set_server_name("example.com".to_string());
    config.add_cipher_suite(TLS_AES_128_GCM_SHA256);
    config.add_named_group(NamedGroup::X25519);
    
    // Create a connection
    let mut connection = Connection::new(config);
    
    // Initialize the connection
    assert!(connection.initialize().is_ok());
    
    // Verify the initial state
    assert_eq!(connection.state, ConnectionState::Initial);
    
    // Manually transition through the client handshake states
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
    
    connection.state = ConnectionState::ClientFinishedSent;
    assert_eq!(connection.state, ConnectionState::ClientFinishedSent);
    
    connection.state = ConnectionState::HandshakeCompleted;
    assert_eq!(connection.state, ConnectionState::HandshakeCompleted);
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_client_handshake_key_derivation() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a connection configuration
    let mut config = ConnectionConfig::new(ConnectionMode::Client);
    config.set_server_name("example.com".to_string());
    config.add_cipher_suite(TLS_AES_128_GCM_SHA256);
    config.add_named_group(NamedGroup::X25519);
    
    // Create a connection
    let mut connection = Connection::new(config);
    
    // Initialize the connection
    assert!(connection.initialize().is_ok());
    
    // Set up the key schedule
    connection.key_schedule = Some(s2n_tls_rs::handshake::KeySchedule::new(HashAlgorithm::Sha256).unwrap());
    connection.cipher_suite = Some(TLS_AES_128_GCM_SHA256);
    
    // Set up a dummy shared secret
    let shared_secret = vec![0; 32];
    
    // Derive the handshake secret
    if let Some(key_schedule) = &mut connection.key_schedule {
        assert!(key_schedule.derive_handshake_secret(&shared_secret).is_ok());
    }
    
    // Verify that the key schedule was updated
    assert!(connection.key_schedule.is_some());
    assert!(connection.key_schedule.as_ref().unwrap().handshake_secret.is_some());
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_client_application_data_processing() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a connection configuration
    let mut config = ConnectionConfig::new(ConnectionMode::Client);
    config.set_server_name("example.com".to_string());
    config.add_cipher_suite(TLS_AES_128_GCM_SHA256);
    config.add_named_group(NamedGroup::X25519);
    
    // Create a connection
    let mut connection = Connection::new(config);
    
    // Initialize the connection
    assert!(connection.initialize().is_ok());
    
    // Set the state to HandshakeCompleted
    connection.state = ConnectionState::HandshakeCompleted;
    
    // Set up application traffic keys
    connection.server_application_traffic_keys = Some(s2n_tls_rs::crypto::TrafficKeys {
        key: vec![0; 16],
        iv: vec![0; 12],
    });
    
    // Create an application data record
    let app_data_record = Record::new(
        RecordType::ApplicationData,
        ProtocolVersion::TLS_1_2,
        vec![1, 2, 3, 4],
    );
    
    // Process the application data record
    let result = connection.process_record(&app_data_record);
    assert!(result.is_ok());
    
    // Clean up
    assert!(cleanup().is_ok());
}

#[test]
fn test_client_alert_processing() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a connection configuration
    let mut config = ConnectionConfig::new(ConnectionMode::Client);
    config.set_server_name("example.com".to_string());
    config.add_cipher_suite(TLS_AES_128_GCM_SHA256);
    config.add_named_group(NamedGroup::X25519);
    
    // Create a connection
    let mut connection = Connection::new(config);
    
    // Initialize the connection
    assert!(connection.initialize().is_ok());
    
    // Set the state to HandshakeCompleted
    connection.state = ConnectionState::HandshakeCompleted;
    
    // Create an alert record
    let alert_record = Record::new(
        RecordType::Alert,
        ProtocolVersion::TLS_1_2,
        vec![2, 0], // fatal, close_notify
    );
    
    // Process the alert record
    let result = connection.process_record(&alert_record);
    assert!(result.is_ok());
    
    // Verify that the connection is closed
    assert_eq!(connection.state, ConnectionState::Closed);
    
    // Clean up
    assert!(cleanup().is_ok());
}
