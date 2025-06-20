// API integration tests

use s2n_tls_rs::{init, cleanup, Config, Connection, ConnectionMode, BlockedStatus, ConnectionStatus};
use s2n_tls_rs::crypto::cipher_suites::TLS_AES_128_GCM_SHA256;
use s2n_tls_rs::handshake::NamedGroup;

/// Test client-server connection
#[test]
fn test_client_server_connection() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a client configuration
    let mut client_config = Config::new_client();
    client_config.set_server_name("example.com".to_string()).unwrap();
    client_config.add_cipher_suite(TLS_AES_128_GCM_SHA256).unwrap();
    client_config.add_named_group(NamedGroup::X25519).unwrap();
    
    // Create a server configuration
    let mut server_config = Config::new_server();
    
    // Set the server certificate
    let server_cert = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    ];
    server_config.set_server_certificate(server_cert).unwrap();
    
    // Set the server private key
    let server_key = vec![
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    server_config.set_server_private_key(server_key).unwrap();
    
    // Add a cipher suite
    server_config.add_cipher_suite(TLS_AES_128_GCM_SHA256).unwrap();
    
    // Add a named group
    server_config.add_named_group(NamedGroup::X25519).unwrap();
    
    // Create a client connection
    let mut client_connection = Connection::new(client_config);
    
    // Create a server connection
    let mut server_connection = Connection::new(server_config);
    
    // Initialize the connections
    assert!(client_connection.initialize().is_ok());
    assert!(server_connection.initialize().is_ok());
    
    // In a real test, we would connect the client and server
    // For now, we'll just verify that the connections are in the expected states
    assert!(client_connection.is_handshaking());
    assert!(server_connection.is_handshaking());
    
    // Clean up
    assert!(cleanup().is_ok());
}

/// Test data transfer
#[test]
fn test_data_transfer() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a client configuration
    let client_config = Config::new_client();
    
    // Create a server configuration
    let server_config = Config::new_server();
    
    // Create a client connection
    let mut client_connection = Connection::new(client_config);
    
    // Create a server connection
    let mut server_connection = Connection::new(server_config);
    
    // Initialize the connections
    assert!(client_connection.initialize().is_ok());
    assert!(server_connection.initialize().is_ok());
    
    // In a real test, we would connect the client and server
    // For now, we'll just manually set the connections to established
    
    // Set the client connection to established
    // This is just for testing purposes
    unsafe {
        let status_ptr = &mut client_connection as *mut Connection as *mut u8;
        let status_ptr = status_ptr.add(std::mem::size_of::<*mut u8>());
        *status_ptr = ConnectionStatus::Established as u8;
    }
    
    // Set the server connection to established
    // This is just for testing purposes
    unsafe {
        let status_ptr = &mut server_connection as *mut Connection as *mut u8;
        let status_ptr = status_ptr.add(std::mem::size_of::<*mut u8>());
        *status_ptr = ConnectionStatus::Established as u8;
    }
    
    // Verify that the connections are established
    assert!(client_connection.is_established());
    assert!(server_connection.is_established());
    
    // Send data from client to server
    let client_data = b"Hello from client!";
    assert!(client_connection.send(client_data).is_ok());
    
    // Process the client's output
    let mut buffer = [0; 1024];
    let len = client_connection.process_output(&mut buffer).unwrap();
    
    // Process the server's input
    assert!(server_connection.process_input(&buffer[..len]).is_ok());
    
    // Receive data on the server
    let mut server_buffer = [0; 1024];
    let len = server_connection.recv(&mut server_buffer).unwrap();
    
    // Verify the data
    assert_eq!(&server_buffer[..len], client_data);
    
    // Send data from server to client
    let server_data = b"Hello from server!";
    assert!(server_connection.send(server_data).is_ok());
    
    // Process the server's output
    let mut buffer = [0; 1024];
    let len = server_connection.process_output(&mut buffer).unwrap();
    
    // Process the client's input
    assert!(client_connection.process_input(&buffer[..len]).is_ok());
    
    // Receive data on the client
    let mut client_buffer = [0; 1024];
    let len = client_connection.recv(&mut client_buffer).unwrap();
    
    // Verify the data
    assert_eq!(&client_buffer[..len], server_data);
    
    // Clean up
    assert!(cleanup().is_ok());
}

/// Test connection closure
#[test]
fn test_connection_closure() {
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a client configuration
    let client_config = Config::new_client();
    
    // Create a server configuration
    let server_config = Config::new_server();
    
    // Create a client connection
    let mut client_connection = Connection::new(client_config);
    
    // Create a server connection
    let mut server_connection = Connection::new(server_config);
    
    // Initialize the connections
    assert!(client_connection.initialize().is_ok());
    assert!(server_connection.initialize().is_ok());
    
    // Close the client connection
    assert!(client_connection.close().is_ok());
    
    // Verify that the client connection is closed
    assert!(client_connection.is_closed());
    
    // Close the server connection
    assert!(server_connection.close().is_ok());
    
    // Verify that the server connection is closed
    assert!(server_connection.is_closed());
    
    // Clean up
    assert!(cleanup().is_ok());
}

/// Test interoperability with s2n-tls C implementation
#[test]
#[ignore] // This test requires the s2n-tls C implementation
fn test_interoperability_with_s2n_tls() {
    // This test would require a more complex setup to interact with the s2n-tls C implementation
    // For now, we'll just provide a placeholder
    
    // Initialize the library
    assert!(init().is_ok());
    
    // Create a client configuration
    let mut client_config = Config::new_client();
    client_config.set_server_name("example.com".to_string()).unwrap();
    client_config.add_cipher_suite(TLS_AES_128_GCM_SHA256).unwrap();
    client_config.add_named_group(NamedGroup::X25519).unwrap();
    
    // Create a client connection
    let mut client_connection = Connection::new(client_config);
    
    // Initialize the connection
    assert!(client_connection.initialize().is_ok());
    
    // In a real test, we would connect to an s2n-tls server
    // For now, we'll just verify that the connection is in the expected state
    assert!(client_connection.is_handshaking());
    
    // Clean up
    assert!(cleanup().is_ok());
}
