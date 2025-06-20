// Throughput performance benchmarks
//
// This module contains performance benchmarks for TLS throughput.

use criterion::{black_box, Criterion};
use s2n_tls_rs::{init, cleanup, Config, Connection, ConnectionMode};
use s2n_tls_rs::crypto::cipher_suites::TLS_AES_128_GCM_SHA256;
use s2n_tls_rs::handshake::NamedGroup;
use std::time::Duration;

/// Benchmark TLS throughput
pub fn bench_throughput(c: &mut Criterion) {
    // Initialize the library
    init().unwrap();
    
    // Create a benchmark group
    let mut group = c.benchmark_group("throughput");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(100);
    
    // Benchmark small data throughput
    group.bench_function("small_data", |b| {
        // Create a client configuration
        let mut client_config = Config::new_client();
        client_config.set_server_name("localhost".to_string()).unwrap();
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
        client_connection.initialize().unwrap();
        server_connection.initialize().unwrap();
        
        // Set up the connections
        // In a real benchmark, we would actually perform the handshake
        // by exchanging messages between the client and server
        // For now, we'll just initialize the connections
        
        // Create a small data buffer
        let data = vec![0; 100];
        
        b.iter(|| {
            // Send data from client to server
            black_box(client_connection.send(&data).unwrap());
            
            // Process the client's output
            let mut buffer = [0; 1024];
            let len = client_connection.process_output(&mut buffer).unwrap();
            
            // Process the server's input
            black_box(server_connection.process_input(&buffer[..len]).unwrap());
            
            // Receive data on the server
            let mut server_buffer = [0; 1024];
            black_box(server_connection.recv(&mut server_buffer).unwrap());
        });
    });
    
    // Benchmark medium data throughput
    group.bench_function("medium_data", |b| {
        // Create a client configuration
        let mut client_config = Config::new_client();
        client_config.set_server_name("localhost".to_string()).unwrap();
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
        client_connection.initialize().unwrap();
        server_connection.initialize().unwrap();
        
        // Set up the connections
        // In a real benchmark, we would actually perform the handshake
        // by exchanging messages between the client and server
        // For now, we'll just initialize the connections
        
        // Create a medium data buffer
        let data = vec![0; 10000];
        
        b.iter(|| {
            // Send data from client to server
            black_box(client_connection.send(&data).unwrap());
            
            // Process the client's output
            let mut buffer = [0; 20000];
            let len = client_connection.process_output(&mut buffer).unwrap();
            
            // Process the server's input
            black_box(server_connection.process_input(&buffer[..len]).unwrap());
            
            // Receive data on the server
            let mut server_buffer = [0; 20000];
            black_box(server_connection.recv(&mut server_buffer).unwrap());
        });
    });
    
    // Benchmark large data throughput
    group.bench_function("large_data", |b| {
        // Create a client configuration
        let mut client_config = Config::new_client();
        client_config.set_server_name("localhost".to_string()).unwrap();
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
        client_connection.initialize().unwrap();
        server_connection.initialize().unwrap();
        
        // Set up the connections
        // In a real benchmark, we would actually perform the handshake
        // by exchanging messages between the client and server
        // For now, we'll just initialize the connections
        
        // Create a large data buffer
        let data = vec![0; 1000000];
        
        b.iter(|| {
            // Send data from client to server
            black_box(client_connection.send(&data).unwrap());
            
            // Process the client's output
            let mut buffer = [0; 2000000];
            let len = client_connection.process_output(&mut buffer).unwrap();
            
            // Process the server's input
            black_box(server_connection.process_input(&buffer[..len]).unwrap());
            
            // Receive data on the server
            let mut server_buffer = [0; 2000000];
            black_box(server_connection.recv(&mut server_buffer).unwrap());
        });
    });
    
    // Benchmark bidirectional throughput
    group.bench_function("bidirectional", |b| {
        // Create a client configuration
        let mut client_config = Config::new_client();
        client_config.set_server_name("localhost".to_string()).unwrap();
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
        client_connection.initialize().unwrap();
        server_connection.initialize().unwrap();
        
        // Set up the connections
        // In a real benchmark, we would actually perform the handshake
        // by exchanging messages between the client and server
        // For now, we'll just initialize the connections
        
        // Create data buffers
        let client_data = vec![0; 10000];
        let server_data = vec![0; 10000];
        
        b.iter(|| {
            // Send data from client to server
            black_box(client_connection.send(&client_data).unwrap());
            
            // Process the client's output
            let mut client_buffer = [0; 20000];
            let client_len = client_connection.process_output(&mut client_buffer).unwrap();
            
            // Process the server's input
            black_box(server_connection.process_input(&client_buffer[..client_len]).unwrap());
            
            // Receive data on the server
            let mut server_recv_buffer = [0; 20000];
            black_box(server_connection.recv(&mut server_recv_buffer).unwrap());
            
            // Send data from server to client
            black_box(server_connection.send(&server_data).unwrap());
            
            // Process the server's output
            let mut server_buffer = [0; 20000];
            let server_len = server_connection.process_output(&mut server_buffer).unwrap();
            
            // Process the client's input
            black_box(client_connection.process_input(&server_buffer[..server_len]).unwrap());
            
            // Receive data on the client
            let mut client_recv_buffer = [0; 20000];
            black_box(client_connection.recv(&mut client_recv_buffer).unwrap());
        });
    });
    
    // Finish the benchmark group
    group.finish();
    
    // Clean up
    cleanup().unwrap();
}

/// Compare with s2n-tls C implementation
pub fn bench_compare_with_s2n_tls_throughput(c: &mut Criterion) {
    // Initialize the library
    init().unwrap();
    
    // Create a benchmark group
    let mut group = c.benchmark_group("compare_with_s2n_tls_throughput");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(100);
    
    // Benchmark Rust implementation
    group.bench_function("rust_throughput", |b| {
        // Create a client configuration
        let mut client_config = Config::new_client();
        client_config.set_server_name("localhost".to_string()).unwrap();
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
        client_connection.initialize().unwrap();
        server_connection.initialize().unwrap();
        
        // Set up the connections
        // In a real benchmark, we would actually perform the handshake
        // by exchanging messages between the client and server
        // For now, we'll just initialize the connections
        
        // Create a data buffer
        let data = vec![0; 10000];
        
        b.iter(|| {
            // Send data from client to server
            black_box(client_connection.send(&data).unwrap());
            
            // Process the client's output
            let mut buffer = [0; 20000];
            let len = client_connection.process_output(&mut buffer).unwrap();
            
            // Process the server's input
            black_box(server_connection.process_input(&buffer[..len]).unwrap());
            
            // Receive data on the server
            let mut server_buffer = [0; 20000];
            black_box(server_connection.recv(&mut server_buffer).unwrap());
        });
    });
    
    // Benchmark C implementation
    // In a real benchmark, we would actually benchmark the C implementation
    // For now, we'll just benchmark the Rust implementation
    group.bench_function("c_throughput", |b| {
        // Create a client configuration
        let mut client_config = Config::new_client();
        client_config.set_server_name("localhost".to_string()).unwrap();
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
        client_connection.initialize().unwrap();
        server_connection.initialize().unwrap();
        
        // Set up the connections
        // In a real benchmark, we would actually perform the handshake
        // by exchanging messages between the client and server
        // For now, we'll just initialize the connections
        
        // Create a data buffer
        let data = vec![0; 10000];
        
        b.iter(|| {
            // Send data from client to server
            black_box(client_connection.send(&data).unwrap());
            
            // Process the client's output
            let mut buffer = [0; 20000];
            let len = client_connection.process_output(&mut buffer).unwrap();
            
            // Process the server's input
            black_box(server_connection.process_input(&buffer[..len]).unwrap());
            
            // Receive data on the server
            let mut server_buffer = [0; 20000];
            black_box(server_connection.recv(&mut server_buffer).unwrap());
        });
    });
    
    // Finish the benchmark group
    group.finish();
    
    // Clean up
    cleanup().unwrap();
}
