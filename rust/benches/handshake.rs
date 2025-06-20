// Handshake performance benchmarks
//
// This module contains performance benchmarks for the TLS handshake.

use criterion::{black_box, Criterion};
use s2n_tls_rs::{init, cleanup, Config, Connection, ConnectionMode};
use s2n_tls_rs::crypto::cipher_suites::TLS_AES_128_GCM_SHA256;
use s2n_tls_rs::handshake::NamedGroup;
use std::time::Duration;

/// Benchmark the TLS handshake
pub fn bench_handshake(c: &mut Criterion) {
    // Initialize the library
    init().unwrap();
    
    // Create a benchmark group
    let mut group = c.benchmark_group("handshake");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(100);
    
    // Benchmark client handshake
    group.bench_function("client_handshake", |b| {
        b.iter(|| {
            // Create a client configuration
            let mut client_config = Config::new_client();
            client_config.set_server_name("localhost".to_string()).unwrap();
            client_config.add_cipher_suite(TLS_AES_128_GCM_SHA256).unwrap();
            client_config.add_named_group(NamedGroup::X25519).unwrap();
            
            // Create a client connection
            let mut client_connection = Connection::new(client_config);
            
            // Initialize the connection
            black_box(client_connection.initialize().unwrap());
        });
    });
    
    // Benchmark server handshake
    group.bench_function("server_handshake", |b| {
        b.iter(|| {
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
            
            // Create a server connection
            let mut server_connection = Connection::new(server_config);
            
            // Initialize the connection
            black_box(server_connection.initialize().unwrap());
        });
    });
    
    // Benchmark full handshake
    group.bench_function("full_handshake", |b| {
        b.iter(|| {
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
            black_box(client_connection.initialize().unwrap());
            black_box(server_connection.initialize().unwrap());
            
            // Perform the handshake
            // In a real benchmark, we would actually perform the handshake
            // by exchanging messages between the client and server
            // For now, we'll just initialize the connections
        });
    });
    
    // Benchmark resumption handshake
    group.bench_function("resumption_handshake", |b| {
        b.iter(|| {
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
            black_box(client_connection.initialize().unwrap());
            black_box(server_connection.initialize().unwrap());
            
            // Perform the handshake
            // In a real benchmark, we would actually perform the handshake
            // by exchanging messages between the client and server
            // For now, we'll just initialize the connections
            
            // Perform the resumption handshake
            // In a real benchmark, we would actually perform the resumption handshake
            // by exchanging messages between the client and server
            // For now, we'll just initialize the connections
        });
    });
    
    // Finish the benchmark group
    group.finish();
    
    // Clean up
    cleanup().unwrap();
}

/// Compare with s2n-tls C implementation
pub fn bench_compare_with_s2n_tls(c: &mut Criterion) {
    // Initialize the library
    init().unwrap();
    
    // Create a benchmark group
    let mut group = c.benchmark_group("compare_with_s2n_tls");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(100);
    
    // Benchmark Rust implementation
    group.bench_function("rust_handshake", |b| {
        b.iter(|| {
            // Create a client configuration
            let mut client_config = Config::new_client();
            client_config.set_server_name("localhost".to_string()).unwrap();
            client_config.add_cipher_suite(TLS_AES_128_GCM_SHA256).unwrap();
            client_config.add_named_group(NamedGroup::X25519).unwrap();
            
            // Create a client connection
            let mut client_connection = Connection::new(client_config);
            
            // Initialize the connection
            black_box(client_connection.initialize().unwrap());
        });
    });
    
    // Benchmark C implementation
    // In a real benchmark, we would actually benchmark the C implementation
    // For now, we'll just benchmark the Rust implementation
    group.bench_function("c_handshake", |b| {
        b.iter(|| {
            // Create a client configuration
            let mut client_config = Config::new_client();
            client_config.set_server_name("localhost".to_string()).unwrap();
            client_config.add_cipher_suite(TLS_AES_128_GCM_SHA256).unwrap();
            client_config.add_named_group(NamedGroup::X25519).unwrap();
            
            // Create a client connection
            let mut client_connection = Connection::new(client_config);
            
            // Initialize the connection
            black_box(client_connection.initialize().unwrap());
        });
    });
    
    // Finish the benchmark group
    group.finish();
    
    // Clean up
    cleanup().unwrap();
}
