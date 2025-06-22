# s2n-tls-rs

A memory-safe TLS implementation in Rust compatible with s2n-tls.

## Overview

s2n-tls-rs is a Rust implementation of the TLS protocol that is compatible with the s2n-tls C implementation. It focuses on memory safety, performance, and interoperability with s2n-tls.

The implementation currently supports TLS 1.3 as specified in RFC 8446.

## Features

- Memory-safe TLS implementation in Rust
- Compatible with s2n-tls C implementation
- Uses aws-lc-rs for cryptographic operations
- Supports TLS 1.3 protocol (RFC 8446)
- Provides both client and server functionality
- Zero-copy parsing with the zerocopy crate
- Comprehensive error handling with thiserror
- Extensive test coverage including property testing and differential fuzzing

## Building

### Prerequisites

- Rust 1.65 or later
- Cargo
- CMake (for aws-lc-rs)
- C compiler (for aws-lc-rs)

### Building the Library

To build the library, run:

```bash
cd rust
cargo build
```

For a release build, run:

```bash
cd rust
cargo build --release
```

### Running Tests

To run the tests, run:

```bash
cd rust
cargo test
```

The project includes several types of tests:

- **Unit Tests**: Test individual components in isolation
- **Property Tests**: Test properties of components with randomly generated inputs using Bolero
- **Snapshot Tests**: Test that output matches expected snapshots using insta
- **Compliance Tests**: Ensure compliance with TLS specifications using Duvet
- **Interoperability Tests**: Verify interoperability with the C s2n-tls implementation
- **Differential Fuzzing**: Compare behavior with s2n-tls C implementation

For more information about the testing infrastructure, see [tests/README.md](tests/README.md).

#### Running Specific Test Types

```bash
# Run unit tests
make test-unit

# Run property tests
make test-property

# Run snapshot tests
make test-snapshot

# Run interoperability tests
make test-interop

# Run differential fuzzing tests
make test-fuzzing

# Generate compliance report
make compliance-report
```

### Building with FIPS Support

To build with FIPS support, enable the `fips` feature:

```bash
cd rust
cargo build --features fips
```

## Usage Guide

### Library Initialization

Before using any functionality, you must initialize the library:

```rust
use s2n_tls_rs::init;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the library
    init()?;
    
    // Use the library...
    
    // Clean up when done
    s2n_tls_rs::cleanup()?;
    
    Ok(())
}
```

### Creating a TLS Client

Here's how to create a TLS client that connects to a server:

```rust
use s2n_tls_rs::{init, Config, Connection};
use s2n_tls_rs::crypto::cipher_suites::TLS_AES_128_GCM_SHA256;
use s2n_tls_rs::handshake::NamedGroup;
use std::io::{Read, Write};
use std::net::TcpStream;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the library
    init()?;
    
    // Create a client configuration
    let mut config = Config::new_client();
    config.set_server_name("example.com".to_string())?;
    config.add_cipher_suite(TLS_AES_128_GCM_SHA256)?;
    config.add_named_group(NamedGroup::X25519)?;
    
    // Create a client connection
    let mut connection = Connection::new(config);
    connection.initialize()?;
    
    // Connect to the server
    let mut stream = TcpStream::connect("example.com:443")?;
    
    // Perform the TLS handshake
    connection.negotiate()?;
    
    // Send data
    connection.send(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")?;
    
    // Process the output
    let mut output_buffer = [0; 16384];
    let len = connection.process_output(&mut output_buffer)?;
    stream.write_all(&output_buffer[..len])?;
    
    // Receive data
    let mut response_buffer = [0; 16384];
    let bytes_read = stream.read(&mut response_buffer)?;
    connection.process_input(&response_buffer[..bytes_read])?;
    
    // Get the decrypted data
    let mut decrypted_buffer = [0; 16384];
    let decrypted_bytes = connection.recv(&mut decrypted_buffer)?;
    println!("{}", String::from_utf8_lossy(&decrypted_buffer[..decrypted_bytes]));
    
    // Close the connection
    connection.close()?;
    
    // Clean up
    s2n_tls_rs::cleanup()?;
    
    Ok(())
}
```

### Creating a TLS Server

Here's how to create a TLS server that accepts connections:

```rust
use s2n_tls_rs::{init, Config, Connection};
use s2n_tls_rs::crypto::cipher_suites::TLS_AES_128_GCM_SHA256;
use s2n_tls_rs::handshake::NamedGroup;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

fn handle_client(stream: TcpStream, cert_data: Vec<u8>, key_data: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
    // Create a server configuration
    let mut config = Config::new_server();
    config.set_server_certificate(cert_data)?;
    config.set_server_private_key(key_data)?;
    config.add_cipher_suite(TLS_AES_128_GCM_SHA256)?;
    config.add_named_group(NamedGroup::X25519)?;
    
    // Create a server connection
    let mut connection = Connection::new(config);
    connection.initialize()?;
    
    // Perform the TLS handshake
    connection.negotiate()?;
    
    // Handle client data...
    
    // Close the connection
    connection.close()?;
    
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the library
    init()?;
    
    // Read certificate and key
    let mut cert_data = Vec::new();
    let mut key_data = Vec::new();
    File::open("server.cert.pem")?.read_to_end(&mut cert_data)?;
    File::open("server.key.pem")?.read_to_end(&mut key_data)?;
    
    // Create a TCP listener
    let listener = TcpListener::bind("0.0.0.0:8443")?;
    
    // Accept connections
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let cert_clone = cert_data.clone();
                let key_clone = key_data.clone();
                std::thread::spawn(move || {
                    if let Err(e) = handle_client(stream, cert_clone, key_clone) {
                        eprintln!("Error handling client: {}", e);
                    }
                });
            }
            Err(e) => {
                eprintln!("Error accepting connection: {}", e);
            }
        }
    }
    
    // Clean up
    s2n_tls_rs::cleanup()?;
    
    Ok(())
}
```

### Error Handling

The library uses the `thiserror` crate for defining error types. All errors are wrapped in the `Error` enum, which provides detailed information about the error:

```rust
use s2n_tls_rs::{init, Error};

fn main() {
    match init() {
        Ok(()) => println!("Library initialized successfully"),
        Err(e) => match e {
            Error::Io(io_err) => eprintln!("I/O error: {}", io_err),
            Error::Protocol { kind, .. } => eprintln!("Protocol error: {}", kind),
            Error::Crypto { kind, .. } => eprintln!("Crypto error: {}", kind),
            Error::Config { kind, .. } => eprintln!("Config error: {}", kind),
            Error::Internal { kind, .. } => eprintln!("Internal error: {}", kind),
            Error::Usage { kind, .. } => eprintln!("Usage error: {}", kind),
            Error::Closed => eprintln!("Connection closed"),
            Error::Blocked(blocked_err) => eprintln!("Operation would block: {}", blocked_err),
            Error::Alert(alert_code) => eprintln!("TLS alert received: {}", alert_code),
        }
    }
}
```

### Interoperability with s2n-tls

The library is designed to be interoperable with the s2n-tls C implementation. You can use the Rust implementation as a client connecting to an s2n-tls server, or as a server accepting connections from an s2n-tls client.

See the [examples/interop.rs](examples/interop.rs) file for a complete example of interoperability between the Rust and C implementations.

## Performance

The library is designed to be performant, with a focus on minimizing memory allocations and copying. It uses the zerocopy crate for zero-copy parsing and serialization.

For performance benchmarks, see the [benches](benches) directory.

## Security

Security is the top priority for this library. It leverages Rust's safety guarantees to prevent memory-related vulnerabilities, and uses aws-lc-rs for cryptographic operations.

The library is designed to be resistant to various attacks, including:

- Timing attacks
- Buffer overflows
- Memory leaks
- Protocol downgrade attacks
- Padding oracle attacks

## License

This library is licensed under the Apache License 2.0.
