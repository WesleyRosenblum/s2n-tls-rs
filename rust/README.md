# s2n-tls-rs

A memory-safe TLS implementation in Rust compatible with s2n-tls.

## Overview

s2n-tls-rs is a Rust implementation of the TLS protocol that is compatible with the s2n-tls C implementation. It focuses on memory safety, performance, and interoperability with s2n-tls.

The implementation currently supports TLS 1.3 as specified in RFC 8446.

## Features

- Memory-safe TLS implementation in Rust
- Compatible with s2n-tls
- Uses aws-lc-rs for cryptographic operations
- Supports TLS 1.3
- Provides both client and server functionality

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

### Building with FIPS Support

To build with FIPS support, enable the `fips` feature:

```bash
cd rust
cargo build --features fips
```

## Usage

### Basic Usage

```rust
use s2n_tls_rs::{init, Config, Connection};
use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the library
    init()?;
    
    // Create a configuration
    let mut config = Config::new()?;
    // Configure the client or server
    
    // Create a connection
    let mut conn = Connection::new_client()?;
    conn.set_config(Arc::new(config))?;
    
    // Set up I/O
    // ...
    
    // Perform the TLS handshake
    conn.negotiate()?;
    
    // Send and receive data
    conn.send(b"Hello, world!")?;
    let mut buf = [0u8; 1024];
    let n = conn.recv(&mut buf)?;
    
    // Close the connection
    conn.shutdown()?;
    
    Ok(())
}
```

### Demo Application

The library includes a demo application that shows how to use the library in both client and server modes.

To run the demo application in client mode:

```bash
cd rust
cargo run --bin s2n-tls-rs-demo -- client
```

To run the demo application in server mode:

```bash
cd rust
cargo run --bin s2n-tls-rs-demo -- server
```

## License

This library is licensed under the Apache License 2.0.