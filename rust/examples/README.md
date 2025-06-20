# s2n-tls-rs Examples

This directory contains example applications demonstrating how to use the s2n-tls-rs library.

## Client Example

The `client.rs` example demonstrates how to create a TLS client that connects to a server, performs a TLS handshake, and sends/receives data.

To run the client example:

```bash
cargo run --example client -- <host> <port>
```

For example:

```bash
cargo run --example client -- localhost 443
```

## Server Example

The `server.rs` example demonstrates how to create a TLS server that accepts connections from clients, performs a TLS handshake, and sends/receives data.

To run the server example:

```bash
cargo run --example server -- <port> <cert_file> <key_file>
```

For example:

```bash
cargo run --example server -- 8443 tests/pems/server.cert.pem tests/pems/server.key.pem
```

## Interoperability Example

The `interop.rs` example demonstrates interoperability between the Rust and C implementations of s2n-tls. It can run in three modes:

1. Rust client connecting to a C server
2. C client connecting to a Rust server
3. Demo mode that runs both scenarios

To run the interoperability example:

```bash
# Run a Rust client connecting to a C server
cargo run --example interop -- rust-client <host> <port>

# Run a Rust server accepting connections from a C client
cargo run --example interop -- rust-server <port> <cert_file> <key_file>

# Run the demo mode
cargo run --example interop -- demo
```

## Interoperability Demo Script

The `demo_interop.sh` script provides an easy way to demonstrate the interoperability between s2n-tls-rs and s2n-tls. It:

1. Starts an s2n-tls server and connects to it with a Rust client
2. Starts a Rust server and connects to it with an s2n-tls client

To run the demo script:

```bash
chmod +x examples/demo_interop.sh
./examples/demo_interop.sh
```

### Expected Output

When running the interoperability demo script, you should see output similar to the following:

```
Building Rust examples...
Starting s2n-tls server on port 8443...


========== RUST CLIENT -> S2N-TLS SERVER ==========

Running Rust client connecting to s2n-tls server...
Connecting to localhost:8443...
Connected to localhost:8443
Performing TLS handshake...
TLS handshake completed successfully
Sending HTTP request...
Receiving response...
HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 13

Hello, world!

Received 77 bytes
s2n-tls server stopped.


========== S2N-TLS CLIENT -> RUST SERVER ==========

Starting Rust server on port 8444...
Running s2n-tls client connecting to Rust server...
Server listening on port 8444
Accepted connection from 127.0.0.1:12345
Performing TLS handshake with 127.0.0.1:12345...
TLS handshake with 127.0.0.1:12345 completed successfully
Received request from 127.0.0.1:12345:
GET / HTTP/1.1
Host: localhost
Connection: close

Received 61 bytes from 127.0.0.1:12345
Connection with 127.0.0.1:12345 closed
HTTP/1.1 200 OK
Content-Type: text/plain
Connection: close
Content-Length: 13

Hello, world!
Rust server stopped.


========== INTEROPERABILITY DEMO COMPLETE ==========

Successfully demonstrated s2n-tls-rs handshaking with s2n-tls in both directions!
```

This demonstrates that the s2n-tls-rs implementation can successfully handshake with the s2n-tls C implementation in both directions:
1. As a client connecting to an s2n-tls server
2. As a server accepting connections from an s2n-tls client

## Requirements

To run these examples, you need:

1. Rust and Cargo installed
2. s2n-tls C implementation installed (for the interoperability examples)
3. OpenSSL installed (for certificate generation)

For the interoperability examples, make sure the `s2nc` and `s2nd` commands are available in your PATH.
