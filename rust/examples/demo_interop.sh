#!/bin/bash
# Demo script to show s2n-tls-rs handshaking successfully with s2n-tls

# Exit on error, but allow the script to handle server process termination
set -e

echo "=== S2N-TLS-RS INTEROPERABILITY DEMO ==="
echo "This script demonstrates s2n-tls-rs handshaking with s2n-tls in both directions."
echo ""

# Check if s2n-tls is installed
if ! command -v s2nd &> /dev/null; then
    echo "Error: s2nd command not found. Please install s2n-tls first."
    exit 1
fi

if ! command -v s2nc &> /dev/null; then
    echo "Error: s2nc command not found. Please install s2n-tls first."
    exit 1
fi

# Check if openssl is installed
if ! command -v openssl &> /dev/null; then
    echo "Error: openssl command not found. Please install openssl first."
    exit 1
fi

# Create temporary certificate and key if they don't exist
CERT_DIR="./tests/pems"
mkdir -p "$CERT_DIR"

if [ ! -f "$CERT_DIR/server.cert.pem" ] || [ ! -f "$CERT_DIR/server.key.pem" ]; then
    echo "Generating temporary certificate and key..."
    openssl req -x509 -newkey rsa:2048 -keyout "$CERT_DIR/server.key.pem" -out "$CERT_DIR/server.cert.pem" -days 365 -nodes -subj "/CN=localhost"
    
    # Verify the certificate and key were created
    if [ ! -f "$CERT_DIR/server.cert.pem" ] || [ ! -f "$CERT_DIR/server.key.pem" ]; then
        echo "Error: Failed to create certificate and key files."
        exit 1
    fi
    
    echo "Certificate and key generated successfully."
    echo "Certificate path: $CERT_DIR/server.cert.pem"
    echo "Key path: $CERT_DIR/server.key.pem"
fi

# Build the Rust examples
echo "Building Rust examples..."
cargo build --examples

# Check if the build was successful
if [ ! -f "./target/debug/examples/client" ] || [ ! -f "./target/debug/examples/server" ]; then
    echo "Error: Failed to build Rust examples."
    echo "Please check your Rust installation and try again."
    exit 1
fi

echo "Rust examples built successfully."

# Define ports
RUST_CLIENT_PORT=8443
RUST_SERVER_PORT=8444

echo -e "\n\n========== RUST CLIENT -> S2N-TLS SERVER ==========\n"

# Start s2n-tls server in the background with more verbose output
echo "Starting s2n-tls server on port $RUST_CLIENT_PORT..."
s2nd --cert "$CERT_DIR/server.cert.pem" --key "$CERT_DIR/server.key.pem" --port $RUST_CLIENT_PORT localhost &
S2ND_PID=$!

# Wait for the server to start
sleep 2
echo "s2n-tls server started with PID $S2ND_PID"

# Run Rust client to connect to s2n-tls server
echo "Running Rust client connecting to s2n-tls server..."
./target/debug/examples/client localhost $RUST_CLIENT_PORT || {
    echo "Error: Rust client failed to connect to s2n-tls server."
    kill $S2ND_PID 2>/dev/null || true
    exit 1
}

# Kill the s2n-tls server
echo "Stopping s2n-tls server..."
kill $S2ND_PID 2>/dev/null || true
wait $S2ND_PID 2>/dev/null || true
echo "s2n-tls server stopped."

echo -e "\n\n========== S2N-TLS CLIENT -> RUST SERVER ==========\n"

# Start Rust server in the background
echo "Starting Rust server on port $RUST_SERVER_PORT..."
./target/debug/examples/server $RUST_SERVER_PORT "$CERT_DIR/server.cert.pem" "$CERT_DIR/server.key.pem" &
RUST_SERVER_PID=$!

# Wait for the server to start
sleep 2
echo "Rust server started with PID $RUST_SERVER_PID"

# Run s2n-tls client to connect to Rust server
echo "Running s2n-tls client connecting to Rust server..."
echo -e "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" | s2nc --port $RUST_SERVER_PORT localhost || {
    echo "Error: s2n-tls client failed to connect to Rust server."
    kill $RUST_SERVER_PID 2>/dev/null || true
    exit 1
}

# Kill the Rust server
echo "Stopping Rust server..."
kill $RUST_SERVER_PID 2>/dev/null || true
wait $RUST_SERVER_PID 2>/dev/null || true
echo "Rust server stopped."

echo -e "\n\n========== INTEROPERABILITY DEMO COMPLETE ==========\n"
echo "Successfully demonstrated s2n-tls-rs handshaking with s2n-tls in both directions!"
