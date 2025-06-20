#!/bin/bash
# Script to run the handshake demo between s2n-tls-rs and s2n-tls

set -e

echo "=== S2N-TLS-RS HANDSHAKE DEMO ==="
echo "This script demonstrates the TLS handshake between s2n-tls-rs and s2n-tls."
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

# Build the handshake demo
echo "Building handshake demo..."
cargo build --example handshake_demo

# Check if the build was successful
if [ ! -f "./target/debug/examples/handshake_demo" ]; then
    echo "Error: Failed to build handshake demo."
    echo "Please check your Rust installation and try again."
    exit 1
fi

echo "Handshake demo built successfully."

# Define ports
S2N_SERVER_PORT=8443
S2N_CLIENT_PORT=8444

echo -e "\n\n========== DEMO 1: S2N-TLS-RS CLIENT -> S2N-TLS SERVER ==========\n"

# Start s2n-tls server in the background
echo "Starting s2n-tls server on port $S2N_SERVER_PORT..."
s2nd --cert "$CERT_DIR/server.cert.pem" --key "$CERT_DIR/server.key.pem" --port $S2N_SERVER_PORT localhost &
S2ND_PID=$!

# Wait for the server to start
sleep 2
echo "s2n-tls server started with PID $S2ND_PID"

# Run s2n-tls-rs client
echo "Running s2n-tls-rs client connecting to s2n-tls server..."
./target/debug/examples/handshake_demo client || {
    echo "Error: s2n-tls-rs client failed to connect to s2n-tls server."
    kill $S2ND_PID 2>/dev/null || true
    exit 1
}

# Kill the s2n-tls server
echo "Stopping s2n-tls server..."
kill $S2ND_PID 2>/dev/null || true
wait $S2ND_PID 2>/dev/null || true
echo "s2n-tls server stopped."

echo -e "\n\n========== DEMO 2: S2N-TLS CLIENT -> S2N-TLS-RS SERVER ==========\n"

# Start s2n-tls-rs server in the background
echo "Starting s2n-tls-rs server on port $S2N_CLIENT_PORT..."
./target/debug/examples/handshake_demo server &
RUST_SERVER_PID=$!

# Wait for the server to start
sleep 2
echo "s2n-tls-rs server started with PID $RUST_SERVER_PID"

# Run s2n-tls client
echo "Running s2n-tls client connecting to s2n-tls-rs server..."
echo -e "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" | s2nc --port $S2N_CLIENT_PORT localhost || {
    echo "Error: s2n-tls client failed to connect to s2n-tls-rs server."
    kill $RUST_SERVER_PID 2>/dev/null || true
    exit 1
}

# Kill the s2n-tls-rs server
echo "Stopping s2n-tls-rs server..."
kill $RUST_SERVER_PID 2>/dev/null || true
wait $RUST_SERVER_PID 2>/dev/null || true
echo "s2n-tls-rs server stopped."

echo -e "\n\n========== HANDSHAKE DEMO COMPLETE ==========\n"
echo "Successfully demonstrated TLS handshake between s2n-tls-rs and s2n-tls in both directions!"
