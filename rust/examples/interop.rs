// TLS interoperability demo application
//
// This application demonstrates interoperability between the Rust and C implementations of s2n-tls.
// It can run in two modes:
// 1. Rust client connecting to a C server
// 2. C client connecting to a Rust server

use s2n_tls_rs::{init, cleanup, Config, Connection, ConnectionMode, BlockedStatus, ConnectionStatus};
use s2n_tls_rs::crypto::cipher_suites::TLS_AES_128_GCM_SHA256;
use s2n_tls_rs::handshake::NamedGroup;
use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio, exit};
use std::thread;
use std::time::Duration;

fn print_usage() {
    println!("Usage: interop <mode> [options]");
    println!("Modes:");
    println!("  rust-client <host> <port>: Run a Rust client connecting to a C server");
    println!("  rust-server <port> <cert_file> <key_file>: Run a Rust server accepting connections from a C client");
    println!("  demo: Run both a C server and a Rust client in the same process");
}

fn run_rust_client(host: &str, port: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Running Rust client connecting to C server at {}:{}...", host, port);
    
    // Initialize the library
    init()?;
    
    // Create a client configuration
    let mut config = Config::new_client();
    config.set_server_name(host.to_string())?;
    config.add_cipher_suite(TLS_AES_128_GCM_SHA256)?;
    config.add_named_group(NamedGroup::X25519)?;
    
    // Create a client connection
    let mut connection = Connection::new(config);
    
    // Initialize the connection
    connection.initialize()?;
    
    // Connect to the server
    println!("Connecting to {}:{}...", host, port);
    let mut stream = TcpStream::connect(format!("{}:{}", host, port))?;
    println!("Connected to {}:{}", host, port);
    
    // Perform the TLS handshake
    println!("Performing TLS handshake...");
    
    // Negotiate the connection
    connection.negotiate()?;
    
    // Check if the connection is established
    if !connection.is_established() {
        println!("Failed to establish TLS connection");
        exit(1);
    }
    
    println!("TLS handshake completed successfully");
    
    // Send a simple HTTP request
    println!("Sending HTTP request...");
    let request = format!("GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", host);
    connection.send(request.as_bytes())?;
    
    // Process the output
    let mut output_buffer = [0; 16384];
    let len = connection.process_output(&mut output_buffer)?;
    
    // Send the data to the server
    stream.write_all(&output_buffer[..len])?;
    
    // Receive the response
    println!("Receiving response...");
    let mut response_buffer = [0; 16384];
    let mut total_bytes = 0;
    
    loop {
        // Read data from the server
        let bytes_read = stream.read(&mut response_buffer)?;
        if bytes_read == 0 {
            break;
        }
        
        // Process the input
        connection.process_input(&response_buffer[..bytes_read])?;
        
        // Receive the decrypted data
        let mut decrypted_buffer = [0; 16384];
        let decrypted_bytes = connection.recv(&mut decrypted_buffer)?;
        
        // Print the response
        if decrypted_bytes > 0 {
            print!("{}", String::from_utf8_lossy(&decrypted_buffer[..decrypted_bytes]));
            total_bytes += decrypted_bytes;
        }
    }
    
    println!("\nReceived {} bytes", total_bytes);
    
    // Close the connection
    connection.close()?;
    
    // Clean up
    cleanup()?;
    
    println!("Rust client completed successfully");
    
    Ok(())
}

fn handle_client(stream: TcpStream, cert_data: Vec<u8>, key_data: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
    let peer_addr = stream.peer_addr()?;
    println!("Accepted connection from {}", peer_addr);
    
    // Create a server configuration
    let mut config = Config::new_server();
    config.set_server_certificate(cert_data)?;
    config.set_server_private_key(key_data)?;
    config.add_cipher_suite(TLS_AES_128_GCM_SHA256)?;
    config.add_named_group(NamedGroup::X25519)?;
    
    // Create a server connection
    let mut connection = Connection::new(config);
    
    // Initialize the connection
    connection.initialize()?;
    
    // Perform the TLS handshake
    println!("Performing TLS handshake with {}...", peer_addr);
    
    // Negotiate the connection
    connection.negotiate()?;
    
    // Check if the connection is established
    if !connection.is_established() {
        println!("Failed to establish TLS connection with {}", peer_addr);
        return Ok(());
    }
    
    println!("TLS handshake with {} completed successfully", peer_addr);
    
    // Handle the client request
    let mut stream = stream;
    let mut request_buffer = [0; 16384];
    let mut total_bytes = 0;
    
    loop {
        // Read data from the client
        let bytes_read = match stream.read(&mut request_buffer) {
            Ok(0) => break, // Connection closed
            Ok(n) => n,
            Err(e) => {
                println!("Error reading from client: {}", e);
                break;
            }
        };
        
        // Process the input
        connection.process_input(&request_buffer[..bytes_read])?;
        
        // Receive the decrypted data
        let mut decrypted_buffer = [0; 16384];
        let decrypted_bytes = connection.recv(&mut decrypted_buffer)?;
        
        // Process the request
        if decrypted_bytes > 0 {
            let request = String::from_utf8_lossy(&decrypted_buffer[..decrypted_bytes]);
            println!("Received request from {}:\n{}", peer_addr, request);
            total_bytes += decrypted_bytes;
            
            // Check if we've received the end of the request
            if request.contains("\r\n\r\n") {
                break;
            }
        }
    }
    
    println!("Received {} bytes from {}", total_bytes, peer_addr);
    
    // Send a simple HTTP response
    let response = "HTTP/1.1 200 OK\r\n\
                    Content-Type: text/plain\r\n\
                    Connection: close\r\n\
                    Content-Length: 13\r\n\
                    \r\n\
                    Hello, world!";
    
    connection.send(response.as_bytes())?;
    
    // Process the output
    let mut output_buffer = [0; 16384];
    let len = connection.process_output(&mut output_buffer)?;
    
    // Send the data to the client
    stream.write_all(&output_buffer[..len])?;
    
    // Close the connection
    connection.close()?;
    
    println!("Connection with {} closed", peer_addr);
    
    Ok(())
}

fn run_rust_server(port: &str, cert_file: &str, key_file: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Running Rust server accepting connections from C client on port {}...", port);
    
    // Initialize the library
    init()?;
    
    // Read the certificate and key files
    let mut cert_data = Vec::new();
    let mut key_data = Vec::new();
    
    File::open(cert_file)?.read_to_end(&mut cert_data)?;
    File::open(key_file)?.read_to_end(&mut key_data)?;
    
    // Create a TCP listener
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port))?;
    println!("Server listening on port {}", port);
    
    // Accept connections
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                // Clone the certificate and key data for the new thread
                let cert_data_clone = cert_data.clone();
                let key_data_clone = key_data.clone();
                
                // Spawn a new thread to handle the client
                thread::spawn(move || {
                    if let Err(e) = handle_client(stream, cert_data_clone, key_data_clone) {
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
    cleanup()?;
    
    Ok(())
}

fn run_c_server(port: &str, cert_file: &str, key_file: &str) -> Result<std::process::Child, Box<dyn std::error::Error>> {
    println!("Starting C server on port {}...", port);
    
    // Start the s2nd server
    let server = Command::new("s2nd")
        .arg("--cert")
        .arg(cert_file)
        .arg("--key")
        .arg(key_file)
        .arg("--port")
        .arg(port)
        .arg("localhost")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    
    // Wait for the server to start
    thread::sleep(Duration::from_millis(100));
    
    println!("C server started on port {}", port);
    
    Ok(server)
}

fn run_c_client(host: &str, port: &str) -> Result<std::process::Child, Box<dyn std::error::Error>> {
    println!("Starting C client connecting to {}:{}...", host, port);
    
    // Start the s2nc client
    let client = Command::new("s2nc")
        .arg("--port")
        .arg(port)
        .arg(host)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    
    println!("C client started");
    
    Ok(client)
}

fn run_demo() -> Result<(), Box<dyn std::error::Error>> {
    println!("Running interoperability demo...");
    
    // Check if s2n-tls C implementation is available
    let s2n_available = Command::new("which")
        .arg("s2nd")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);
    
    if !s2n_available {
        println!("s2n-tls C implementation not found. Please install it and make sure s2nd and s2nc are in your PATH.");
        exit(1);
    }
    
    // Start the C server
    let port = "8443";
    let cert_file = "tests/pems/rsa_2048_sha256_wildcard_cert.pem";
    let key_file = "tests/pems/rsa_2048_sha256_wildcard_key.pem";
    
    let mut server = run_c_server(port, cert_file, key_file)?;
    
    // Run the Rust client
    run_rust_client("localhost", port)?;
    
    // Stop the C server
    server.kill()?;
    
    // Start the Rust server
    let port = "8444";
    let rust_server_thread = thread::spawn(move || {
        if let Err(e) = run_rust_server(port, cert_file, key_file) {
            eprintln!("Error running Rust server: {}", e);
        }
    });
    
    // Wait for the server to start
    thread::sleep(Duration::from_millis(100));
    
    // Run the C client
    let mut client = run_c_client("localhost", port)?;
    
    // Wait for the client to finish
    let status = client.wait()?;
    println!("C client exited with status: {}", status);
    
    // We can't actually join the rust_server_thread because it runs indefinitely
    // In a real application, we would have a way to signal the server to shut down
    
    println!("Interoperability demo completed successfully");
    
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        exit(1);
    }
    
    match args[1].as_str() {
        "rust-client" => {
            if args.len() != 4 {
                println!("Error: rust-client mode requires host and port arguments");
                print_usage();
                exit(1);
            }
            run_rust_client(&args[2], &args[3])
        }
        "rust-server" => {
            if args.len() != 5 {
                println!("Error: rust-server mode requires port, cert_file, and key_file arguments");
                print_usage();
                exit(1);
            }
            run_rust_server(&args[2], &args[3], &args[4])
        }
        "demo" => {
            run_demo()
        }
        _ => {
            println!("Error: unknown mode '{}'", args[1]);
            print_usage();
            exit(1);
        }
    }
}
