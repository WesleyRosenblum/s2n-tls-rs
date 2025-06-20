// Handshake demonstration between s2n-tls-rs and s2n-tls
//
// This example demonstrates the TLS handshake process between s2n-tls-rs and s2n-tls.
// It provides a detailed view of the handshake messages exchanged between the two implementations.

use s2n_tls_rs::{init, cleanup, Config, Connection};
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
    println!("Usage: handshake_demo <mode>");
    println!("Modes:");
    println!("  client: Run as a client connecting to an s2n-tls server");
    println!("  server: Run as a server accepting connections from an s2n-tls client");
}

fn run_client() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== S2N-TLS-RS CLIENT HANDSHAKE DEMO ===");
    println!("This demo shows the TLS handshake process between an s2n-tls-rs client and an s2n-tls server.");
    println!("");
    
    // Initialize the library
    println!("Initializing s2n-tls-rs...");
    init()?;
    
    // Create a client configuration
    println!("Creating client configuration...");
    let mut config = Config::new_client();
    config.set_server_name("localhost".to_string())?;
    config.add_cipher_suite(TLS_AES_128_GCM_SHA256)?;
    config.add_named_group(NamedGroup::X25519)?;
    
    // Create a client connection
    println!("Creating client connection...");
    let mut connection = Connection::new(config);
    
    // Initialize the connection
    println!("Initializing connection...");
    connection.initialize()?;
    
    // Connect to the server
    println!("Connecting to localhost:8443...");
    let mut stream = TcpStream::connect("localhost:8443")?;
    println!("Connected to localhost:8443");
    
    // Perform the TLS handshake
    println!("\n=== STARTING TLS HANDSHAKE ===\n");
    
    // Send ClientHello
    println!("Sending ClientHello...");
    
    // Process the output (ClientHello)
    let mut output_buffer = [0; 16384];
    let len = connection.process_output(&mut output_buffer)?;
    println!("Sending {} bytes of ClientHello data to server...", len);
    stream.write_all(&output_buffer[..len])?;
    
    // Receive ServerHello, etc.
    println!("Waiting for server response (ServerHello, Certificate, etc.)...");
    let mut response_buffer = [0; 16384];
    let bytes_read = stream.read(&mut response_buffer)?;
    println!("Received {} bytes from server", bytes_read);
    
    // Process the input
    println!("Processing server response...");
    connection.process_input(&response_buffer[..bytes_read])?;
    
    // Process the output (ClientFinished)
    let mut output_buffer = [0; 16384];
    let len = connection.process_output(&mut output_buffer)?;
    println!("Sending {} bytes of ClientFinished data to server...", len);
    stream.write_all(&output_buffer[..len])?;
    
    // Check if the connection is established
    if connection.status() == s2n_tls_rs::ConnectionStatus::Established {
        println!("\n=== TLS HANDSHAKE COMPLETED SUCCESSFULLY ===\n");
        println!("Connection established with s2n-tls server!");
        
        // Send a simple HTTP request
        println!("Sending HTTP request...");
        let request = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        connection.send(request.as_bytes())?;
        
        // Process the output
        let mut output_buffer = [0; 16384];
        let len = connection.process_output(&mut output_buffer)?;
        stream.write_all(&output_buffer[..len])?;
        
        // Receive the response
        println!("Receiving response...");
        let mut response_buffer = [0; 16384];
        let mut total_bytes = 0;
        
        loop {
            let bytes_read = stream.read(&mut response_buffer)?;
            if bytes_read == 0 {
                break;
            }
            
            connection.process_input(&response_buffer[..bytes_read])?;
            
            let mut decrypted_buffer = [0; 16384];
            let decrypted_bytes = connection.recv(&mut decrypted_buffer)?;
            
            if decrypted_bytes > 0 {
                println!("Received {} bytes of application data:", decrypted_bytes);
                println!("{}", String::from_utf8_lossy(&decrypted_buffer[..decrypted_bytes]));
                total_bytes += decrypted_bytes;
            }
        }
        
        println!("\nTotal application data received: {} bytes", total_bytes);
    } else {
        println!("\n=== TLS HANDSHAKE FAILED ===\n");
        println!("Connection status: {:?}", connection.status());
        println!("Blocked status: {:?}", connection.blocked_status());
    }
    
    // Close the connection
    println!("Closing connection...");
    connection.close()?;
    
    // Clean up
    println!("Cleaning up...");
    cleanup()?;
    
    println!("\n=== DEMO COMPLETED ===\n");
    
    Ok(())
}

fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== S2N-TLS-RS SERVER HANDSHAKE DEMO ===");
    println!("This demo shows the TLS handshake process between an s2n-tls-rs server and an s2n-tls client.");
    println!("");
    
    // Initialize the library
    println!("Initializing s2n-tls-rs...");
    init()?;
    
    // Create a server configuration
    println!("Creating server configuration...");
    let mut config = Config::new_server();
    
    // Set the server certificate and key
    println!("Loading certificate and key...");
    let cert_path = "tests/pems/server.cert.pem";
    let key_path = "tests/pems/server.key.pem";
    
    let mut cert_data = Vec::new();
    let mut key_data = Vec::new();
    
    File::open(cert_path)?.read_to_end(&mut cert_data)?;
    File::open(key_path)?.read_to_end(&mut key_data)?;
    
    config.set_server_certificate(cert_data)?;
    config.set_server_private_key(key_data)?;
    config.add_cipher_suite(TLS_AES_128_GCM_SHA256)?;
    config.add_named_group(NamedGroup::X25519)?;
    
    // Create a TCP listener
    println!("Starting server on port 8444...");
    let listener = TcpListener::bind("0.0.0.0:8444")?;
    println!("Server listening on port 8444");
    
    // Accept a connection
    println!("Waiting for client connection...");
    let (mut stream, peer_addr) = listener.accept()?;
    println!("Accepted connection from {}", peer_addr);
    
    // Create a server connection
    println!("Creating server connection...");
    let mut connection = Connection::new(config);
    
    // Initialize the connection
    println!("Initializing connection...");
    connection.initialize()?;
    
    // Perform the TLS handshake
    println!("\n=== STARTING TLS HANDSHAKE ===\n");
    
    // Receive ClientHello
    println!("Waiting for ClientHello...");
    let mut client_hello_buffer = [0; 16384];
    let bytes_read = stream.read(&mut client_hello_buffer)?;
    println!("Received {} bytes of ClientHello data", bytes_read);
    
    // Process the input
    println!("Processing ClientHello...");
    connection.process_input(&client_hello_buffer[..bytes_read])?;
    
    // Process the output (ServerHello, Certificate, etc.)
    println!("Sending ServerHello, Certificate, etc...");
    let mut output_buffer = [0; 16384];
    let len = connection.process_output(&mut output_buffer)?;
    println!("Sending {} bytes to client...", len);
    stream.write_all(&output_buffer[..len])?;
    
    // Receive ClientFinished
    println!("Waiting for ClientFinished...");
    let mut client_finished_buffer = [0; 16384];
    let bytes_read = stream.read(&mut client_finished_buffer)?;
    println!("Received {} bytes of ClientFinished data", bytes_read);
    
    // Process the input
    println!("Processing ClientFinished...");
    connection.process_input(&client_finished_buffer[..bytes_read])?;
    
    // Check if the connection is established
    if connection.status() == s2n_tls_rs::ConnectionStatus::Established {
        println!("\n=== TLS HANDSHAKE COMPLETED SUCCESSFULLY ===\n");
        println!("Connection established with s2n-tls client!");
        
        // Handle the client request
        println!("Waiting for client request...");
        let mut request_buffer = [0; 16384];
        let mut total_bytes = 0;
        
        loop {
            let bytes_read = match stream.read(&mut request_buffer) {
                Ok(0) => break, // Connection closed
                Ok(n) => n,
                Err(e) => {
                    println!("Error reading from client: {}", e);
                    break;
                }
            };
            
            connection.process_input(&request_buffer[..bytes_read])?;
            
            let mut decrypted_buffer = [0; 16384];
            let decrypted_bytes = connection.recv(&mut decrypted_buffer)?;
            
            if decrypted_bytes > 0 {
                let request = String::from_utf8_lossy(&decrypted_buffer[..decrypted_bytes]);
                println!("Received {} bytes of application data:", decrypted_bytes);
                println!("{}", request);
                total_bytes += decrypted_bytes;
                
                if request.contains("\r\n\r\n") {
                    break;
                }
            }
        }
        
        println!("\nTotal application data received: {} bytes", total_bytes);
        
        // Send a simple HTTP response
        println!("Sending HTTP response...");
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
        println!("Sending {} bytes of application data...", len);
        stream.write_all(&output_buffer[..len])?;
    } else {
        println!("\n=== TLS HANDSHAKE FAILED ===\n");
        println!("Connection status: {:?}", connection.status());
        println!("Blocked status: {:?}", connection.blocked_status());
    }
    
    // Close the connection
    println!("Closing connection...");
    connection.close()?;
    
    // Clean up
    println!("Cleaning up...");
    cleanup()?;
    
    println!("\n=== DEMO COMPLETED ===\n");
    
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        print_usage();
        exit(1);
    }
    
    match args[1].as_str() {
        "client" => run_client(),
        "server" => run_server(),
        _ => {
            println!("Error: unknown mode '{}'", args[1]);
            print_usage();
            exit(1);
        }
    }
}
