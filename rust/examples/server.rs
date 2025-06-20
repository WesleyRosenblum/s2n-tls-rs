// TLS server demo application
//
// This is a simple TLS server application that demonstrates how to use the s2n-tls-rs library.

use s2n_tls_rs::{init, cleanup, Config, Connection, ConnectionMode, BlockedStatus, ConnectionStatus};
use s2n_tls_rs::crypto::cipher_suites::TLS_AES_128_GCM_SHA256;
use s2n_tls_rs::handshake::NamedGroup;
use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::exit;
use std::thread;

fn print_usage() {
    println!("Usage: server <port> <cert_file> <key_file>");
    println!("  <port>: The port to listen on");
    println!("  <cert_file>: The path to the certificate file");
    println!("  <key_file>: The path to the private key file");
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        print_usage();
        exit(1);
    }
    
    let port = &args[1];
    let cert_file = &args[2];
    let key_file = &args[3];
    
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
