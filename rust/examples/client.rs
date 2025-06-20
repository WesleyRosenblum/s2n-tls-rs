// TLS client demo application
//
// This is a simple TLS client application that demonstrates how to use the s2n-tls-rs library.

use s2n_tls_rs::{init, cleanup, Config, Connection, ConnectionMode, BlockedStatus, ConnectionStatus};
use s2n_tls_rs::crypto::cipher_suites::TLS_AES_128_GCM_SHA256;
use s2n_tls_rs::handshake::NamedGroup;
use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::exit;

fn print_usage() {
    println!("Usage: client <host> <port>");
    println!("  <host>: The hostname or IP address to connect to");
    println!("  <port>: The port to connect to");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        print_usage();
        exit(1);
    }
    
    let host = &args[1];
    let port = &args[2];
    
    // Initialize the library
    init()?;
    
    // Create a client configuration
    let mut config = Config::new_client();
    config.set_server_name(host.clone())?;
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
    
    Ok(())
}
