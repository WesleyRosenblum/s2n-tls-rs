//! Demo application for the s2n-tls-rs library
//!
//! This is a simple demo application that shows how to use the s2n-tls-rs library.
//! It can be run in either client or server mode.

use std::env;
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::Arc;

use s2n_tls_rs::{init, Config, Connection, BlockedStatus};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the library
    init()?;
    
    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} [client|server] [options]", args[0]);
        return Ok(());
    }
    
    match args[1].as_str() {
        "client" => run_client(&args[2..])?,
        "server" => run_server(&args[2..])?,
        _ => {
            println!("Unknown mode: {}", args[1]);
            println!("Usage: {} [client|server] [options]", args[0]);
        }
    }
    
    Ok(())
}

fn run_client(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting TLS client...");
    
    // Create a TLS client connection
    let mut config = Config::new_client();
    // Configure the client
    
    let mut conn = Connection::new(config);
    conn.initialize()?;
    
    // Connect to the server
    let server_addr = "127.0.0.1:8443";
    println!("Connecting to {}...", server_addr);
    let socket = TcpStream::connect(server_addr)?;
    // Note: In the current API, we don't have direct fd support
    // This would need to be implemented using process_input/process_output
    
    // Perform the TLS handshake
    println!("Performing TLS handshake...");
    let mut blocked = BlockedStatus::NotBlocked;
    while let Err(e) = conn.negotiate() {
        // Handle blocking I/O
        // This is a placeholder for now
        println!("Handshake error: {}", e);
        return Err(e.into());
    }
    
    // Send and receive data
    println!("Sending data...");
    conn.send(b"Hello, server!")?;
    
    let mut buf = [0u8; 1024];
    let n = conn.recv(&mut buf)?;
    println!("Received: {}", std::str::from_utf8(&buf[..n])?);
    
    // Close the connection
    println!("Closing connection...");
    conn.close()?;
    
    println!("Client finished.");
    Ok(())
}

fn run_server(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting TLS server...");
    
    // Create a TLS server connection
    let mut config = Config::new_server();
    // Configure the server
    
    // Listen for connections
    let addr = "127.0.0.1:8443";
    println!("Listening on {}...", addr);
    let listener = TcpListener::bind(addr)?;
    
    for stream in listener.incoming() {
        let stream = stream?;
        println!("Connection from {}", stream.peer_addr()?);
        
        let mut conn = Connection::new(config.clone());
        conn.initialize()?;
        // Note: In the current API, we don't have direct fd support
        // This would need to be implemented using process_input/process_output
        
        // Perform the TLS handshake
        println!("Performing TLS handshake...");
        let mut blocked = BlockedStatus::NotBlocked;
        while let Err(e) = conn.negotiate() {
            // Handle blocking I/O
            // This is a placeholder for now
            println!("Handshake error: {}", e);
            break;
        }
        
        // Send and receive data
        let mut buf = [0u8; 1024];
        let n = conn.recv(&mut buf)?;
        println!("Received: {}", std::str::from_utf8(&buf[..n])?);
        
        println!("Sending data...");
        conn.send(b"Hello, client!")?;
        
        // Close the connection
        println!("Closing connection...");
        conn.close()?;
    }
    
    println!("Server finished.");
    Ok(())
}
