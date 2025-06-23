//! Demo application for the s2n-tls-rs library
//!
//! This is a simple demo application that shows how to use the s2n-tls-rs library.
//! It can be run in either client or server mode.

use std::env;
use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write};
use std::thread;
use std::time::Duration;

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
    // Add default cipher suites and named groups
    // The library will use default cipher suites and named groups internally
    
    let mut conn = Connection::new(config);
    conn.initialize()?;
    
    // Connect to the server
    let server_addr = "127.0.0.1:8443";
    println!("Connecting to {}...", server_addr);
    let mut socket = TcpStream::connect(server_addr)?;
    socket.set_nonblocking(true)?;
    
    // Perform the TLS handshake
    println!("Performing TLS handshake...");
    let mut handshake_complete = false;
    let mut io_buffer = [0u8; 16384];
    
    while !handshake_complete {
        match conn.negotiate() {
            Ok(()) => {
                if conn.is_established() {
                    handshake_complete = true;
                    println!("Handshake completed successfully");
                } else {
                    // Handle blocked I/O
                    if conn.is_read_blocked() {
                        // Read from socket
                        match socket.read(&mut io_buffer) {
                            Ok(n) if n > 0 => {
                                conn.process_input(&io_buffer[..n])?;
                            },
                            Ok(_) => {
                                // No data available, try again
                                thread::sleep(Duration::from_millis(10));
                            },
                            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                // No data available, try again
                                thread::sleep(Duration::from_millis(10));
                            },
                            Err(e) => return Err(e.into()),
                        }
                    } else if conn.is_write_blocked() {
                        // Write to socket
                        let n = conn.process_output(&mut io_buffer)?;
                        if n > 0 {
                            socket.write_all(&io_buffer[..n])?;
                        }
                    }
                }
            },
            Err(e) => {
                if e.is_blocked() {
                    // Handle blocked I/O
                    if conn.is_read_blocked() {
                        // Read from socket
                        match socket.read(&mut io_buffer) {
                            Ok(n) if n > 0 => {
                                conn.process_input(&io_buffer[..n])?;
                            },
                            Ok(_) => {
                                // No data available, try again
                                thread::sleep(Duration::from_millis(10));
                            },
                            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                // No data available, try again
                                thread::sleep(Duration::from_millis(10));
                            },
                            Err(e) => return Err(e.into()),
                        }
                    } else if conn.is_write_blocked() {
                        // Write to socket
                        let n = conn.process_output(&mut io_buffer)?;
                        if n > 0 {
                            socket.write_all(&io_buffer[..n])?;
                        }
                    }
                } else {
                    // Real error
                    println!("Handshake error: {}", e);
                    return Err(e.into());
                }
            }
        }
        
        // Check if the connection is established
        if conn.is_established() {
            handshake_complete = true;
            println!("Handshake completed successfully");
        }
    }
    
    // Send data
    println!("Sending data...");
    conn.send(b"Hello, server!")?;
    
    // Process output to send data
    let n = conn.process_output(&mut io_buffer)?;
    if n > 0 {
        socket.write_all(&io_buffer[..n])?;
    }
    
    // Receive data
    let mut received_data = false;
    while !received_data {
        // Read from socket
        match socket.read(&mut io_buffer) {
            Ok(n) if n > 0 => {
                // Process input
                conn.process_input(&io_buffer[..n])?;
                
                // Try to receive decrypted data
                let mut buf = [0u8; 1024];
                match conn.recv(&mut buf) {
                    Ok(n) if n > 0 => {
                        println!("Received: {}", std::str::from_utf8(&buf[..n])?);
                        received_data = true;
                    },
                    Ok(_) => {
                        // No data available yet
                        thread::sleep(Duration::from_millis(10));
                    },
                    Err(e) => {
                        if !e.is_blocked() {
                            return Err(e.into());
                        }
                        // Blocked, try again
                        thread::sleep(Duration::from_millis(10));
                    }
                }
            },
            Ok(_) => {
                // No data available, try again
                thread::sleep(Duration::from_millis(10));
            },
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No data available, try again
                thread::sleep(Duration::from_millis(10));
            },
            Err(e) => return Err(e.into()),
        }
    }
    
    // Close the connection
    println!("Closing connection...");
    conn.close()?;
    
    // Process output to send close notify
    let n = conn.process_output(&mut io_buffer)?;
    if n > 0 {
        socket.write_all(&io_buffer[..n])?;
    }
    
    println!("Client finished.");
    Ok(())
}

fn run_server(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting TLS server...");
    
    // Create a TLS server connection
    let mut config = Config::new_server();
    // Add default cipher suites and named groups
    // The library will use default cipher suites and named groups internally
    
    // Listen for connections
    let addr = "127.0.0.1:8443";
    println!("Listening on {}...", addr);
    let listener = TcpListener::bind(addr)?;
    
    for stream in listener.incoming() {
        let mut stream = stream?;
        println!("Connection from {}", stream.peer_addr()?);
        stream.set_nonblocking(true)?;
        
        let mut conn = Connection::new(config.clone());
        conn.initialize()?;
        
        // Perform the TLS handshake
        println!("Performing TLS handshake...");
        let mut handshake_complete = false;
        let mut io_buffer = [0u8; 16384];
        
        while !handshake_complete {
            match conn.negotiate() {
                Ok(()) => {
                    if conn.is_established() {
                        handshake_complete = true;
                        println!("Handshake completed successfully");
                    } else {
                        // Handle blocked I/O
                        if conn.is_read_blocked() {
                            // Read from socket
                            match stream.read(&mut io_buffer) {
                                Ok(n) if n > 0 => {
                                    conn.process_input(&io_buffer[..n])?;
                                },
                                Ok(_) => {
                                    // No data available, try again
                                    thread::sleep(Duration::from_millis(10));
                                },
                                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                    // No data available, try again
                                    thread::sleep(Duration::from_millis(10));
                                },
                                Err(e) => {
                                    println!("Read error: {}", e);
                                    break;
                                },
                            }
                        } else if conn.is_write_blocked() {
                            // Write to socket
                            let n = conn.process_output(&mut io_buffer)?;
                            if n > 0 {
                                match stream.write_all(&io_buffer[..n]) {
                                    Ok(_) => {},
                                    Err(e) => {
                                        println!("Write error: {}", e);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                },
                Err(e) => {
                    if e.is_blocked() {
                        // Handle blocked I/O
                        if conn.is_read_blocked() {
                            // Read from socket
                            match stream.read(&mut io_buffer) {
                                Ok(n) if n > 0 => {
                                    conn.process_input(&io_buffer[..n])?;
                                },
                                Ok(_) => {
                                    // No data available, try again
                                    thread::sleep(Duration::from_millis(10));
                                },
                                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                    // No data available, try again
                                    thread::sleep(Duration::from_millis(10));
                                },
                                Err(e) => {
                                    println!("Read error: {}", e);
                                    break;
                                },
                            }
                        } else if conn.is_write_blocked() {
                            // Write to socket
                            let n = conn.process_output(&mut io_buffer)?;
                            if n > 0 {
                                match stream.write_all(&io_buffer[..n]) {
                                    Ok(_) => {},
                                    Err(e) => {
                                        println!("Write error: {}", e);
                                        break;
                                    }
                                }
                            }
                        }
                    } else {
                        // Real error
                        println!("Handshake error: {}", e);
                        break;
                    }
                }
            }
            
            // Check if the connection is established
            if conn.is_established() {
                handshake_complete = true;
                println!("Handshake completed successfully");
            }
        }
        
        if !handshake_complete {
            println!("Handshake failed, closing connection");
            continue;
        }
        
        // Receive data
        let mut received_data = false;
        while !received_data {
            // Read from socket
            match stream.read(&mut io_buffer) {
                Ok(n) if n > 0 => {
                    // Process input
                    conn.process_input(&io_buffer[..n])?;
                    
                    // Try to receive decrypted data
                    let mut buf = [0u8; 1024];
                    match conn.recv(&mut buf) {
                        Ok(n) if n > 0 => {
                            println!("Received: {}", std::str::from_utf8(&buf[..n])?);
                            received_data = true;
                        },
                        Ok(_) => {
                            // No data available yet
                            thread::sleep(Duration::from_millis(10));
                        },
                        Err(e) => {
                            if !e.is_blocked() {
                                println!("Receive error: {}", e);
                                break;
                            }
                            // Blocked, try again
                            thread::sleep(Duration::from_millis(10));
                        }
                    }
                },
                Ok(_) => {
                    // No data available, try again
                    thread::sleep(Duration::from_millis(10));
                },
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No data available, try again
                    thread::sleep(Duration::from_millis(10));
                },
                Err(e) => {
                    println!("Read error: {}", e);
                    break;
                },
            }
        }
        
        // Send data
        println!("Sending data...");
        conn.send(b"Hello, client!")?;
        
        // Process output to send data
        let n = conn.process_output(&mut io_buffer)?;
        if n > 0 {
            match stream.write_all(&io_buffer[..n]) {
                Ok(_) => {},
                Err(e) => {
                    println!("Write error: {}", e);
                    continue;
                }
            }
        }
        
        // Close the connection
        println!("Closing connection...");
        conn.close()?;
        
        // Process output to send close notify
        let n = conn.process_output(&mut io_buffer)?;
        if n > 0 {
            match stream.write_all(&io_buffer[..n]) {
                Ok(_) => {},
                Err(e) => {
                    println!("Write error: {}", e);
                }
            }
        }
    }
    
    println!("Server finished.");
    Ok(())
}
