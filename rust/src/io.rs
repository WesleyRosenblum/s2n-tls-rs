//! I/O abstractions for the s2n-tls-rs library
//!
//! This module provides I/O abstractions for the s2n-tls-rs library.
//! It includes the IoProvider trait and implementations for file descriptors
//! and Rust's Read + Write traits.

use std::io::{self, Read, Write};
use std::os::fd::RawFd;
use libc;

/// I/O provider trait
pub trait IoProvider {
    /// Read data from the underlying I/O source
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
    
    /// Write data to the underlying I/O sink
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize>;
}

/// I/O provider for file descriptors
pub struct FdIoProvider {
    fd: RawFd,
}

impl FdIoProvider {
    /// Create a new FdIoProvider
    pub fn new(fd: RawFd) -> Self {
        Self { fd }
    }
}

impl IoProvider for FdIoProvider {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // Safety: We're calling libc::read with a valid file descriptor and buffer
        let result = unsafe {
            libc::read(
                self.fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len() as libc::size_t,
            )
        };
        
        if result < 0 {
            // If read returns a negative value, it indicates an error
            Err(io::Error::last_os_error())
        } else {
            // Otherwise, it returns the number of bytes read
            Ok(result as usize)
        }
    }
    
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Safety: We're calling libc::write with a valid file descriptor and buffer
        let result = unsafe {
            libc::write(
                self.fd,
                buf.as_ptr() as *const libc::c_void,
                buf.len() as libc::size_t,
            )
        };
        
        if result < 0 {
            // If write returns a negative value, it indicates an error
            Err(io::Error::last_os_error())
        } else {
            // Otherwise, it returns the number of bytes written
            Ok(result as usize)
        }
    }
}

/// I/O provider for Rust's Read + Write traits
pub struct RwIoProvider<T: Read + Write> {
    io: T,
}

impl<T: Read + Write> RwIoProvider<T> {
    /// Create a new RwIoProvider
    pub fn new(io: T) -> Self {
        Self { io }
    }
}

impl<T: Read + Write> IoProvider for RwIoProvider<T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.io.read(buf)
    }
    
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.io.write(buf)
    }
}
