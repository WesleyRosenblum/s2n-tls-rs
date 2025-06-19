//! I/O abstractions for the s2n-tls-rs library
//!
//! This module provides I/O abstractions for the s2n-tls-rs library.
//! It includes the IoProvider trait and implementations for file descriptors
//! and Rust's Read + Write traits.

use std::io::{Read, Write};
use std::os::fd::RawFd;

/// I/O provider trait
pub(crate) trait IoProvider {
    /// Read data from the underlying I/O source
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
    
    /// Write data to the underlying I/O sink
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize>;
}

/// I/O provider for file descriptors
pub(crate) struct FdIoProvider {
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
        // Implementation will use libc::read
        // This is a placeholder for now
        Ok(0)
    }
    
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Implementation will use libc::write
        // This is a placeholder for now
        Ok(0)
    }
}

/// I/O provider for Rust's Read + Write traits
pub(crate) struct RwIoProvider<T: Read + Write> {
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