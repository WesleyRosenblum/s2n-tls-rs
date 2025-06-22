//! Unit tests for I/O abstractions

use std::io::{self, Read, Write};
use std::os::fd::RawFd;

// Import the IoProvider trait and implementations
// Note: These are pub(crate) in the main code, so we need to use the crate's public API
// to test them indirectly or make them public for testing
use s2n_tls_rs::testing::io::{FdIoProvider, IoProvider, RwIoProvider};

/// A mock Read + Write implementation for testing
struct MockRw {
    read_data: Vec<u8>,
    write_data: Vec<u8>,
    read_error: Option<io::Error>,
    write_error: Option<io::Error>,
}

impl MockRw {
    fn new() -> Self {
        Self {
            read_data: Vec::new(),
            write_data: Vec::new(),
            read_error: None,
            write_error: None,
        }
    }
    
    fn with_read_data(mut self, data: &[u8]) -> Self {
        self.read_data = data.to_vec();
        self
    }
    
    fn with_read_error(mut self, error: io::Error) -> Self {
        self.read_error = Some(error);
        self
    }
    
    fn with_write_error(mut self, error: io::Error) -> Self {
        self.write_error = Some(error);
        self
    }
    
    fn written_data(&self) -> &[u8] {
        &self.write_data
    }
}

impl Read for MockRw {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(error) = &self.read_error {
            return Err(io::Error::new(error.kind(), error.to_string()));
        }
        
        if self.read_data.is_empty() {
            return Ok(0);
        }
        
        let n = std::cmp::min(buf.len(), self.read_data.len());
        buf[..n].copy_from_slice(&self.read_data[..n]);
        self.read_data.drain(..n);
        Ok(n)
    }
}

impl Write for MockRw {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(error) = &self.write_error {
            return Err(io::Error::new(error.kind(), error.to_string()));
        }
        
        self.write_data.extend_from_slice(buf);
        Ok(buf.len())
    }
    
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn test_rw_io_provider_read() {
    let mock = MockRw::new().with_read_data(b"hello world");
    let mut provider = RwIoProvider::new(mock);
    
    let mut buf = [0u8; 5];
    let n = provider.read(&mut buf).unwrap();
    
    assert_eq!(n, 5);
    assert_eq!(&buf, b"hello");
    
    let mut buf = [0u8; 10];
    let n = provider.read(&mut buf).unwrap();
    
    assert_eq!(n, 6);
    assert_eq!(&buf[..n], b" world");
}

#[test]
fn test_rw_io_provider_read_error() {
    let error = io::Error::new(io::ErrorKind::Other, "test error");
    let mock = MockRw::new().with_read_error(error);
    let mut provider = RwIoProvider::new(mock);
    
    let mut buf = [0u8; 5];
    let result = provider.read(&mut buf);
    
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Other);
}

#[test]
fn test_rw_io_provider_write() {
    let mock = MockRw::new();
    let mut provider = RwIoProvider::new(mock);
    
    let n = provider.write(b"hello").unwrap();
    assert_eq!(n, 5);
    
    let n = provider.write(b" world").unwrap();
    assert_eq!(n, 6);
    
    let mock = provider.io;
    assert_eq!(mock.written_data(), b"hello world");
}

#[test]
fn test_rw_io_provider_write_error() {
    let error = io::Error::new(io::ErrorKind::Other, "test error");
    let mock = MockRw::new().with_write_error(error);
    let mut provider = RwIoProvider::new(mock);
    
    let result = provider.write(b"hello");
    
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Other);
}

// Note: Testing FdIoProvider would require actual file descriptors or mocking at a lower level,
// which is beyond the scope of these unit tests. Integration tests would be more appropriate
// for testing FdIoProvider with real file descriptors.
