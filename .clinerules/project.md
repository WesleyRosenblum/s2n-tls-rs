# Memory Bank for s2n-tls-rs Implementation

This document serves as a quick reference for key requirements and design principles that should be considered when implementing each task in the s2n-tls-rs project.

## Core Principles

1. **Security First**: Security is the top priority, followed by readability, ease of use, and performance.
2. **Memory Safety**: Leverage Rust's safety guarantees to prevent memory-related vulnerabilities.
3. **Interoperability**: Maintain wire-format compatibility with s2n-tls C implementation.
4. **Performance**: Achieve performance comparable to the C implementation.
5. **Idiomatic Rust**: Follow Rust idioms and best practices.

## Key Requirements

### Code Quality Requirements

1. **No Unsafe Code**: Avoid `unsafe` code whenever possible.
2. **No Panics**: Avoid `panic!`, `unwrap()`, or `expect()` in production code; use `Result` with proper error types.
3. **Visibility Control**: Use minimum necessary visibility modifiers, preferring `pub(crate)` for internal API.
4. **Type Conversion**: Implement `From` and `TryFrom` traits where appropriate.
5. **Function Size**: Functions should not exceed 90 lines of code.
6. **Error Handling**: Use the `thiserror` crate for defining error types.
7. **Immutability**: Variables should only be mutable when absolutely necessary.
8. **Single Responsibility**: Functions should be responsible for a small, single unit of work.

### Technical Requirements

1. **TLS Protocol**: Comply with RFC 8446 (TLS 1.3) specifications.
2. **Cryptography**: Use aws-lc-rs as the cryptographic library.
3. **Memory Management**: Use Rust's safe abstractions instead of C-style memory management.
4. **Zero-Copy Operations**: Use the zerocopy crate for safe, zero-cost memory operations.
5. **API Design**: Follow Rust idioms and conventions for API design.
6. **Documentation**: All public APIs should be well-documented with examples.

### Testing Requirements

1. **Unit Tests**: Each component must have unit tests with high coverage.
2. **Interoperability Tests**: Test interoperability with s2n-tls and other TLS implementations.
3. **Property Tests**: Use Bolero for property testing.
4. **Snapshot Tests**: Use insta for snapshot testing.
5. **Compliance Testing**: Use Duvet to track compliance with TLS specifications.
6. **Differential Fuzzing**: Ensure equivalence with s2n-tls.

## Architecture Overview

The architecture consists of the following components:

1. **API Layer**: Public interface for applications.
2. **TLS State Machine**: Manages protocol state transitions.
3. **Record Layer**: Handles TLS record protocol.
4. **Handshake Layer**: Manages TLS handshake protocol.
5. **Crypto Operations**: Abstracts cryptographic operations.
6. **aws-lc-rs Integration**: Interfaces with aws-lc-rs.

## Error Handling Strategy

Use Rust's `Result` type with custom error types defined using the thiserror crate:

```rust
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("TLS protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
    
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),
    
    // ... other error types
}
```

## Memory Safety Strategy

1. **Zero-Copy Parsing**: Use the zerocopy crate.
2. **Bounds Checking**: Rely on Rust's built-in bounds checking.
3. **Resource Management**: Use RAII for resource management.
4. **Error Handling**: Use Result for error propagation.

## API Design Principles

1. **Predictability**: APIs should be predictable and easy to use correctly.
2. **Flexibility**: APIs should be flexible and composable.
3. **Ergonomics**: APIs should be ergonomic and intuitive.
4. **Documentation**: All public APIs should be well-documented with examples.

## Implementation Focus

The current focus is on creating the best possible TLS 1.3 implementation, with support for TLS 1.2, TLS 1.1, and TLS 1.0 to be added in future iterations if needed.

## Task Checklist

Before marking a task as complete, ensure:

1. **Requirements Met**: All relevant requirements from the requirements document are met.
2. **Design Followed**: The implementation follows the architecture and design principles.
3. **Tests Written**: Appropriate tests are written and passing.
4. **Documentation Added**: Code is well-documented, especially public APIs.
5. **Code Quality**: Code follows Rust best practices and passes clippy checks.
6. **Performance**: Performance is comparable to the C implementation where applicable.
7. **Interoperability**: Interoperability with s2n-tls is maintained where applicable.


More details are in ./kiro/specs/rust-tls-implementation/design.md, ./kiro/specs/rust-tls-implementation/requirements.md, and ./kiro/specs/rust-tls-implementation/tasks.md. Ensure the guidelines in them are followed for every task.