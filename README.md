<img src="docs/images/s2n_logo_github.png" alt="s2n">

s2n-tls is a C99 implementation of the TLS/SSL protocols that is designed to be simple, small, fast, and with security as a priority. It is released and licensed under the Apache License 2.0.

> s2n-tls is short for "signal to noise" and is a nod to the almost magical act of encryption — disguising meaningful signals, like your critical data, as seemingly random noise.
>
> -- [s2n-tls announcement](https://aws.amazon.com/blogs/security/introducing-s2n-a-new-open-source-tls-implementation/)

[![Build Status](https://codebuild.us-west-2.amazonaws.com/badges?uuid=eyJlbmNyeXB0ZWREYXRhIjoiMndlTzJNbHVxWEo3Nm82alp4eGdGNm4rTWdxZDVYU2VTbitIR0ZLbHVtcFFGOW5majk5QnhqaUp3ZEkydG1ueWg0NGlhRE43a1ZnUzZaQTVnSm91TzFFPSIsIml2UGFyYW1ldGVyU3BlYyI6IlJLbW42NENlYXhJNy80QnYiLCJtYXRlcmlhbFNldFNlcmlhbCI6MX0%3D&branch=main)](https://github.com/aws/s2n-tls/)
[![Apache 2 License](https://img.shields.io/github/license/aws/s2n-tls.svg)](http://aws.amazon.com/apache-2-0/)
[![C99](https://img.shields.io/badge/language-C99-blue.svg)](http://www.open-std.org/jtc1/sc22/wg14/www/docs/n1256.pdf)
[![Github forks](https://img.shields.io/github/forks/aws/s2n-tls.svg)](https://github.com/aws/s2n-tls/network)
[![Github stars](https://img.shields.io/github/stars/aws/s2n-tls.svg)](https://github.com/aws/s2n-tls/stargazers)

## Quickstart for Ubuntu

```bash
# clone s2n-tls
git clone https://github.com/aws/s2n-tls.git
cd s2n-tls

# install build dependencies
sudo apt update
sudo apt install cmake

# install a libcrypto
sudo apt install libssl-dev

# build s2n-tls
cmake . -Bbuild \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=./s2n-tls-install
cmake --build build -j $(nproc)
CTEST_PARALLEL_LEVEL=$(nproc) ctest --test-dir build
cmake --install build
```

See the [s2n-tls build documentation](docs/BUILD.md) for further guidance on building s2n-tls for your platform.

## Have a Question?
If you think you might have found a security impacting issue, please follow our [Security Notification Process.](#security-issue-notifications)

If you have any questions about submitting PRs, s2n-tls API usage, or something similar, please open an issue.

## Documentation

s2n-tls uses [Doxygen](https://doxygen.nl/index.html) to document its public API. The latest s2n-tls documentation can be found on [GitHub pages](https://aws.github.io/s2n-tls/doxygen/). The [Usage Guide](https://aws.github.io/s2n-tls/usage-guide/) explains how different TLS features can be configured and used. s2n-tls Rust bindings docs can be found [here](https://docs.rs/s2n-tls/latest/s2n_tls/).

Documentation for older versions or branches of s2n-tls can be generated locally. To generate the documentation, install doxygen and run `doxygen docs/doxygen/Doxyfile`. The doxygen documentation can now be found at `docs/doxygen/output/html/index.html`.

Doxygen installation instructions are available at the [Doxygen](https://doxygen.nl/download.html) webpage.

## Platform Support

We’ve listed the distributions and platforms under two tiers: Tier 1 platforms are guaranteed to build, run, and pass tests in CI. Tier 2 platforms are guaranteed to build and we'll address issues opened against them, but they aren't currently running in our CI and are not actively reviewed with every commit. If you use a platform not listed below and would like to request (or help!) add it to our CI, please open an issue for discussion.

### Tier 1

|Distribution in CI                                     |Platforms        |
|-------------------------------------------------------|-----------------|
|Ubuntu18, Ubuntu24**                                   | x86_64          |
|Ubuntu22                                               | x86_64, i686    |
|AL2, AL2023**                                          | x86_64, aarch64 |
|NixOS                                                  | x86_64, aarch64 |
|OpenBSD [7.4](https://github.com/cross-platform-actions/action/blob/master/readme.md#supported-platforms)| x86_64 |
|FreeBSD [latest](https://github.com/vmactions/freebsd-vm/blob/v1/conf/default.release.conf)| x86_64  |
|OSX [latest](https://github.com/actions/runner-images?tab=readme-ov-file#available-images) | aarch64 |

**Work in Progress

### Tier 2

|Distribution not in CI |Platforms|
|-----------------------|---------|
| Fedora Core 34-36     | x86_64, aarch64 |
| Ubuntu14/16/20        | x86_64, aarch64 |
| Ubuntu18/22/24        | aarch64         |
| [OSX](https://github.com/actions/runner-images/tree/main/images/macos) 12-14 |x86_64|

These distribution lists are not exhaustive and missing tooling or a missing supported libcrypto library could prevent a successful build.

## Using s2n-tls

The s2n-tls I/O APIs are designed to be intuitive to developers familiar with the widely-used POSIX I/O APIs, and s2n-tls supports blocking, non-blocking, and full-duplex I/O. Additionally there are no locks or mutexes within s2n-tls.

```c
/* Create a server mode connection handle */
struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
if (conn == NULL) {
    ... error ...
}

/* Associate a connection with a file descriptor */
if (s2n_connection_set_fd(conn, fd) < 0) {
    ... error ...
}

/* Negotiate the TLS handshake */
s2n_blocked_status blocked;
if (s2n_negotiate(conn, &blocked) < 0) {
    ... error ...
}

/* Write data to the connection */
int bytes_written;
bytes_written = s2n_send(conn, "Hello World", sizeof("Hello World"), &blocked);
```

For details on building the s2n-tls library and how to use s2n-tls in an application you are developing, see the [Usage Guide](https://aws.github.io/s2n-tls/usage-guide).

## Rust Implementation (s2n-tls-rs)

s2n-tls includes a memory-safe Rust implementation of the TLS protocol that is compatible with the C implementation. The Rust implementation (s2n-tls-rs) is located in the [rust](./rust) directory and provides the same security guarantees as the C implementation while leveraging Rust's memory safety features.

```rust
// Create a server mode connection
let mut config = Config::new_server();
config.set_server_certificate(cert_data)?;
config.set_server_private_key(key_data)?;

// Create a connection
let mut connection = Connection::new(config);
connection.initialize()?;

// Negotiate the TLS handshake
connection.negotiate()?;

// Send data
connection.send(b"Hello World")?;
```

For more details on using the Rust implementation, see the [s2n-tls-rs README](./rust/README.md).

## s2n-tls features

s2n-tls implements SSLv3, TLS1.0, TLS1.1, TLS1.2, and TLS1.3. For encryption, s2n-tls supports 128-bit and 256-bit AES in the CBC and GCM modes, ChaCha20, 3DES, and RC4. For forward secrecy, s2n-tls supports both DHE and ECDHE. s2n-tls also supports the Server Name Indicator (SNI), Application-Layer Protocol Negotiation (ALPN), and Online Certificate Status Protocol (OCSP) TLS extensions. SSLv3, RC4, 3DES, and DHE are each disabled by default for security reasons.

As it can be difficult to keep track of which encryption algorithms and protocols are best to use, s2n-tls features a simple API to use the latest "default" set of preferences. If you prefer to remain on a specific version for backwards compatibility, that is also supported.

```c
/* Use the latest s2n-tls "default" set of ciphersuite and protocol preferences */
s2n_config_set_cipher_preferences(config, "default");

/* Use a specific set of preferences, update when you're ready */
s2n_config_set_cipher_preferences(config, "20150306")
```

## s2n-tls safety mechanisms

Internally s2n-tls takes a systematic approach to data protection and includes several mechanisms designed to improve safety.

##### Auditable code base
s2n-tls's code is structured and written with a focus on reviewability. All s2n-tls code is subject to code review, and we plan to complete security evaluations of s2n-tls on an annual basis.

To date there have been two external code-level reviews of s2n-tls, including one by a commercial security vendor. s2n-tls has also been shared with some trusted members of the broader cryptography, security, and Open Source communities. Any issues discovered are always recorded in the s2n-tls issue tracker.

##### Static analysis, fuzz-testing and penetration testing

In addition to code reviews, s2n-tls is subject to regular static analysis, fuzz-testing, and penetration testing. Several penetration tests have occurred, including two by commercial vendors.

##### Unit tests and end-to-end testing

s2n-tls includes positive and negative unit tests and end-to-end test cases.

Unit test coverage can be viewed [here](https://dx1inn44oyl7n.cloudfront.net/main/index.html). Note that this represents unit coverage for a particular build. Since that build won't necessarily support all s2n-tls features, test coverage may be artificially lowered.

##### Erase on read
s2n-tls encrypts or erases plaintext data as quickly as possible. For example, decrypted data buffers are erased as they are read by the application.

##### Built-in memory protection
s2n-tls uses operating system features to protect data from being swapped to disk or appearing in core dumps.

##### Minimalist feature adoption
s2n-tls avoids implementing rarely used options and extensions, as well as features with a history of triggering protocol-level vulnerabilities. For example, there is no support for DTLS.

##### Compartmentalized random number generation
The security of TLS and its associated encryption algorithms depends upon secure random number generation. s2n-tls provides every thread with two separate random number generators. One for "public" randomly generated data that may appear in the clear, and one for "private" data that should remain secret. This approach lessens the risk of potential predictability weaknesses in random number generation algorithms from leaking information across contexts.

##### Modularized encryption
s2n-tls has been structured so that different encryption libraries may be used. Today s2n-tls supports AWS-LC, OpenSSL (versions 1.0.2, 1.1.1 and 3.0.x), LibreSSL, and BoringSSL to perform the underlying cryptographic operations. Check the [libcrypto build documentation](docs/BUILD.md#building-with-a-specific-libcrypto) for a list of libcrypto-specific features.

##### Timing blinding
s2n-tls includes structured support for blinding time-based side-channels that may leak sensitive data. For example, if s2n-tls fails to parse a TLS record or handshake message, s2n-tls will add a randomized delay of between 10 and 30 seconds, granular to nanoseconds, before responding. This raises the complexity of real-world timing side-channel attacks by a factor of at least tens of trillions.

##### Table based state-machines
s2n-tls uses simple tables to drive the TLS/SSL state machines, making it difficult for invalid out-of-order states to arise.

##### C safety
s2n-tls is written in C, but makes light use of standard C library functions and wraps all memory handling, string handling, and serialization in systematic boundary-enforcing checks.

## Security issue notifications
If you discover a potential security issue in s2n-tls we ask that you notify
AWS Security via our [vulnerability reporting page](http://aws.amazon.com/security/vulnerability-reporting/). Please do **not** create a public github issue.

If you package or distribute s2n-tls, or use s2n-tls as part of a large multi-user service, you may be eligible for pre-notification of future s2n-tls releases. Please contact s2n-pre-notification@amazon.com.

## Contributing to s2n-tls
If you are interested in contributing to s2n-tls, please see our [development guide](https://github.com/aws/s2n-tls/blob/main/docs/DEVELOPMENT-GUIDE.md).

## Language Bindings for s2n-tls
See our [language bindings list](https://github.com/aws/s2n-tls/blob/main/docs/BINDINGS.md) for language bindings for s2n-tls that we're aware of.
