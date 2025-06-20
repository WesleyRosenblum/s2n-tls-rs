# Testing Infrastructure for s2n-tls-rs

This directory contains the testing infrastructure for the Rust implementation of s2n-tls.

## Test Types

### Unit Tests

Unit tests are located in the `unit` directory and test individual components of the library in isolation. These tests are run with the standard Rust testing framework.

To run unit tests:

```bash
cargo test --package s2n-tls-rs --test unit
```

### Property Tests

Property tests are located in the `property` directory and use the Bolero property testing framework to test properties of the library components with randomly generated inputs.

To run property tests:

```bash
cargo test --package s2n-tls-rs --test property
```

### Snapshot Tests

Snapshot tests are located in the `snapshot` directory and use the insta snapshot testing framework to test that the output of the library components matches expected snapshots.

To run snapshot tests:

```bash
cargo test --package s2n-tls-rs --test snapshot
```

To update snapshots:

```bash
cargo insta review
```

### Compliance Tests

Compliance tests ensure that the implementation complies with the TLS specifications. The code is annotated with references to the relevant RFC sections, and a compliance report is generated using the Duvet tool.

To generate a compliance report:

```bash
./tests/compliance/generate_report.sh
```

### Interoperability Tests

Interoperability tests verify that the Rust implementation can interoperate with the C s2n-tls implementation. These tests require both implementations to be built.

To run interoperability tests:

```bash
cargo test --package s2n-tls-rs --test interop -- --ignored
```

## Running All Tests

To run all tests:

```bash
cargo test --package s2n-tls-rs
```

## Adding New Tests

When adding new functionality to the library, please add corresponding tests:

1. Unit tests for basic functionality
2. Property tests for properties that should hold for all inputs
3. Snapshot tests for complex output that should remain consistent
4. Compliance annotations for code that implements RFC requirements
5. Interoperability tests for features that should work with the C implementation