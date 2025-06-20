# Makefile for s2n-tls-rs testing

.PHONY: test test-unit test-property test-snapshot test-interop compliance-report

# Run all tests
test:
	cargo test --all

# Run unit tests
test-unit:
	cargo test --lib --test unit

# Run property tests
test-property:
	cargo test --test property

# Run snapshot tests
test-snapshot:
	cargo test --test snapshot

# Run interoperability tests (requires C s2n-tls to be built)
test-interop:
	cargo test --test interop -- --ignored

# Generate compliance report
compliance-report:
	bash tests/compliance/generate_report.sh

# Update snapshots
update-snapshots:
	cargo insta review

# Run clippy
clippy:
	cargo clippy --all-targets --all-features -- -D warnings

# Run rustfmt
format:
	cargo fmt --all

# Check formatting
check-format:
	cargo fmt --all -- --check

# Clean build artifacts
clean:
	cargo clean