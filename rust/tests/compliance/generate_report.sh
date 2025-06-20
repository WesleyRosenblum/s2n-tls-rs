#!/bin/bash

# Generate compliance report for the Rust TLS implementation
# This script uses the duvet tool to generate a compliance report

# Change to the repository root
cd "$(git rev-parse --show-toplevel)" || exit 1

# Check if duvet is installed
if ! command -v duvet &> /dev/null; then
    echo "Error: duvet is not installed. Please install it with 'cargo install duvet'."
    exit 1
fi

# Check if duvet is initialized
if [ ! -d ".duvet" ]; then
    echo "Initializing duvet..."
    duvet init --lang-rust
fi
# Generate the report
echo "Generating compliance report..."
duvet report --html rust/tests/compliance/report.html

echo "Report generated at rust/tests/compliance/report.html"