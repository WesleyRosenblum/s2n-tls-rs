#!/bin/bash

# Generate compliance report for the Rust TLS implementation
# This script uses the duvet tool to generate a compliance report

# Change to the repository root
cd "$(git rev-parse --show-toplevel)" || exit 1

# Initialize duvet if needed
if [ ! -d "compliance/specs" ]; then
    echo "Initializing duvet..."
    bash compliance/initialize_duvet.sh
fi

# Generate the report
echo "Generating compliance report..."
duvet report --spec-dir compliance/specs --source-dir rust/src --output rust/tests/compliance/report.html

echo "Report generated at rust/tests/compliance/report.html"