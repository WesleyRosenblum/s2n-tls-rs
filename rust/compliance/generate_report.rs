// Generate compliance report
//
// This script generates a compliance report for the s2n-tls-rs implementation.

use std::fs::File;
use std::io::Write;
use std::path::Path;

fn main() -> std::io::Result<()> {
    // Generate the compliance report
    let report = s2n_tls_rs::compliance::generate_compliance_report();
    
    // Create the output directory if it doesn't exist
    let output_dir = Path::new("compliance/report");
    if !output_dir.exists() {
        std::fs::create_dir_all(output_dir)?;
    }
    
    // Write the report to a file
    let output_file = output_dir.join("compliance_report.md");
    let mut file = File::create(output_file)?;
    file.write_all(report.as_bytes())?;
    
    println!("Compliance report generated successfully.");
    
    Ok(())
}
