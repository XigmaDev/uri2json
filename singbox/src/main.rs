//! Small CLI for testing conversions locally:
//!
//! ```text
//! cargo run -p singbox -- <version> <URI> [output.json]
//! ```
//!
//! Prints the generated sing-box config to stdout, or writes it to the given file.

use singbox::config;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (version, uri, output) = match args.as_slice() {
        [version, uri] => (version, uri, None),
        [version, uri, output] => (version, uri, Some(output)),
        _ => {
            eprintln!("Usage: singbox <version> <URI> [output.json]");
            eprintln!("Example: singbox 1.12.0 'vless://uuid@host:443?security=tls&type=ws'");
            return ExitCode::from(2);
        }
    };

    let json = match config::generate(version, uri) {
        Ok(json) => json,
        Err(e) => {
            eprintln!("Error: {}", e);
            return ExitCode::FAILURE;
        }
    };

    match output {
        Some(path) => {
            if let Err(e) = std::fs::write(path, json) {
                eprintln!("Failed to write '{}': {}", path, e);
                return ExitCode::FAILURE;
            }
            eprintln!("Saved config to '{}'", path);
        }
        None => println!("{}", json),
    }
    ExitCode::SUCCESS
}
