//! Fetch an OpenPGP key by email address via WKD (Web Key Directory).
//!
//! Run with: cargo run --example fetch_key

use std::io::{self, Write};
use wecanencrypt::{fetch_key_by_email, parse_cert_bytes, KeyType};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Prompt user for email
    print!("Enter email address: ");
    io::stdout().flush()?;

    let mut email = String::new();
    io::stdin().read_line(&mut email)?;
    let email = email.trim();

    if email.is_empty() {
        eprintln!("Error: Email address is required");
        std::process::exit(1);
    }

    println!("\nFetching key for '{}'...\n", email);

    // Fetch key via WKD
    let cert_data = fetch_key_by_email(email)?;

    // Parse and display key details
    let info = parse_cert_bytes(&cert_data, true)?;

    println!("Key found!");
    println!("==========\n");
    println!("Fingerprint:  {}", info.fingerprint);
    println!("Key ID:       {}", info.key_id);
    println!("Created:      {}", info.creation_time.format("%Y-%m-%d %H:%M:%S UTC"));

    if let Some(exp) = info.expiration_time {
        println!("Expires:      {}", exp.format("%Y-%m-%d %H:%M:%S UTC"));
    } else {
        println!("Expires:      Never");
    }

    println!("Primary sign: {}", if info.can_primary_sign { "Yes" } else { "No" });

    println!("\nUser IDs:");
    for uid in &info.user_ids {
        println!("  - {}", uid);
    }

    println!("\nSubkeys ({}):", info.subkeys.len());
    for subkey in &info.subkeys {
        let capability = match subkey.key_type {
            KeyType::Encryption => "encrypt",
            KeyType::Signing => "sign",
            KeyType::Authentication => "auth",
            KeyType::Certification => "certify",
            KeyType::Unknown => "unknown",
        };

        let revoked = if subkey.is_revoked { " [REVOKED]" } else { "" };

        println!(
            "  - {} {} ({} bits) [{}]{}",
            &subkey.fingerprint[..16],
            subkey.algorithm,
            subkey.bit_length,
            capability,
            revoked
        );
    }

    Ok(())
}
