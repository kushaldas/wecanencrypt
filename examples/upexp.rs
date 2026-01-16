// Update key expiry using a YubiKey/OpenPGP smart card.
//
// Run with: cargo run --features card --example upexp -- <path_to_public_key>
//
// This example mimics the johnnycanencrypt update_expiry.py script:
// 1. Reads a public key file
// 2. Displays key information (primary key, subkeys, expiration dates)
// 3. Prompts for confirmation
// 4. Prompts for new expiry date (YYYY-MM-DD)
// 5. Prompts for YubiKey PIN
// 6. Updates primary key and subkey expiry using the card
// 7. Saves the updated key

use std::fs;
use std::io::{self, Write};

use chrono::{NaiveDate, Utc};
use wecanencrypt::card::{
    is_card_connected, verify_user_pin, update_primary_expiry_on_card,
    update_subkeys_expiry_on_card,
};
use wecanencrypt::parse_cert_bytes;

fn read_line(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

fn read_password(prompt: &str) -> String {
    // For a real application, use rpassword crate for hidden input
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <path_to_public_key>", args[0]);
        eprintln!("\nExample:");
        eprintln!("  cargo run --features card --example upexp -- mykey.pub");
        std::process::exit(1);
    }

    let key_path = &args[1];

    // Read the public key
    let public_key = match fs::read(key_path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error: Failed to read public key file '{}': {}", key_path, e);
            std::process::exit(1);
        }
    };

    // Parse and display key information
    let info = match parse_cert_bytes(&public_key, true) {
        Ok(info) => info,
        Err(e) => {
            eprintln!("Error: Failed to parse public key: {}", e);
            std::process::exit(1);
        }
    };

    println!("\n=== Key Information ===\n");
    println!("Primary key: {}", info.fingerprint);
    println!("Key expiring on: {:?}", info.expiration_time);

    if !info.subkeys.is_empty() {
        println!("\nSubkeys:");
        for subkey in &info.subkeys {
            println!(
                "  {} - expires: {:?}, type: {:?}",
                subkey.fingerprint, subkey.expiration_time, subkey.key_type
            );
        }
    }

    // Ask for confirmation
    println!();
    let confirm = read_line("If all looks good, enter YES: ");
    if confirm.to_uppercase() != "YES" {
        println!("Aborted.");
        std::process::exit(0);
    }

    // Ask for new expiry date
    let date_str = read_line("\nEnter new expiry date (YYYY-MM-DD): ");

    // Parse the date and calculate seconds from now
    let expiry_seconds = match parse_expiry_date(&date_str) {
        Ok(secs) => secs,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    // Check for YubiKey
    println!("\nNow connect the YubiKey and make sure you have only one YubiKey inserted.");
    let _ = read_line("Press Enter when ready...");

    if !is_card_connected() {
        eprintln!("Error: No smart card detected. Please insert a YubiKey.");
        std::process::exit(1);
    }

    // Get PIN
    let pin = read_password("Enter your YubiKey PIN: ");
    let pin_bytes = pin.as_bytes();

    // Verify PIN
    println!("\nVerifying the user PIN...");
    match verify_user_pin(pin_bytes) {
        Ok(true) => println!("User PIN verified.\n"),
        Ok(false) => {
            eprintln!("Error: PIN verification returned false.");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!(
                "Error: User PIN failed. Double check before you lock your card.\n{}",
                e
            );
            std::process::exit(1);
        }
    }

    // Update primary key expiry
    println!("Updating primary key expiry. Touch the YubiKey when flashing...");
    let updated_with_primary = match update_primary_expiry_on_card(&public_key, expiry_seconds, pin_bytes) {
        Ok(data) => {
            println!("Primary key expiry updated.");
            data
        }
        Err(e) => {
            eprintln!("Error: Failed to update primary key expiry: {}", e);
            std::process::exit(1);
        }
    };

    // Get subkey fingerprints
    let subkey_fps: Vec<&str> = info.subkeys.iter().map(|s| s.fingerprint.as_str()).collect();

    // Update subkey expiry
    if !subkey_fps.is_empty() {
        println!("\nUpdating subkey expiry. Touch the YubiKey when flashing...");
        let updated_full = match update_subkeys_expiry_on_card(
            &updated_with_primary,
            &subkey_fps,
            expiry_seconds,
            pin_bytes,
        ) {
            Ok(data) => {
                println!("Subkey expiry updated.");
                data
            }
            Err(e) => {
                eprintln!("Error: Failed to update subkey expiry: {}", e);
                std::process::exit(1);
            }
        };

        // Save the updated key
        let output_path = format!("updated_{}.pub", info.fingerprint);
        match fs::write(&output_path, &updated_full) {
            Ok(_) => println!("\nUpdated key saved as {}", output_path),
            Err(e) => {
                eprintln!("Error: Failed to write updated key: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        // No subkeys, save the primary-only update
        let output_path = format!("updated_{}.pub", info.fingerprint);
        match fs::write(&output_path, &updated_with_primary) {
            Ok(_) => println!("\nUpdated key saved as {}", output_path),
            Err(e) => {
                eprintln!("Error: Failed to write updated key: {}", e);
                std::process::exit(1);
            }
        }
    }

    println!("\nDone!");
}

/// Parse a YYYY-MM-DD date string and return seconds from now until that date.
fn parse_expiry_date(date_str: &str) -> Result<u64, String> {
    // Parse YYYY-MM-DD using chrono
    let target_date = NaiveDate::parse_from_str(date_str, "%Y-%m-%d")
        .map_err(|e| format!("Invalid date format. Use YYYY-MM-DD: {}", e))?;

    // Convert to datetime at midnight UTC
    let target_datetime = target_date
        .and_hms_opt(0, 0, 0)
        .ok_or("Failed to create datetime")?
        .and_utc();

    let now = Utc::now();

    if target_datetime <= now {
        return Err("Expiry date must be in the future".to_string());
    }

    // Calculate seconds from now until the target date
    let duration = target_datetime.signed_duration_since(now);

    // Add 1 day buffer (like the Python script)
    let seconds_until_expiry = duration.num_seconds() as u64 + 86400;

    Ok(seconds_until_expiry)
}
