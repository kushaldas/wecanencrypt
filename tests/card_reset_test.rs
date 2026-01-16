//! Destructive smart card reset test.
//!
//! This test is in a separate file because it ERASES ALL DATA on the card.
//! Run separately with: cargo test --features card --test card_reset_test -- --ignored
//!
//! WARNING: This will:
//! - Block the admin PIN by entering wrong PIN 3 times
//! - Factory reset the card
//! - Erase ALL keys and settings
//! - Reset PINs to defaults (User: 123456, Admin: 12345678)

#[cfg(feature = "card")]
mod card_reset_test {
    use wecanencrypt::card::{reset_card, verify_admin_pin};

    #[test]
    #[ignore = "DESTRUCTIVE: requires physical smart card, will reset to factory defaults"]
    fn test_reset_card() {
        println!("========================================");
        println!("WARNING: DESTRUCTIVE TEST");
        println!("========================================");
        println!("This will reset the card to factory defaults!");
        println!("All keys and settings will be erased!");
        println!();

        // First, block the admin PIN by entering it wrong 3 times
        // (This is required for factory reset to work on most cards)
        println!("Step 1: Blocking admin PIN...");
        for i in 1..=3 {
            let _ = verify_admin_pin(b"00000000");
            println!("  Wrong PIN attempt {}/3", i);
        }

        // Now reset the card
        println!();
        println!("Step 2: Resetting card...");
        let result = reset_card();

        match result {
            Ok(()) => {
                println!();
                println!("========================================");
                println!("Card reset successful!");
                println!("========================================");
                println!("Default PINs have been restored:");
                println!("  User PIN:  123456");
                println!("  Admin PIN: 12345678");
            }
            Err(e) => {
                println!();
                println!("Card reset failed: {}", e);
                println!("Some cards may require a different reset procedure.");
            }
        }
    }
}
