// Run with: cargo run --example gen_keys
use wecanencrypt::{create_key, CipherSuite, SubkeyFlags};
use std::fs;

fn main() {
    let password = "testpassword";
    let user_id = "Test User <test@example.com>";
    
    let suites = [
        ("nistp256", CipherSuite::NistP256),
        ("nistp384", CipherSuite::NistP384),
        ("nistp521", CipherSuite::NistP521),
        ("cv25519modern", CipherSuite::Cv25519Modern),
        ("rsa4k", CipherSuite::Rsa4k),
    ];
    
    for (name, suite) in suites {
        println!("Generating {} key...", name);
        let key = create_key(
            password,
            &[user_id],
            suite,
            None, None, None,
            SubkeyFlags::all(),
            false,
            true,
        ).expect(&format!("Failed to generate {} key", name));
        
        // Write public key
        fs::write(
            format!("tests/files/store/{}_public.asc", name),
            &key.public_key
        ).expect("Failed to write public key");
        
        // Write secret key  
        fs::write(
            format!("tests/files/store/{}_secret.asc", name),
            &key.secret_key
        ).expect("Failed to write secret key");
        
        println!("  Fingerprint: {}", key.fingerprint);
    }
    
    println!("Done!");
}
