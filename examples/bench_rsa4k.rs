// Benchmark RSA4k key generation
//
// Steps to run on another machine:
// 1. Clone the repository
// 2. Build in release mode: cargo build --release --example bench_rsa4k
// 3. Run: cargo run --release --example bench_rsa4k
//
// Or run directly after build:
//    ./target/release/examples/bench_rsa4k

use std::time::Instant;
use wecanencrypt::{create_key, CipherSuite, SubkeyFlags};

fn main() {
    println!("RSA-4096 Key Generation Benchmark");
    println!("==================================\n");

    let password = "testpassword";
    let user_id = "Benchmark User <bench@example.com>";

    println!("Generating RSA-4096 key...");
    println!("  User ID: {}", user_id);
    println!("  Subkeys: encryption, signing, authentication\n");

    let start = Instant::now();

    let key = create_key(
        password,
        &[user_id],
        CipherSuite::Rsa4k,
        None,
        None,
        None,
        SubkeyFlags::all(),
        false,
        true,
    )
    .expect("Failed to generate RSA4k key");

    let elapsed = start.elapsed();

    println!("Key generated successfully!");
    println!("  Fingerprint: {}", key.fingerprint);
    println!("  Public key size: {} bytes", key.public_key.len());
    println!("  Secret key size: {} bytes", key.secret_key.len());
    println!("\nTime taken: {:.2?}", elapsed);
}
