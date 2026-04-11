# Build the project
build:
    cargo build --features card

# Build with post-quantum cryptography
build-pqc:
    cargo build --features draft-pqc

# Run all tests
test:
    cargo test --features card --test '*'

# Run a specific test file
test-file file:
    cargo test --features card --test {{file}}

# Run a single test by name
test-one file name:
    cargo test --features card --test {{file}} {{name}}

# Run smart card tests (requires physical YubiKey or jcecard)
test-card:
    cargo test --features card --test card_tests -- --ignored --test-threads=1
    cargo test --features card --test card_reset_test -- --ignored --test-threads=1

# Run clippy with warnings as errors
lint:
    cargo clippy --features card -- -D warnings

# Check without building
check:
    cargo check --features card
