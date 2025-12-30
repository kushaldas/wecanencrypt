//! KeyStore implementation.

use std::path::{Path, PathBuf};

use rusqlite::{params, Connection};

use crate::error::{Error, Result};
use crate::internal::{fingerprint_to_hex, keyid_to_hex, parse_cert, public_key_to_armored};
use crate::parse::parse_cert_bytes;
use crate::types::CertificateInfo;

use super::schema::init_schema;

/// SQLite-backed certificate storage.
///
/// The `KeyStore` provides persistent storage for OpenPGP certificates
/// in a SQLite database. It indexes keys by fingerprint, key ID, user ID,
/// and email for efficient lookup.
///
/// # Database Schema
///
/// The keystore uses three tables:
/// - `certificates`: Stores the raw certificate data and metadata
/// - `user_ids`: Indexes user IDs and emails for search
/// - `subkeys`: Indexes subkey fingerprints and key IDs
///
/// # Thread Safety
///
/// The `KeyStore` is not `Sync` due to the underlying SQLite connection.
/// For multi-threaded access, create a separate `KeyStore` instance per thread
/// or use external synchronization.
pub struct KeyStore {
    conn: Connection,
    path: Option<PathBuf>,
}

impl KeyStore {
    /// Open or create a keystore at the given path.
    ///
    /// If the database file doesn't exist, it will be created with the
    /// appropriate schema. Parent directories must already exist.
    ///
    /// # Arguments
    /// * `path` - Path to the SQLite database file
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wecanencrypt::KeyStore;
    ///
    /// // Open or create a keystore
    /// let store = KeyStore::open("/home/user/.myapp/keys.db").unwrap();
    ///
    /// // Check how many keys are stored
    /// println!("Keys in store: {}", store.count().unwrap());
    /// ```
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let conn = Connection::open(path)?;

        // Enable foreign keys
        conn.execute("PRAGMA foreign_keys = ON", [])?;

        init_schema(&conn)?;

        Ok(Self {
            conn,
            path: Some(path.to_path_buf()),
        })
    }

    /// Create an in-memory keystore.
    ///
    /// Creates a temporary keystore that exists only in memory. Useful for
    /// testing or when persistence is not needed.
    ///
    /// # Example
    ///
    /// ```
    /// use wecanencrypt::KeyStore;
    ///
    /// let store = KeyStore::open_in_memory().unwrap();
    /// assert!(store.path().is_none());
    /// assert_eq!(store.count().unwrap(), 0);
    /// ```
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute("PRAGMA foreign_keys = ON", [])?;
        init_schema(&conn)?;

        Ok(Self { conn, path: None })
    }

    /// Import a certificate into the keystore.
    ///
    /// Stores the certificate and indexes it by fingerprint, key ID, user IDs,
    /// and email addresses. If a certificate with the same fingerprint already
    /// exists, it will be replaced.
    ///
    /// # Arguments
    /// * `cert_data` - Certificate data (armored or binary), can be public or secret key
    ///
    /// # Returns
    /// The fingerprint of the imported certificate.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wecanencrypt::{KeyStore, create_key_simple};
    ///
    /// let store = KeyStore::open_in_memory().unwrap();
    ///
    /// // Generate a new key
    /// let key = create_key_simple("password", &["Alice <alice@example.com>"]).unwrap();
    ///
    /// // Import the secret key
    /// let fp = store.import_cert(&key.secret_key).unwrap();
    /// println!("Imported key with fingerprint: {}", fp);
    ///
    /// // Can also import just the public key
    /// let fp2 = store.import_cert(key.public_key.as_bytes()).unwrap();
    /// assert_eq!(fp, fp2);  // Same fingerprint
    /// ```
    pub fn import_cert(&self, cert_data: &[u8]) -> Result<String> {
        let (public_key, is_secret) = parse_cert(cert_data)?;
        let fingerprint = fingerprint_to_hex(&public_key.primary_key);

        // Get primary UID
        let primary_uid = public_key
            .details
            .users
            .first()
            .map(|u| String::from_utf8_lossy(u.id.id()).to_string());

        // Store the certificate
        self.conn.execute(
            "INSERT OR REPLACE INTO certificates (fingerprint, cert_data, is_secret, primary_uid, updated_at)
             VALUES (?1, ?2, ?3, ?4, CURRENT_TIMESTAMP)",
            params![&fingerprint, cert_data, is_secret as i32, primary_uid,],
        )?;

        // Update user IDs
        self.conn.execute(
            "DELETE FROM user_ids WHERE fingerprint = ?1",
            [&fingerprint],
        )?;

        for user in &public_key.details.users {
            let uid = String::from_utf8_lossy(user.id.id()).to_string();
            let email = extract_email(&uid);

            self.conn.execute(
                "INSERT INTO user_ids (fingerprint, uid, email) VALUES (?1, ?2, ?3)",
                params![&fingerprint, &uid, email],
            )?;
        }

        // Update subkeys
        self.conn.execute(
            "DELETE FROM subkeys WHERE fingerprint = ?1",
            [&fingerprint],
        )?;

        // Add primary key
        let primary_key_id = keyid_to_hex(&public_key.primary_key);
        self.conn.execute(
            "INSERT OR REPLACE INTO subkeys (fingerprint, subkey_fingerprint, key_id, key_type)
             VALUES (?1, ?2, ?3, ?4)",
            params![&fingerprint, &fingerprint, &primary_key_id, "certification"],
        )?;

        // Add subkeys
        for subkey in &public_key.public_subkeys {
            let subkey_fp = fingerprint_to_hex(&subkey.key);
            let key_id = keyid_to_hex(&subkey.key);

            // Determine key type from flags
            let key_type = subkey
                .signatures
                .iter()
                .find_map(|sig| {
                    let flags = sig.key_flags();
                    if flags.encrypt_comms() || flags.encrypt_storage() {
                        Some("encryption")
                    } else if flags.sign() {
                        Some("signing")
                    } else if flags.authentication() {
                        Some("authentication")
                    } else {
                        None
                    }
                })
                .unwrap_or("unknown");

            self.conn.execute(
                "INSERT OR REPLACE INTO subkeys (fingerprint, subkey_fingerprint, key_id, key_type)
                 VALUES (?1, ?2, ?3, ?4)",
                params![&fingerprint, &subkey_fp, &key_id, key_type],
            )?;
        }

        Ok(fingerprint)
    }

    /// Import a certificate from a file.
    ///
    /// Reads a certificate file (armored or binary) and imports it into
    /// the keystore.
    ///
    /// # Arguments
    /// * `path` - Path to the certificate file
    ///
    /// # Returns
    /// The fingerprint of the imported certificate.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wecanencrypt::KeyStore;
    ///
    /// let store = KeyStore::open("keys.db").unwrap();
    ///
    /// // Import a public key from file
    /// let fp = store.import_cert_file("alice.asc").unwrap();
    /// println!("Imported: {}", fp);
    /// ```
    pub fn import_cert_file(&self, path: impl AsRef<Path>) -> Result<String> {
        let data = std::fs::read(path.as_ref())?;
        self.import_cert(&data)
    }

    /// Export a certificate by fingerprint.
    ///
    /// Returns the certificate in its original format (as imported).
    /// If the certificate was imported as a secret key, the secret key
    /// material is returned.
    ///
    /// # Arguments
    /// * `fingerprint` - The certificate fingerprint (hex string)
    ///
    /// # Returns
    /// The certificate data in its original format.
    ///
    /// # Errors
    /// Returns `Error::KeyNotFound` if no certificate with the given
    /// fingerprint exists.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wecanencrypt::KeyStore;
    ///
    /// let store = KeyStore::open("keys.db").unwrap();
    ///
    /// // Export a certificate
    /// let cert_data = store.export_cert("ABCD1234...").unwrap();
    ///
    /// // Write to file
    /// std::fs::write("exported.key", &cert_data).unwrap();
    /// ```
    pub fn export_cert(&self, fingerprint: &str) -> Result<Vec<u8>> {
        let data: Vec<u8> = self
            .conn
            .query_row(
                "SELECT cert_data FROM certificates WHERE fingerprint = ?1",
                [fingerprint],
                |row| row.get(0),
            )
            .map_err(|_| Error::KeyNotFound(fingerprint.to_string()))?;

        Ok(data)
    }

    /// Export a certificate as ASCII-armored public key.
    ///
    /// Always exports as a public key, even if the stored certificate
    /// contains secret key material. The output is suitable for sharing
    /// with others.
    ///
    /// # Arguments
    /// * `fingerprint` - The certificate fingerprint (hex string)
    ///
    /// # Returns
    /// ASCII-armored public key string.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wecanencrypt::KeyStore;
    ///
    /// let store = KeyStore::open("keys.db").unwrap();
    ///
    /// // Export public key for sharing
    /// let armored = store.export_cert_armored("ABCD1234...").unwrap();
    /// println!("{}", armored);
    /// // -----BEGIN PGP PUBLIC KEY BLOCK-----
    /// // ...
    /// // -----END PGP PUBLIC KEY BLOCK-----
    /// ```
    pub fn export_cert_armored(&self, fingerprint: &str) -> Result<String> {
        let data = self.export_cert(fingerprint)?;
        let (public_key, _) = parse_cert(&data)?;
        public_key_to_armored(&public_key)
    }

    /// Get certificate info by fingerprint.
    ///
    /// Returns detailed information about the certificate including
    /// fingerprint, user IDs, subkeys, and expiration dates.
    ///
    /// # Arguments
    /// * `fingerprint` - The certificate fingerprint (hex string)
    ///
    /// # Returns
    /// A `CertificateInfo` struct with certificate details.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wecanencrypt::KeyStore;
    ///
    /// let store = KeyStore::open("keys.db").unwrap();
    ///
    /// let info = store.get_cert_info("ABCD1234...").unwrap();
    /// println!("Fingerprint: {}", info.fingerprint);
    /// println!("User IDs: {:?}", info.user_ids);
    /// println!("Has secret key: {}", info.is_secret);
    /// ```
    pub fn get_cert_info(&self, fingerprint: &str) -> Result<CertificateInfo> {
        let data = self.export_cert(fingerprint)?;
        parse_cert_bytes(&data, true)
    }

    /// Get certificate data and info by fingerprint.
    ///
    /// Returns both the raw certificate bytes and parsed certificate
    /// information in a single call. This is more efficient than calling
    /// `export_cert()` and `get_cert_info()` separately when you need both.
    ///
    /// # Arguments
    /// * `fingerprint` - The certificate fingerprint (hex string)
    ///
    /// # Returns
    /// A tuple of `(Vec<u8>, CertificateInfo)` containing:
    /// - The raw certificate data (as originally imported)
    /// - Parsed certificate information (fingerprint, user IDs, subkeys, etc.)
    ///
    /// # Errors
    /// Returns `Error::KeyNotFound` if no certificate with the given
    /// fingerprint exists.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wecanencrypt::{KeyStore, encrypt_bytes};
    ///
    /// let store = KeyStore::open("keys.db").unwrap();
    ///
    /// // Get both cert data and info in one call
    /// let (cert_data, info) = store.get_cert("ABCD1234...").unwrap();
    ///
    /// println!("Key: {} ({:?})", info.fingerprint, info.user_ids);
    /// println!("Has secret key: {}", info.is_secret);
    ///
    /// // Use cert_data for crypto operations
    /// let ciphertext = encrypt_bytes(&cert_data, b"Hello!", true).unwrap();
    /// ```
    pub fn get_cert(&self, fingerprint: &str) -> Result<(Vec<u8>, CertificateInfo)> {
        let data = self.export_cert(fingerprint)?;
        let info = parse_cert_bytes(&data, true)?;
        Ok((data, info))
    }

    /// Check if a key exists by fingerprint.
    ///
    /// # Arguments
    /// * `fingerprint` - The certificate fingerprint (hex string)
    ///
    /// # Returns
    /// `true` if the certificate exists, `false` otherwise.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wecanencrypt::KeyStore;
    ///
    /// let store = KeyStore::open("keys.db").unwrap();
    ///
    /// if store.contains("ABCD1234...").unwrap() {
    ///     println!("Key is in the store");
    /// } else {
    ///     println!("Key not found");
    /// }
    /// ```
    pub fn contains(&self, fingerprint: &str) -> Result<bool> {
        let count: i32 = self.conn.query_row(
            "SELECT COUNT(*) FROM certificates WHERE fingerprint = ?1",
            [fingerprint],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Delete a certificate by fingerprint.
    ///
    /// Removes the certificate and all associated index entries (user IDs,
    /// subkeys) from the database.
    ///
    /// # Arguments
    /// * `fingerprint` - The certificate fingerprint (hex string)
    ///
    /// # Errors
    /// Returns `Error::KeyNotFound` if no certificate with the given
    /// fingerprint exists.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wecanencrypt::KeyStore;
    ///
    /// let store = KeyStore::open("keys.db").unwrap();
    ///
    /// // Delete a key
    /// store.delete_cert("ABCD1234...").unwrap();
    /// assert!(!store.contains("ABCD1234...").unwrap());
    /// ```
    pub fn delete_cert(&self, fingerprint: &str) -> Result<()> {
        let rows = self.conn.execute(
            "DELETE FROM certificates WHERE fingerprint = ?1",
            [fingerprint],
        )?;

        if rows == 0 {
            return Err(Error::KeyNotFound(fingerprint.to_string()));
        }

        Ok(())
    }

    /// List all certificates in the store.
    ///
    /// Returns information about all stored certificates, ordered by
    /// most recently updated first.
    ///
    /// # Returns
    /// A vector of `CertificateInfo` structs for all certificates.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wecanencrypt::KeyStore;
    ///
    /// let store = KeyStore::open("keys.db").unwrap();
    ///
    /// for cert in store.list_certs().unwrap() {
    ///     println!("{} - {:?}", cert.fingerprint, cert.user_ids);
    /// }
    /// ```
    pub fn list_certs(&self) -> Result<Vec<CertificateInfo>> {
        let mut stmt = self
            .conn
            .prepare("SELECT cert_data FROM certificates ORDER BY updated_at DESC")?;

        let rows = stmt.query_map([], |row| {
            let data: Vec<u8> = row.get(0)?;
            Ok(data)
        })?;

        let mut certs = Vec::new();
        for row in rows {
            let data = row?;
            if let Ok(info) = parse_cert_bytes(&data, true) {
                certs.push(info);
            }
        }

        Ok(certs)
    }

    /// List all fingerprints in the store.
    ///
    /// Returns just the fingerprints without parsing the full certificates.
    /// More efficient than `list_certs()` when you only need fingerprints.
    ///
    /// # Returns
    /// A vector of fingerprint strings.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wecanencrypt::KeyStore;
    ///
    /// let store = KeyStore::open("keys.db").unwrap();
    ///
    /// println!("Stored keys:");
    /// for fp in store.list_fingerprints().unwrap() {
    ///     println!("  {}", fp);
    /// }
    /// ```
    pub fn list_fingerprints(&self) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT fingerprint FROM certificates ORDER BY updated_at DESC")?;

        let rows = stmt.query_map([], |row| row.get(0))?;

        let mut fingerprints = Vec::new();
        for row in rows {
            fingerprints.push(row?);
        }

        Ok(fingerprints)
    }

    /// Search certificates by User ID (substring match).
    ///
    /// Finds all certificates with a user ID containing the search string.
    /// The search is case-sensitive.
    ///
    /// # Arguments
    /// * `query` - Substring to search for in user IDs
    ///
    /// # Returns
    /// Certificates with matching user IDs.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wecanencrypt::KeyStore;
    ///
    /// let store = KeyStore::open("keys.db").unwrap();
    ///
    /// // Find all keys with "Alice" in the user ID
    /// let results = store.search_by_uid("Alice").unwrap();
    /// for cert in results {
    ///     println!("{}: {:?}", cert.fingerprint, cert.user_ids);
    /// }
    /// ```
    pub fn search_by_uid(&self, query: &str) -> Result<Vec<CertificateInfo>> {
        let pattern = format!("%{}%", query);
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT c.cert_data FROM certificates c
             JOIN user_ids u ON c.fingerprint = u.fingerprint
             WHERE u.uid LIKE ?1
             ORDER BY c.updated_at DESC",
        )?;

        let rows = stmt.query_map([&pattern], |row| {
            let data: Vec<u8> = row.get(0)?;
            Ok(data)
        })?;

        let mut certs = Vec::new();
        for row in rows {
            let data = row?;
            if let Ok(info) = parse_cert_bytes(&data, true) {
                certs.push(info);
            }
        }

        Ok(certs)
    }

    /// Search certificates by email address.
    ///
    /// Finds all certificates with the exact email address (case-insensitive).
    /// The email is extracted from user IDs in the format "Name <email@example.com>".
    ///
    /// # Arguments
    /// * `email` - Email address to search for
    ///
    /// # Returns
    /// Certificates with matching email addresses.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wecanencrypt::KeyStore;
    ///
    /// let store = KeyStore::open("keys.db").unwrap();
    ///
    /// // Find key by email
    /// let results = store.search_by_email("alice@example.com").unwrap();
    /// if let Some(cert) = results.first() {
    ///     println!("Found: {}", cert.fingerprint);
    /// }
    /// ```
    pub fn search_by_email(&self, email: &str) -> Result<Vec<CertificateInfo>> {
        let email_lower = email.to_lowercase();
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT c.cert_data FROM certificates c
             JOIN user_ids u ON c.fingerprint = u.fingerprint
             WHERE LOWER(u.email) = ?1
             ORDER BY c.updated_at DESC",
        )?;

        let rows = stmt.query_map([&email_lower], |row| {
            let data: Vec<u8> = row.get(0)?;
            Ok(data)
        })?;

        let mut certs = Vec::new();
        for row in rows {
            let data = row?;
            if let Ok(info) = parse_cert_bytes(&data, true) {
                certs.push(info);
            }
        }

        Ok(certs)
    }

    /// Get all secret keys.
    ///
    /// Returns only certificates that contain secret key material
    /// (i.e., keys you own and can use for signing/decryption).
    ///
    /// # Returns
    /// Certificates with secret key material.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wecanencrypt::KeyStore;
    ///
    /// let store = KeyStore::open("keys.db").unwrap();
    ///
    /// println!("Your keys:");
    /// for cert in store.list_secret_keys().unwrap() {
    ///     println!("  {} - {:?}", cert.fingerprint, cert.user_ids);
    /// }
    /// ```
    pub fn list_secret_keys(&self) -> Result<Vec<CertificateInfo>> {
        let mut stmt = self.conn.prepare(
            "SELECT cert_data FROM certificates WHERE is_secret = 1 ORDER BY updated_at DESC",
        )?;

        let rows = stmt.query_map([], |row| {
            let data: Vec<u8> = row.get(0)?;
            Ok(data)
        })?;

        let mut certs = Vec::new();
        for row in rows {
            let data = row?;
            if let Ok(info) = parse_cert_bytes(&data, true) {
                certs.push(info);
            }
        }

        Ok(certs)
    }

    /// Get all public-only keys.
    ///
    /// Returns only certificates that contain only public key material
    /// (i.e., other people's keys that you can use for encryption/verification).
    ///
    /// # Returns
    /// Certificates with only public key material.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wecanencrypt::KeyStore;
    ///
    /// let store = KeyStore::open("keys.db").unwrap();
    ///
    /// println!("Contacts:");
    /// for cert in store.list_public_keys().unwrap() {
    ///     println!("  {} - {:?}", cert.fingerprint, cert.user_ids);
    /// }
    /// ```
    pub fn list_public_keys(&self) -> Result<Vec<CertificateInfo>> {
        let mut stmt = self.conn.prepare(
            "SELECT cert_data FROM certificates WHERE is_secret = 0 ORDER BY updated_at DESC",
        )?;

        let rows = stmt.query_map([], |row| {
            let data: Vec<u8> = row.get(0)?;
            Ok(data)
        })?;

        let mut certs = Vec::new();
        for row in rows {
            let data = row?;
            if let Ok(info) = parse_cert_bytes(&data, true) {
                certs.push(info);
            }
        }

        Ok(certs)
    }

    /// Update a certificate.
    ///
    /// Replaces an existing certificate with new data. The fingerprint must
    /// match the existing certificate. Use this when you've modified a
    /// certificate (added user IDs, updated expiry, etc.).
    ///
    /// # Arguments
    /// * `fingerprint` - The certificate fingerprint (must match existing)
    /// * `cert_data` - The updated certificate data
    ///
    /// # Errors
    /// - `Error::KeyNotFound` if no certificate exists with the fingerprint
    /// - `Error::InvalidInput` if the new data has a different fingerprint
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wecanencrypt::{KeyStore, add_uid};
    ///
    /// let store = KeyStore::open("keys.db").unwrap();
    ///
    /// // Get existing key
    /// let cert_data = store.export_cert("ABCD1234...").unwrap();
    ///
    /// // Add a new user ID
    /// let updated = add_uid(&cert_data, "New Name <new@example.com>", "password").unwrap();
    ///
    /// // Update the stored certificate
    /// store.update_cert("ABCD1234...", &updated).unwrap();
    /// ```
    pub fn update_cert(&self, fingerprint: &str, cert_data: &[u8]) -> Result<()> {
        if !self.contains(fingerprint)? {
            return Err(Error::KeyNotFound(fingerprint.to_string()));
        }

        // Re-import (which will update)
        let new_fp = self.import_cert(cert_data)?;

        if new_fp != fingerprint {
            return Err(Error::InvalidInput(format!(
                "Certificate fingerprint mismatch: expected {}, got {}",
                fingerprint, new_fp
            )));
        }

        Ok(())
    }

    /// Get certificate count.
    ///
    /// Returns the total number of certificates in the store.
    ///
    /// # Example
    ///
    /// ```
    /// use wecanencrypt::KeyStore;
    ///
    /// let store = KeyStore::open_in_memory().unwrap();
    /// assert_eq!(store.count().unwrap(), 0);
    /// ```
    pub fn count(&self) -> Result<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM certificates", [], |row| row.get(0))?;
        Ok(count as usize)
    }

    /// Get database path.
    ///
    /// Returns the path to the SQLite database file, or `None` for
    /// in-memory stores.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wecanencrypt::KeyStore;
    ///
    /// let store = KeyStore::open("keys.db").unwrap();
    /// println!("Database: {:?}", store.path());  // Some("keys.db")
    ///
    /// let mem_store = KeyStore::open_in_memory().unwrap();
    /// assert!(mem_store.path().is_none());
    /// ```
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Find certificate by key ID.
    ///
    /// Searches for a certificate by the key ID of its primary key or any
    /// subkey. Key IDs are the last 16 hex characters of a fingerprint.
    ///
    /// # Arguments
    /// * `key_id` - The key ID to search for (hex string)
    ///
    /// # Returns
    /// The certificate data if found, or `None` if not found.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wecanencrypt::KeyStore;
    ///
    /// let store = KeyStore::open("keys.db").unwrap();
    ///
    /// // Find by key ID (last 16 chars of fingerprint)
    /// if let Some(cert) = store.find_by_key_id("ABCD1234EFGH5678").unwrap() {
    ///     println!("Found certificate");
    /// }
    /// ```
    pub fn find_by_key_id(&self, key_id: &str) -> Result<Option<Vec<u8>>> {
        let result: std::result::Result<String, _> = self.conn.query_row(
            "SELECT fingerprint FROM subkeys WHERE key_id = ?1",
            [key_id],
            |row| row.get(0),
        );

        match result {
            Ok(fp) => {
                let data = self.export_cert(&fp)?;
                Ok(Some(data))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

/// Extract email from a User ID string (e.g., "Name <email@example.com>").
fn extract_email(uid: &str) -> Option<String> {
    if let Some(start) = uid.find('<') {
        if let Some(end) = uid.find('>') {
            if start < end {
                return Some(uid[start + 1..end].to_string());
            }
        }
    }
    // Check if the whole thing is an email
    if uid.contains('@') && !uid.contains(' ') {
        return Some(uid.to_string());
    }
    None
}

// Convenience functions for crypto operations with KeyStore

/// Encrypt bytes using a key from the store.
///
/// Retrieves the recipient's public key from the store and encrypts
/// the plaintext to that key.
///
/// # Arguments
/// * `store` - The keystore containing the recipient's key
/// * `recipient_fingerprint` - Fingerprint of the recipient's key
/// * `plaintext` - Data to encrypt
/// * `armor` - If true, output ASCII-armored; if false, binary
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{KeyStore, encrypt_bytes_from_store};
///
/// let store = KeyStore::open("keys.db").unwrap();
///
/// let ciphertext = encrypt_bytes_from_store(
///     &store,
///     "ABCD1234...",
///     b"Secret message",
///     true,  // ASCII armor
/// ).unwrap();
/// ```
pub fn encrypt_bytes_from_store(
    store: &KeyStore,
    recipient_fingerprint: &str,
    plaintext: &[u8],
    armor: bool,
) -> Result<Vec<u8>> {
    let cert_data = store.export_cert(recipient_fingerprint)?;
    crate::encrypt::encrypt_bytes(&cert_data, plaintext, armor)
}

/// Encrypt to multiple recipients from the store.
///
/// Encrypts data to multiple recipients. Any recipient can decrypt
/// the message with their private key.
///
/// # Arguments
/// * `store` - The keystore containing recipients' keys
/// * `recipient_fingerprints` - Fingerprints of all recipients
/// * `plaintext` - Data to encrypt
/// * `armor` - If true, output ASCII-armored; if false, binary
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{KeyStore, encrypt_bytes_to_multiple_from_store};
///
/// let store = KeyStore::open("keys.db").unwrap();
///
/// let ciphertext = encrypt_bytes_to_multiple_from_store(
///     &store,
///     &["ALICE_FP...", "BOB_FP..."],
///     b"Group message",
///     true,
/// ).unwrap();
/// ```
pub fn encrypt_bytes_to_multiple_from_store(
    store: &KeyStore,
    recipient_fingerprints: &[&str],
    plaintext: &[u8],
    armor: bool,
) -> Result<Vec<u8>> {
    let certs: Vec<Vec<u8>> = recipient_fingerprints
        .iter()
        .map(|fp| store.export_cert(fp))
        .collect::<Result<Vec<_>>>()?;

    let cert_refs: Vec<&[u8]> = certs.iter().map(|c| c.as_slice()).collect();
    crate::encrypt::encrypt_bytes_to_multiple(&cert_refs, plaintext, armor)
}

/// Decrypt bytes using a secret key from the store.
///
/// Retrieves your secret key from the store and decrypts the ciphertext.
/// The key must have been imported with secret key material.
///
/// # Arguments
/// * `store` - The keystore containing your secret key
/// * `secret_key_fingerprint` - Fingerprint of your secret key
/// * `ciphertext` - Encrypted data (armored or binary)
/// * `password` - Password protecting the secret key
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{KeyStore, decrypt_bytes_from_store};
///
/// let store = KeyStore::open("keys.db").unwrap();
/// let ciphertext = b"-----BEGIN PGP MESSAGE-----...";
///
/// let plaintext = decrypt_bytes_from_store(
///     &store,
///     "MY_KEY_FP...",
///     ciphertext,
///     "my_password",
/// ).unwrap();
/// ```
pub fn decrypt_bytes_from_store(
    store: &KeyStore,
    secret_key_fingerprint: &str,
    ciphertext: &[u8],
    password: &str,
) -> Result<Vec<u8>> {
    let cert_data = store.export_cert(secret_key_fingerprint)?;
    crate::decrypt::decrypt_bytes(&cert_data, ciphertext, password)
}

/// Sign bytes using a secret key from the store.
///
/// Creates an inline-signed message. The signature is embedded with
/// the data in a single OpenPGP message.
///
/// # Arguments
/// * `store` - The keystore containing your secret key
/// * `signer_fingerprint` - Fingerprint of your signing key
/// * `data` - Data to sign
/// * `password` - Password protecting the secret key
///
/// # Returns
/// Armored signed message containing both data and signature.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{KeyStore, sign_bytes_from_store};
///
/// let store = KeyStore::open("keys.db").unwrap();
///
/// let signed = sign_bytes_from_store(
///     &store,
///     "MY_KEY_FP...",
///     b"Important message",
///     "my_password",
/// ).unwrap();
/// ```
pub fn sign_bytes_from_store(
    store: &KeyStore,
    signer_fingerprint: &str,
    data: &[u8],
    password: &str,
) -> Result<Vec<u8>> {
    let cert_data = store.export_cert(signer_fingerprint)?;
    crate::sign::sign_bytes(&cert_data, data, password)
}

/// Sign bytes detached using a secret key from the store.
///
/// Creates a detached signature. The signature is separate from the data,
/// suitable for signing files where you want to keep the original unchanged.
///
/// # Arguments
/// * `store` - The keystore containing your secret key
/// * `signer_fingerprint` - Fingerprint of your signing key
/// * `data` - Data to sign
/// * `password` - Password protecting the secret key
///
/// # Returns
/// Armored detached signature.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{KeyStore, sign_bytes_detached_from_store};
///
/// let store = KeyStore::open("keys.db").unwrap();
///
/// let signature = sign_bytes_detached_from_store(
///     &store,
///     "MY_KEY_FP...",
///     b"Document content",
///     "my_password",
/// ).unwrap();
///
/// // Save signature separately
/// std::fs::write("document.sig", &signature).unwrap();
/// ```
pub fn sign_bytes_detached_from_store(
    store: &KeyStore,
    signer_fingerprint: &str,
    data: &[u8],
    password: &str,
) -> Result<String> {
    let cert_data = store.export_cert(signer_fingerprint)?;
    crate::sign::sign_bytes_detached(&cert_data, data, password)
}

/// Verify bytes using a key from the store.
///
/// Verifies an inline-signed message using the signer's public key
/// from the store.
///
/// # Arguments
/// * `store` - The keystore containing the signer's key
/// * `signer_fingerprint` - Fingerprint of the signer's key
/// * `signed_message` - The signed message to verify
///
/// # Returns
/// `true` if the signature is valid, `false` otherwise.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{KeyStore, verify_bytes_from_store};
///
/// let store = KeyStore::open("keys.db").unwrap();
/// let signed_message = b"-----BEGIN PGP MESSAGE-----...";
///
/// let valid = verify_bytes_from_store(
///     &store,
///     "SIGNER_FP...",
///     signed_message,
/// ).unwrap();
///
/// if valid {
///     println!("Signature is valid");
/// }
/// ```
pub fn verify_bytes_from_store(
    store: &KeyStore,
    signer_fingerprint: &str,
    signed_message: &[u8],
) -> Result<bool> {
    let cert_data = store.export_cert(signer_fingerprint)?;
    crate::verify::verify_bytes(&cert_data, signed_message)
}

/// Verify detached signature using a key from the store.
///
/// Verifies a detached signature against the original data using
/// the signer's public key from the store.
///
/// # Arguments
/// * `store` - The keystore containing the signer's key
/// * `signer_fingerprint` - Fingerprint of the signer's key
/// * `data` - The original data that was signed
/// * `signature` - The detached signature (armored or binary)
///
/// # Returns
/// `true` if the signature is valid, `false` otherwise.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{KeyStore, verify_bytes_detached_from_store};
///
/// let store = KeyStore::open("keys.db").unwrap();
/// let document = std::fs::read("document.txt").unwrap();
/// let signature = std::fs::read("document.txt.sig").unwrap();
///
/// let valid = verify_bytes_detached_from_store(
///     &store,
///     "SIGNER_FP...",
///     &document,
///     &signature,
/// ).unwrap();
///
/// if valid {
///     println!("Document signature is valid");
/// }
/// ```
pub fn verify_bytes_detached_from_store(
    store: &KeyStore,
    signer_fingerprint: &str,
    data: &[u8],
    signature: &[u8],
) -> Result<bool> {
    let cert_data = store.export_cert(signer_fingerprint)?;
    crate::verify::verify_bytes_detached(&cert_data, data, signature)
}

// File-based store operations

/// Encrypt a file using a key from the store.
///
/// Encrypts a file to a recipient whose key is in the store.
///
/// # Arguments
/// * `store` - The keystore containing the recipient's key
/// * `recipient_fingerprint` - Fingerprint of the recipient's key
/// * `input` - Path to the file to encrypt
/// * `output` - Path where encrypted file will be written
/// * `armor` - If true, output ASCII-armored; if false, binary
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{KeyStore, encrypt_file_from_store};
///
/// let store = KeyStore::open("keys.db").unwrap();
///
/// encrypt_file_from_store(
///     &store,
///     "RECIPIENT_FP...",
///     "document.pdf",
///     "document.pdf.gpg",
///     true,
/// ).unwrap();
/// ```
pub fn encrypt_file_from_store(
    store: &KeyStore,
    recipient_fingerprint: &str,
    input: impl AsRef<std::path::Path>,
    output: impl AsRef<std::path::Path>,
    armor: bool,
) -> Result<()> {
    let cert_data = store.export_cert(recipient_fingerprint)?;
    crate::encrypt::encrypt_file(&cert_data, input, output, armor)
}

/// Encrypt a file to multiple recipients from the store.
///
/// Encrypts a file to multiple recipients. Any recipient can decrypt.
///
/// # Arguments
/// * `store` - The keystore containing recipients' keys
/// * `recipient_fingerprints` - Fingerprints of all recipients
/// * `input` - Path to the file to encrypt
/// * `output` - Path where encrypted file will be written
/// * `armor` - If true, output ASCII-armored; if false, binary
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{KeyStore, encrypt_file_to_multiple_from_store};
///
/// let store = KeyStore::open("keys.db").unwrap();
///
/// encrypt_file_to_multiple_from_store(
///     &store,
///     &["ALICE_FP...", "BOB_FP..."],
///     "document.pdf",
///     "document.pdf.gpg",
///     true,
/// ).unwrap();
/// ```
pub fn encrypt_file_to_multiple_from_store(
    store: &KeyStore,
    recipient_fingerprints: &[&str],
    input: impl AsRef<std::path::Path>,
    output: impl AsRef<std::path::Path>,
    armor: bool,
) -> Result<()> {
    let certs: Vec<Vec<u8>> = recipient_fingerprints
        .iter()
        .map(|fp| store.export_cert(fp))
        .collect::<Result<Vec<_>>>()?;

    let cert_refs: Vec<&[u8]> = certs.iter().map(|c| c.as_slice()).collect();
    crate::encrypt::encrypt_file_to_multiple(&cert_refs, input, output, armor)
}

/// Decrypt a file using a secret key from the store.
///
/// Decrypts a file using your secret key from the store.
///
/// # Arguments
/// * `store` - The keystore containing your secret key
/// * `secret_key_fingerprint` - Fingerprint of your secret key
/// * `input` - Path to the encrypted file
/// * `output` - Path where decrypted file will be written
/// * `password` - Password protecting your secret key
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{KeyStore, decrypt_file_from_store};
///
/// let store = KeyStore::open("keys.db").unwrap();
///
/// decrypt_file_from_store(
///     &store,
///     "MY_KEY_FP...",
///     "document.pdf.gpg",
///     "document.pdf",
///     "my_password",
/// ).unwrap();
/// ```
pub fn decrypt_file_from_store(
    store: &KeyStore,
    secret_key_fingerprint: &str,
    input: impl AsRef<std::path::Path>,
    output: impl AsRef<std::path::Path>,
    password: &str,
) -> Result<()> {
    let cert_data = store.export_cert(secret_key_fingerprint)?;
    crate::decrypt::decrypt_file(&cert_data, input, output, password)
}

/// Sign a file using a secret key from the store.
///
/// Creates an inline-signed file using your secret key from the store.
///
/// # Arguments
/// * `store` - The keystore containing your secret key
/// * `signer_fingerprint` - Fingerprint of your signing key
/// * `input` - Path to the file to sign
/// * `output` - Path where signed file will be written
/// * `password` - Password protecting your secret key
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{KeyStore, sign_file_from_store};
///
/// let store = KeyStore::open("keys.db").unwrap();
///
/// sign_file_from_store(
///     &store,
///     "MY_KEY_FP...",
///     "message.txt",
///     "message.txt.signed",
///     "my_password",
/// ).unwrap();
/// ```
pub fn sign_file_from_store(
    store: &KeyStore,
    signer_fingerprint: &str,
    input: impl AsRef<std::path::Path>,
    output: impl AsRef<std::path::Path>,
    password: &str,
) -> Result<()> {
    let cert_data = store.export_cert(signer_fingerprint)?;
    crate::sign::sign_file(&cert_data, input, output, password)
}

/// Sign a file with detached signature using a secret key from the store.
///
/// Creates a detached signature file. The original file is unchanged.
///
/// # Arguments
/// * `store` - The keystore containing your secret key
/// * `signer_fingerprint` - Fingerprint of your signing key
/// * `input` - Path to the file to sign
/// * `password` - Password protecting your secret key
///
/// # Returns
/// Armored detached signature string.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{KeyStore, sign_file_detached_from_store};
///
/// let store = KeyStore::open("keys.db").unwrap();
///
/// let signature = sign_file_detached_from_store(
///     &store,
///     "MY_KEY_FP...",
///     "document.pdf",
///     "my_password",
/// ).unwrap();
///
/// std::fs::write("document.pdf.sig", &signature).unwrap();
/// ```
pub fn sign_file_detached_from_store(
    store: &KeyStore,
    signer_fingerprint: &str,
    input: impl AsRef<std::path::Path>,
    password: &str,
) -> Result<String> {
    let cert_data = store.export_cert(signer_fingerprint)?;
    crate::sign::sign_file_detached(&cert_data, input, password)
}

/// Verify a signed file using a key from the store.
///
/// Verifies an inline-signed file using the signer's public key.
///
/// # Arguments
/// * `store` - The keystore containing the signer's key
/// * `signer_fingerprint` - Fingerprint of the signer's key
/// * `input` - Path to the signed file
///
/// # Returns
/// `true` if the signature is valid, `false` otherwise.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{KeyStore, verify_file_from_store};
///
/// let store = KeyStore::open("keys.db").unwrap();
///
/// let valid = verify_file_from_store(
///     &store,
///     "SIGNER_FP...",
///     "message.txt.signed",
/// ).unwrap();
///
/// if valid {
///     println!("Signature verified");
/// }
/// ```
pub fn verify_file_from_store(
    store: &KeyStore,
    signer_fingerprint: &str,
    input: impl AsRef<std::path::Path>,
) -> Result<bool> {
    let cert_data = store.export_cert(signer_fingerprint)?;
    crate::verify::verify_file(&cert_data, input)
}

/// Verify a file with detached signature using a key from the store.
///
/// Verifies a detached signature against the original file.
///
/// # Arguments
/// * `store` - The keystore containing the signer's key
/// * `signer_fingerprint` - Fingerprint of the signer's key
/// * `data_file` - Path to the original data file
/// * `sig_file` - Path to the detached signature file
///
/// # Returns
/// `true` if the signature is valid, `false` otherwise.
///
/// # Example
///
/// ```no_run
/// use wecanencrypt::{KeyStore, verify_file_detached_from_store};
///
/// let store = KeyStore::open("keys.db").unwrap();
///
/// let valid = verify_file_detached_from_store(
///     &store,
///     "SIGNER_FP...",
///     "document.pdf",
///     "document.pdf.sig",
/// ).unwrap();
///
/// if valid {
///     println!("Document signature verified");
/// }
/// ```
pub fn verify_file_detached_from_store(
    store: &KeyStore,
    signer_fingerprint: &str,
    data_file: impl AsRef<std::path::Path>,
    sig_file: impl AsRef<std::path::Path>,
) -> Result<bool> {
    let cert_data = store.export_cert(signer_fingerprint)?;
    let sig_data = std::fs::read(sig_file.as_ref())?;
    crate::verify::verify_file_detached(&cert_data, data_file, &sig_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_email() {
        assert_eq!(
            extract_email("Alice <alice@example.com>"),
            Some("alice@example.com".to_string())
        );
        assert_eq!(
            extract_email("bob@example.com"),
            Some("bob@example.com".to_string())
        );
        assert_eq!(extract_email("Just a Name"), None);
    }

    #[test]
    fn test_keystore_open_in_memory() {
        let store = KeyStore::open_in_memory().unwrap();
        assert!(store.path().is_none());
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn test_keystore_get_cert() {
        use crate::create_key_simple;

        let store = KeyStore::open_in_memory().unwrap();

        // Generate and import a key
        let key = create_key_simple("testpass", &["Test User <test@example.com>"]).unwrap();
        let fp = store.import_cert(&key.secret_key).unwrap();

        // Get cert returns both data and info
        let (cert_data, info) = store.get_cert(&fp).unwrap();

        // Verify the info is correct
        assert_eq!(info.fingerprint, fp);
        assert!(info.is_secret);
        assert_eq!(info.user_ids.len(), 1);
        assert!(info.user_ids[0].contains("Test User"));

        // Verify the cert_data matches what was imported
        let exported = store.export_cert(&fp).unwrap();
        assert_eq!(cert_data, exported);

        // Verify get_cert_info returns same info
        let info2 = store.get_cert_info(&fp).unwrap();
        assert_eq!(info.fingerprint, info2.fingerprint);
        assert_eq!(info.is_secret, info2.is_secret);
        assert_eq!(info.user_ids, info2.user_ids);
    }

    #[test]
    fn test_keystore_get_cert_not_found() {
        let store = KeyStore::open_in_memory().unwrap();

        // Try to get a non-existent cert
        let result = store.get_cert("NONEXISTENT1234567890");
        assert!(result.is_err());
    }
}
