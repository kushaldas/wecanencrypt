//! SQLite-backed key storage and store-integrated crypto helpers.
//!
//! [`KeyStore`] persists OpenPGP keys, keeps lookup indexes for fingerprints,
//! key IDs, user IDs, email addresses, and card associations, and exposes
//! convenience wrappers that fetch keys from the store before calling the
//! crate's encryption, decryption, signing, and verification helpers.

use std::path::{Path, PathBuf};

use rusqlite::{params, Connection};

use pgp::types::KeyDetails;

use crate::error::{Error, Result};
use crate::internal::{
    extract_uid_email, fingerprint_to_hex, get_algorithm_name, get_key_bit_size,
    get_key_expiration, keyid_to_hex, most_recent_verified_binding_sig, parse_key,
    public_key_to_armored, system_time_to_datetime, verified_primary_revocation,
};
use crate::parse::parse_key_bytes;
use crate::types::{KeyInfo, KeySummary, SubkeySummary, UserIdSummary};

use super::schema::init_schema;

/// SQLite-backed key storage.
///
/// The `KeyStore` provides persistent storage for OpenPGP keys
/// in a SQLite database. It indexes keys by fingerprint, key ID, user ID,
/// and email for efficient lookup.
///
/// # Database Schema
///
/// The keystore uses three tables:
/// - `keys`: Stores the raw key data and metadata
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

    /// Test-only: expose the raw SQLite connection so in-crate tests
    /// can assert on column contents without going through the public
    /// parse-heavy APIs. Not part of the stable API.
    #[cfg(test)]
    pub(crate) fn raw_conn_for_test(&self) -> &Connection {
        &self.conn
    }

    /// Import a key into the keystore.
    ///
    /// Stores the key and indexes it by fingerprint, key ID, user IDs,
    /// and email addresses. If a key with the same fingerprint already
    /// exists, it will be replaced.
    ///
    /// # Arguments
    /// * `key_data` - Key data (armored or binary), can be public or secret key
    ///
    /// # Returns
    /// The fingerprint of the imported key.
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
    /// let fp = store.import_key(&key.secret_key).unwrap();
    /// println!("Imported key with fingerprint: {}", fp);
    ///
    /// // Can also import just the public key
    /// let fp2 = store.import_key(key.public_key.as_bytes()).unwrap();
    /// assert_eq!(fp, fp2);  // Same fingerprint
    /// ```
    pub fn import_key(&self, key_data: &[u8]) -> Result<String> {
        let (public_key, is_secret) = parse_key(key_data)?;
        let fingerprint = fingerprint_to_hex(&public_key.primary_key);
        let incoming_version = public_key.primary_key.version();

        // Defense-in-depth: if a row already exists for this fingerprint,
        // ensure its primary-key version matches the incoming one. V4 and V6
        // primaries hash over different structures so a collision is
        // cryptographically infeasible, but this guard turns any edge-case
        // attempt at a cross-version overwrite into a precise
        // `KeyVersionMismatch` rather than a silent `INSERT OR REPLACE`.
        if let Ok(stored_data) = self.conn.query_row(
            "SELECT key_data FROM keys WHERE fingerprint = ?1",
            [&fingerprint],
            |row| row.get::<_, Vec<u8>>(0),
        ) {
            let (stored_public, _stored_is_secret) = parse_key(&stored_data)?;
            let stored_version = stored_public.primary_key.version();
            if stored_version != incoming_version {
                return Err(Error::KeyVersionMismatch {
                    existing: stored_version,
                    incoming: incoming_version,
                });
            }
        }

        // Get primary UID
        let primary_uid = public_key
            .details
            .users
            .first()
            .map(|u| String::from_utf8_lossy(u.id.id()).to_string());

        // Summary-view fields (schema v4). Computing these at insert
        // time means `list_keys_summary` / `get_key_summary` never have
        // to re-parse the blob.
        let cert_created_at =
            system_time_to_datetime(public_key.primary_key.created_at().into()).to_rfc3339();
        let expiration_time = get_key_expiration(&public_key)
            .map(system_time_to_datetime)
            .map(|dt| dt.to_rfc3339());
        // Only count a revocation if it cryptographically verifies against
        // the primary key. rpgp parses KeyRevocation packets unverified, so
        // treating their presence as revocation would accept forged packets.
        let revocation_sig = verified_primary_revocation(&public_key);
        let is_revoked = revocation_sig.is_some();
        let revocation_time = revocation_sig.and_then(|sig| sig.created()).map(|ts| {
            let st: std::time::SystemTime = ts.into();
            system_time_to_datetime(st).to_rfc3339()
        });

        // Store the key. Use an UPSERT (in-place UPDATE on conflict) rather
        // than `INSERT OR REPLACE`: REPLACE resolves a PRIMARY KEY conflict by
        // DELETE-ing the existing row and INSERT-ing a new one, and that
        // implicit DELETE fires `card_keys`' `ON DELETE CASCADE`, silently
        // wiping a key's card linkage on every re-import (tumpa-cli#32). An
        // in-place UPDATE issues no DELETE, so the cascade never triggers and
        // card associations survive.
        self.conn.execute(
            "INSERT INTO keys (
                fingerprint, key_data, is_secret, primary_uid,
                is_revoked, revocation_time, expiration_time, cert_created_at,
                updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, CURRENT_TIMESTAMP)
             ON CONFLICT(fingerprint) DO UPDATE SET
                key_data        = excluded.key_data,
                is_secret       = excluded.is_secret,
                primary_uid     = excluded.primary_uid,
                is_revoked      = excluded.is_revoked,
                revocation_time = excluded.revocation_time,
                expiration_time = excluded.expiration_time,
                cert_created_at = excluded.cert_created_at,
                updated_at      = CURRENT_TIMESTAMP",
            params![
                &fingerprint,
                key_data,
                is_secret as i32,
                primary_uid,
                is_revoked as i32,
                revocation_time,
                expiration_time,
                cert_created_at,
            ],
        )?;

        // Update user IDs
        self.conn.execute(
            "DELETE FROM user_ids WHERE fingerprint = ?1",
            [&fingerprint],
        )?;

        for user in &public_key.details.users {
            let uid = String::from_utf8_lossy(user.id.id()).to_string();
            let email = extract_uid_email(&uid);

            self.conn.execute(
                "INSERT INTO user_ids (fingerprint, uid, email) VALUES (?1, ?2, ?3)",
                params![&fingerprint, &uid, email],
            )?;
        }

        // Update subkeys
        self.conn
            .execute("DELETE FROM subkeys WHERE fingerprint = ?1", [&fingerprint])?;

        // Add primary key (cached algorithm + bit_length enable the
        // summary-view query to avoid re-parsing the blob).
        let primary_key_id = keyid_to_hex(&public_key.primary_key);
        let primary_algorithm = get_algorithm_name(&public_key.primary_key);
        let primary_bit_length = get_key_bit_size(&public_key.primary_key) as i64;
        self.conn.execute(
            "INSERT OR REPLACE INTO subkeys
                (fingerprint, subkey_fingerprint, key_id, key_type, algorithm, bit_length)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                &fingerprint,
                &fingerprint,
                &primary_key_id,
                "certification",
                &primary_algorithm,
                primary_bit_length,
            ],
        )?;

        // Add subkeys
        for subkey in &public_key.public_subkeys {
            let subkey_fp = fingerprint_to_hex(&subkey.key);
            let key_id = keyid_to_hex(&subkey.key);

            // Determine key type from the most recent verified binding.
            let key_type = match most_recent_verified_binding_sig(&public_key.primary_key, subkey)
                .map(|sig| sig.key_flags())
            {
                Some(flags) if flags.encrypt_comms() || flags.encrypt_storage() => "encryption",
                Some(flags) if flags.sign() => "signing",
                Some(flags) if flags.authentication() => "authentication",
                _ => "unknown",
            };

            let algorithm = get_algorithm_name(&subkey.key);
            let bit_length = get_key_bit_size(&subkey.key) as i64;

            self.conn.execute(
                "INSERT OR REPLACE INTO subkeys
                    (fingerprint, subkey_fingerprint, key_id, key_type, algorithm, bit_length)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    &fingerprint,
                    &subkey_fp,
                    &key_id,
                    key_type,
                    &algorithm,
                    bit_length,
                ],
            )?;
        }

        Ok(fingerprint)
    }

    /// Import a key from a file.
    ///
    /// Reads a key file (armored or binary) and imports it into
    /// the keystore.
    ///
    /// # Arguments
    /// * `path` - Path to the key file
    ///
    /// # Returns
    /// The fingerprint of the imported key.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wecanencrypt::KeyStore;
    ///
    /// let store = KeyStore::open("keys.db").unwrap();
    ///
    /// // Import a public key from file
    /// let fp = store.import_key_file("alice.asc").unwrap();
    /// println!("Imported: {}", fp);
    /// ```
    pub fn import_key_file(&self, path: impl AsRef<Path>) -> Result<String> {
        let data = std::fs::read(path.as_ref())?;
        self.import_key(&data)
    }

    /// Export a key by fingerprint.
    ///
    /// Returns the key in its original format (as imported).
    /// If the key was imported as a secret key, the secret key
    /// material is returned.
    ///
    /// # Arguments
    /// * `fingerprint` - The key fingerprint (hex string)
    ///
    /// # Returns
    /// The key data in its original format.
    ///
    /// # Errors
    /// Returns `Error::KeyNotFound` if no key with the given
    /// fingerprint exists.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wecanencrypt::KeyStore;
    ///
    /// let store = KeyStore::open("keys.db").unwrap();
    ///
    /// // Export a key
    /// let key_data = store.export_key("ABCD1234...").unwrap();
    ///
    /// // Write to file
    /// std::fs::write("exported.key", &key_data).unwrap();
    /// ```
    pub fn export_key(&self, fingerprint: &str) -> Result<Vec<u8>> {
        let data: Vec<u8> = self
            .conn
            .query_row(
                "SELECT key_data FROM keys WHERE fingerprint = ?1",
                [fingerprint],
                |row| row.get(0),
            )
            .map_err(|_| Error::KeyNotFound(fingerprint.to_string()))?;

        Ok(data)
    }

    /// Export a key as ASCII-armored public key.
    ///
    /// Always exports as a public key, even if the stored key
    /// contains secret key material. The output is suitable for sharing
    /// with others.
    ///
    /// # Arguments
    /// * `fingerprint` - The key fingerprint (hex string)
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
    /// let armored = store.export_key_armored("ABCD1234...").unwrap();
    /// println!("{}", armored);
    /// // -----BEGIN PGP PUBLIC KEY BLOCK-----
    /// // ...
    /// // -----END PGP PUBLIC KEY BLOCK-----
    /// ```
    pub fn export_key_armored(&self, fingerprint: &str) -> Result<String> {
        let data = self.export_key(fingerprint)?;
        let (public_key, _) = parse_key(&data)?;
        public_key_to_armored(&public_key)
    }

    /// Get key info by fingerprint.
    ///
    /// Returns detailed information about the key including
    /// fingerprint, user IDs, subkeys, and expiration dates.
    ///
    /// # Arguments
    /// * `fingerprint` - The key fingerprint (hex string)
    ///
    /// # Returns
    /// A `KeyInfo` struct with key details.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wecanencrypt::KeyStore;
    ///
    /// let store = KeyStore::open("keys.db").unwrap();
    ///
    /// let info = store.get_key_info("ABCD1234...").unwrap();
    /// println!("Fingerprint: {}", info.fingerprint);
    /// println!("User IDs: {:?}", info.user_ids);
    /// println!("Has secret key: {}", info.is_secret);
    /// ```
    pub fn get_key_info(&self, fingerprint: &str) -> Result<KeyInfo> {
        let data = self.export_key(fingerprint)?;
        parse_key_bytes(&data, true)
    }

    /// Get key data and info by fingerprint.
    ///
    /// Returns both the raw key bytes and parsed key
    /// information in a single call. This is more efficient than calling
    /// `export_key()` and `get_key_info()` separately when you need both.
    ///
    /// # Arguments
    /// * `fingerprint` - The key fingerprint (hex string)
    ///
    /// # Returns
    /// A tuple of `(Vec<u8>, KeyInfo)` containing:
    /// - The raw key data (as originally imported)
    /// - Parsed key information (fingerprint, user IDs, subkeys, etc.)
    ///
    /// # Errors
    /// Returns `Error::KeyNotFound` if no key with the given
    /// fingerprint exists.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wecanencrypt::{KeyStore, encrypt_bytes};
    ///
    /// let store = KeyStore::open("keys.db").unwrap();
    ///
    /// // Get both key data and info in one call
    /// let (key_data, info) = store.get_key("ABCD1234...").unwrap();
    ///
    /// println!("Key: {} ({:?})", info.fingerprint, info.user_ids);
    /// println!("Has secret key: {}", info.is_secret);
    ///
    /// // Use key_data for crypto operations
    /// let ciphertext = encrypt_bytes(&key_data, b"Hello!", true).unwrap();
    /// ```
    pub fn get_key(&self, fingerprint: &str) -> Result<(Vec<u8>, KeyInfo)> {
        let data = self.export_key(fingerprint)?;
        let info = parse_key_bytes(&data, true)?;
        Ok((data, info))
    }

    /// Check if a key exists by fingerprint.
    ///
    /// # Arguments
    /// * `fingerprint` - The key fingerprint (hex string)
    ///
    /// # Returns
    /// `true` if the key exists, `false` otherwise.
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
            "SELECT COUNT(*) FROM keys WHERE fingerprint = ?1",
            [fingerprint],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Delete a key by fingerprint.
    ///
    /// Removes the key and all associated index entries (user IDs,
    /// subkeys) from the database.
    ///
    /// # Arguments
    /// * `fingerprint` - The key fingerprint (hex string)
    ///
    /// # Errors
    /// Returns `Error::KeyNotFound` if no key with the given
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
    /// store.delete_key("ABCD1234...").unwrap();
    /// assert!(!store.contains("ABCD1234...").unwrap());
    /// ```
    pub fn delete_key(&self, fingerprint: &str) -> Result<()> {
        let rows = self
            .conn
            .execute("DELETE FROM keys WHERE fingerprint = ?1", [fingerprint])?;

        if rows == 0 {
            return Err(Error::KeyNotFound(fingerprint.to_string()));
        }

        Ok(())
    }

    /// List all keys in the store.
    ///
    /// Returns information about all stored keys, ordered by
    /// most recently updated first.
    ///
    /// # Returns
    /// A vector of `KeyInfo` structs for all keys.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wecanencrypt::KeyStore;
    ///
    /// let store = KeyStore::open("keys.db").unwrap();
    ///
    /// for key in store.list_keys().unwrap() {
    ///     println!("{} - {:?}", key.fingerprint, key.user_ids);
    /// }
    /// ```
    pub fn list_keys(&self) -> Result<Vec<KeyInfo>> {
        let mut stmt = self
            .conn
            .prepare("SELECT key_data FROM keys ORDER BY updated_at DESC")?;

        let rows = stmt.query_map([], |row| {
            let data: Vec<u8> = row.get(0)?;
            Ok(data)
        })?;

        let mut keys = Vec::new();
        for row in rows {
            let data = row?;
            if let Ok(info) = parse_key_bytes(&data, true) {
                keys.push(info);
            }
        }

        Ok(keys)
    }

    /// List all fingerprints in the store.
    ///
    /// Returns just the fingerprints without parsing the full keys.
    /// More efficient than `list_keys()` when you only need fingerprints.
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
            .prepare("SELECT fingerprint FROM keys ORDER BY updated_at DESC")?;

        let rows = stmt.query_map([], |row| row.get(0))?;

        let mut fingerprints = Vec::new();
        for row in rows {
            fingerprints.push(row?);
        }

        Ok(fingerprints)
    }

    /// Search keys by User ID (substring match).
    ///
    /// Finds all keys with a user ID containing the search string.
    /// The search is case-sensitive.
    ///
    /// # Arguments
    /// * `query` - Substring to search for in user IDs
    ///
    /// # Returns
    /// Keys with matching user IDs.
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
    /// for key in results {
    ///     println!("{}: {:?}", key.fingerprint, key.user_ids);
    /// }
    /// ```
    pub fn search_by_uid(&self, query: &str) -> Result<Vec<KeyInfo>> {
        let pattern = format!("%{}%", query);
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT c.key_data FROM keys c
             JOIN user_ids u ON c.fingerprint = u.fingerprint
             WHERE u.uid LIKE ?1
             ORDER BY c.updated_at DESC",
        )?;

        let rows = stmt.query_map([&pattern], |row| {
            let data: Vec<u8> = row.get(0)?;
            Ok(data)
        })?;

        let mut keys = Vec::new();
        for row in rows {
            let data = row?;
            if let Ok(info) = parse_key_bytes(&data, true) {
                keys.push(info);
            }
        }

        Ok(keys)
    }

    /// Search keys by email address.
    ///
    /// Finds all keys with the exact email address (case-insensitive).
    /// The email is extracted from user IDs in the format "Name <email@example.com>".
    ///
    /// # Arguments
    /// * `email` - Email address to search for
    ///
    /// # Returns
    /// Keys with matching email addresses.
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
    /// if let Some(key) = results.first() {
    ///     println!("Found: {}", key.fingerprint);
    /// }
    /// ```
    pub fn search_by_email(&self, email: &str) -> Result<Vec<KeyInfo>> {
        let email_lower = email.to_lowercase();
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT c.key_data FROM keys c
             JOIN user_ids u ON c.fingerprint = u.fingerprint
             WHERE LOWER(u.email) = ?1
             ORDER BY c.updated_at DESC",
        )?;

        let rows = stmt.query_map([&email_lower], |row| {
            let data: Vec<u8> = row.get(0)?;
            Ok(data)
        })?;

        let mut keys = Vec::new();
        for row in rows {
            let data = row?;
            if let Ok(info) = parse_key_bytes(&data, true) {
                keys.push(info);
            }
        }

        Ok(keys)
    }

    /// Get all secret keys.
    ///
    /// Returns only keys that contain secret key material
    /// (i.e., keys you own and can use for signing/decryption).
    ///
    /// # Returns
    /// Keys with secret key material.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wecanencrypt::KeyStore;
    ///
    /// let store = KeyStore::open("keys.db").unwrap();
    ///
    /// println!("Your keys:");
    /// for key in store.list_secret_keys().unwrap() {
    ///     println!("  {} - {:?}", key.fingerprint, key.user_ids);
    /// }
    /// ```
    pub fn list_secret_keys(&self) -> Result<Vec<KeyInfo>> {
        let mut stmt = self
            .conn
            .prepare("SELECT key_data FROM keys WHERE is_secret = 1 ORDER BY updated_at DESC")?;

        let rows = stmt.query_map([], |row| {
            let data: Vec<u8> = row.get(0)?;
            Ok(data)
        })?;

        let mut keys = Vec::new();
        for row in rows {
            let data = row?;
            if let Ok(info) = parse_key_bytes(&data, true) {
                keys.push(info);
            }
        }

        Ok(keys)
    }

    /// Get all public-only keys.
    ///
    /// Returns only keys that contain only public key material
    /// (i.e., other people's keys that you can use for encryption/verification).
    ///
    /// # Returns
    /// Keys with only public key material.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wecanencrypt::KeyStore;
    ///
    /// let store = KeyStore::open("keys.db").unwrap();
    ///
    /// println!("Contacts:");
    /// for key in store.list_public_keys().unwrap() {
    ///     println!("  {} - {:?}", key.fingerprint, key.user_ids);
    /// }
    /// ```
    pub fn list_public_keys(&self) -> Result<Vec<KeyInfo>> {
        let mut stmt = self
            .conn
            .prepare("SELECT key_data FROM keys WHERE is_secret = 0 ORDER BY updated_at DESC")?;

        let rows = stmt.query_map([], |row| {
            let data: Vec<u8> = row.get(0)?;
            Ok(data)
        })?;

        let mut keys = Vec::new();
        for row in rows {
            let data = row?;
            if let Ok(info) = parse_key_bytes(&data, true) {
                keys.push(info);
            }
        }

        Ok(keys)
    }

    /// Update a key.
    ///
    /// Replaces an existing key with new data. The fingerprint must
    /// match the existing key. Use this when you've modified a
    /// key (added user IDs, updated expiry, etc.).
    ///
    /// # Arguments
    /// * `fingerprint` - The key fingerprint (must match existing)
    /// * `key_data` - The updated key data
    ///
    /// # Errors
    /// - `Error::KeyNotFound` if no key exists with the fingerprint
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
    /// let key_data = store.export_key("ABCD1234...").unwrap();
    ///
    /// // Add a new user ID
    /// let updated = add_uid(&key_data, "New Name <new@example.com>", "password").unwrap();
    ///
    /// // Update the stored key
    /// store.update_key("ABCD1234...", &updated).unwrap();
    /// ```
    pub fn update_key(&self, fingerprint: &str, key_data: &[u8]) -> Result<()> {
        if !self.contains(fingerprint)? {
            return Err(Error::KeyNotFound(fingerprint.to_string()));
        }

        // Re-import (which will update)
        let new_fp = self.import_key(key_data)?;

        if new_fp != fingerprint {
            return Err(Error::InvalidInput(format!(
                "Key fingerprint mismatch: expected {}, got {}",
                fingerprint, new_fp
            )));
        }

        Ok(())
    }

    /// Get key count.
    ///
    /// Returns the total number of keys in the store.
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
            .query_row("SELECT COUNT(*) FROM keys", [], |row| row.get(0))?;
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

    /// Find key by key ID.
    ///
    /// Searches for a key by the key ID of its primary key or any
    /// subkey. Key IDs are the last 16 hex characters of a fingerprint.
    ///
    /// # Arguments
    /// * `key_id` - The key ID to search for (hex string)
    ///
    /// # Returns
    /// The key data if found, or `None` if not found.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wecanencrypt::KeyStore;
    ///
    /// let store = KeyStore::open("keys.db").unwrap();
    ///
    /// // Find by key ID (last 16 chars of fingerprint)
    /// if let Some(key) = store.find_by_key_id("ABCD1234EFGH5678").unwrap() {
    ///     println!("Found key");
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
                let data = self.export_key(&fp)?;
                Ok(Some(data))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Find key by subkey fingerprint.
    ///
    /// Searches for a key that contains a subkey with the given
    /// fingerprint. This is useful when a signature's issuer is a subkey
    /// rather than the primary key.
    ///
    /// # Arguments
    /// * `subkey_fp` - The subkey fingerprint to search for (hex string)
    ///
    /// # Returns
    /// The key data if found, or `None` if not found.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wecanencrypt::KeyStore;
    ///
    /// let store = KeyStore::open("keys.db").unwrap();
    ///
    /// // Find by subkey fingerprint
    /// if let Some(key) = store.find_by_subkey_fingerprint("ABCD1234...").unwrap() {
    ///     println!("Found parent key");
    /// }
    /// ```
    pub fn find_by_subkey_fingerprint(&self, subkey_fp: &str) -> Result<Option<Vec<u8>>> {
        let result: std::result::Result<String, _> = self.conn.query_row(
            "SELECT fingerprint FROM subkeys WHERE subkey_fingerprint = ?1",
            [subkey_fp],
            |row| row.get(0),
        );

        match result {
            Ok(fp) => {
                let data = self.export_key(&fp)?;
                Ok(Some(data))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Save a card-key association.
    ///
    /// Records that a specific card slot holds a key belonging to a key.
    /// Uses INSERT OR REPLACE on (card_ident, slot) so repeated calls update
    /// the `last_seen` timestamp.
    ///
    /// # Arguments
    ///
    /// * `key_fingerprint` - Fingerprint of the key (must exist in the store)
    /// * `card_ident` - Card identifier ("MANUFACTURER:SERIAL")
    /// * `card_serial` - Card serial number (hex)
    /// * `card_manufacturer` - Human-readable manufacturer name
    /// * `slot` - Slot name: "signature", "encryption", or "authentication"
    /// * `slot_fingerprint` - Fingerprint of the key in this card slot
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wecanencrypt::{create_key_simple, KeyStore};
    ///
    /// let store = KeyStore::open_in_memory().unwrap();
    /// let key = create_key_simple("password", &["Alice <alice@example.com>"]).unwrap();
    /// let fingerprint = store.import_key(&key.secret_key).unwrap();
    ///
    /// store.save_card_key(
    ///     &fingerprint,
    ///     "0006:00000001",
    ///     "00000001",
    ///     Some("Yubico"),
    ///     "signature",
    ///     &fingerprint,
    /// ).unwrap();
    /// ```
    pub fn save_card_key(
        &self,
        key_fingerprint: &str,
        card_ident: &str,
        card_serial: &str,
        card_manufacturer: Option<&str>,
        slot: &str,
        slot_fingerprint: &str,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO card_keys
                (fingerprint, card_ident, card_serial, card_manufacturer, slot, slot_fingerprint, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, CURRENT_TIMESTAMP)",
            params![key_fingerprint, card_ident, card_serial, card_manufacturer, slot, slot_fingerprint],
        )?;
        Ok(())
    }

    /// Get all card associations for a key.
    ///
    /// Returns information about which smart card slots hold keys belonging
    /// to the given key.
    ///
    /// # Arguments
    ///
    /// * `key_fingerprint` - Fingerprint of the key
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wecanencrypt::{create_key_simple, KeyStore};
    ///
    /// let store = KeyStore::open_in_memory().unwrap();
    /// let key = create_key_simple("password", &["Alice <alice@example.com>"]).unwrap();
    /// let fingerprint = store.import_key(&key.secret_key).unwrap();
    ///
    /// store.save_card_key(&fingerprint, "0006:00000001", "00000001", None, "signature", &fingerprint).unwrap();
    /// let cards = store.get_card_keys(&fingerprint).unwrap();
    /// assert_eq!(cards.len(), 1);
    /// ```
    pub fn get_card_keys(&self, key_fingerprint: &str) -> Result<Vec<StoredCardKey>> {
        let mut stmt = self.conn.prepare(
            "SELECT card_ident, card_serial, card_manufacturer, slot, slot_fingerprint, last_seen
             FROM card_keys WHERE fingerprint = ?1
             ORDER BY card_ident, slot",
        )?;

        let rows = stmt.query_map([key_fingerprint], |row| {
            Ok(StoredCardKey {
                card_ident: row.get(0)?,
                card_serial: row.get(1)?,
                card_manufacturer: row.get(2)?,
                slot: row.get(3)?,
                slot_fingerprint: row.get(4)?,
                last_seen: row.get(5)?,
            })
        })?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    /// Remove all card associations for a specific card.
    ///
    /// # Arguments
    ///
    /// * `card_ident` - Card identifier ("MANUFACTURER:SERIAL")
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wecanencrypt::{create_key_simple, KeyStore};
    ///
    /// let store = KeyStore::open_in_memory().unwrap();
    /// let key = create_key_simple("password", &["Alice <alice@example.com>"]).unwrap();
    /// let fingerprint = store.import_key(&key.secret_key).unwrap();
    ///
    /// store.save_card_key(&fingerprint, "0006:00000001", "00000001", None, "signature", &fingerprint).unwrap();
    /// store.remove_card_keys_for_card("0006:00000001").unwrap();
    /// assert!(store.get_card_keys(&fingerprint).unwrap().is_empty());
    /// ```
    pub fn remove_card_keys_for_card(&self, card_ident: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM card_keys WHERE card_ident = ?1", [card_ident])?;
        Ok(())
    }

    /// Return every row in the `card_keys` table in a single query.
    ///
    /// Equivalent to calling [`KeyStore::get_card_keys`] for every key in
    /// the store, but uses one SQL round-trip instead of N. Intended
    /// for callers that need a fingerprint→cards map - e.g. the
    /// desktop key-list view - so they avoid the N+1 pattern that
    /// otherwise falls out of per-key lookups.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wecanencrypt::{create_key_simple, KeyStore};
    ///
    /// let store = KeyStore::open_in_memory().unwrap();
    /// let key = create_key_simple("password", &["Alice <alice@example.com>"]).unwrap();
    /// let fingerprint = store.import_key(&key.secret_key).unwrap();
    /// store.save_card_key(&fingerprint, "0006:00000001", "00000001", None, "signature", &fingerprint).unwrap();
    ///
    /// let rows = store.list_all_card_keys().unwrap();
    /// assert_eq!(rows[0].0, fingerprint);
    /// ```
    pub fn list_all_card_keys(&self) -> Result<Vec<(String, StoredCardKey)>> {
        let mut stmt = self.conn.prepare(
            "SELECT fingerprint, card_ident, card_serial, card_manufacturer,
                    slot, slot_fingerprint, last_seen
             FROM card_keys
             ORDER BY fingerprint, card_ident, slot",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                StoredCardKey {
                    card_ident: row.get(1)?,
                    card_serial: row.get(2)?,
                    card_manufacturer: row.get(3)?,
                    slot: row.get(4)?,
                    slot_fingerprint: row.get(5)?,
                    last_seen: row.get(6)?,
                },
            ))
        })?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    /// List every key in the store as a lightweight [`KeySummary`].
    ///
    /// Unlike [`KeyStore::list_keys`], this does **not** re-parse the
    /// OpenPGP blob on every row. All fields are read directly from
    /// normalized SQL columns populated at import time (or by the
    /// schema v4 backfill for rows predating that migration). Use
    /// this for list / gallery views where the caller does not need
    /// the full signature graph; call [`KeyStore::get_key_info`] only
    /// when the user drills into a specific key.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wecanencrypt::{create_key_simple, KeyStore};
    ///
    /// let store = KeyStore::open_in_memory().unwrap();
    /// let key = create_key_simple("password", &["Alice <alice@example.com>"]).unwrap();
    /// store.import_key(&key.secret_key).unwrap();
    ///
    /// let summaries = store.list_keys_summary().unwrap();
    /// assert_eq!(summaries.len(), 1);
    /// assert_eq!(summaries[0].primary_uid.as_deref(), Some("Alice <alice@example.com>"));
    /// ```
    pub fn list_keys_summary(&self) -> Result<Vec<KeySummary>> {
        // 1) Primary-row columns.
        let mut stmt = self.conn.prepare(
            "SELECT fingerprint, is_secret, primary_uid,
                    cert_created_at, expiration_time, is_revoked, revocation_time
             FROM keys
             ORDER BY updated_at DESC",
        )?;
        #[allow(clippy::type_complexity)]
        let primaries: Vec<(
            String,
            i32,
            Option<String>,
            Option<String>,
            Option<String>,
            i32,
            Option<String>,
        )> = stmt
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(stmt);

        if primaries.is_empty() {
            return Ok(Vec::new());
        }

        // 2) All user_ids rows in one sweep, grouped by fingerprint.
        let mut uids_by_fp: std::collections::HashMap<String, Vec<UserIdSummary>> =
            std::collections::HashMap::new();
        let mut stmt = self
            .conn
            .prepare("SELECT fingerprint, uid, email FROM user_ids ORDER BY fingerprint, id")?;
        for row in stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })? {
            let (fp, uid, email) = row?;
            uids_by_fp
                .entry(fp)
                .or_default()
                .push(UserIdSummary { uid, email });
        }
        drop(stmt);

        // 3) All subkey rows in one sweep, grouped by fingerprint.
        let mut subkeys_by_fp: std::collections::HashMap<String, Vec<SubkeySummary>> =
            std::collections::HashMap::new();
        let mut stmt = self.conn.prepare(
            "SELECT fingerprint, subkey_fingerprint, key_id, key_type,
                    algorithm, bit_length
             FROM subkeys
             ORDER BY fingerprint, id",
        )?;
        for row in stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<i64>>(5)?,
            ))
        })? {
            let (fp, subkey_fp, key_id, key_type, algorithm, bit_length) = row?;
            subkeys_by_fp.entry(fp).or_default().push(SubkeySummary {
                fingerprint: subkey_fp,
                key_id,
                key_type,
                algorithm,
                bit_length: bit_length.map(|n| n as usize),
            });
        }
        drop(stmt);

        // 4) Assemble.
        let mut out = Vec::with_capacity(primaries.len());
        for (
            fingerprint,
            is_secret,
            primary_uid,
            cert_created_at,
            expiration_time,
            is_revoked,
            revocation_time,
        ) in primaries
        {
            let user_ids = uids_by_fp.remove(&fingerprint).unwrap_or_default();
            let subkeys = subkeys_by_fp.remove(&fingerprint).unwrap_or_default();
            out.push(KeySummary {
                fingerprint,
                is_secret: is_secret != 0,
                primary_uid,
                user_ids,
                subkeys,
                creation_time: cert_created_at.and_then(parse_rfc3339_utc),
                expiration_time: expiration_time.and_then(parse_rfc3339_utc),
                is_revoked: is_revoked != 0,
                revocation_time: revocation_time.and_then(parse_rfc3339_utc),
            });
        }
        Ok(out)
    }

    /// Fetch a single [`KeySummary`] by fingerprint. Same payload as
    /// one entry of [`KeyStore::list_keys_summary`], scoped to a
    /// single row.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use wecanencrypt::{create_key_simple, KeyStore};
    ///
    /// let store = KeyStore::open_in_memory().unwrap();
    /// let key = create_key_simple("password", &["Alice <alice@example.com>"]).unwrap();
    /// let fingerprint = store.import_key(&key.secret_key).unwrap();
    ///
    /// let summary = store.get_key_summary(&fingerprint).unwrap();
    /// assert_eq!(summary.fingerprint, fingerprint);
    /// ```
    pub fn get_key_summary(&self, fingerprint: &str) -> Result<KeySummary> {
        let primary: (
            i32,
            Option<String>,
            Option<String>,
            Option<String>,
            i32,
            Option<String>,
        ) = self
            .conn
            .query_row(
                "SELECT is_secret, primary_uid,
                        cert_created_at, expiration_time, is_revoked, revocation_time
                 FROM keys WHERE fingerprint = ?1",
                [fingerprint],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Error::KeyNotFound(fingerprint.to_string()),
                other => other.into(),
            })?;

        let mut uid_stmt = self
            .conn
            .prepare("SELECT uid, email FROM user_ids WHERE fingerprint = ?1 ORDER BY id")?;
        let user_ids: Vec<UserIdSummary> = uid_stmt
            .query_map([fingerprint], |row| {
                Ok(UserIdSummary {
                    uid: row.get(0)?,
                    email: row.get(1)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(uid_stmt);

        let mut sk_stmt = self.conn.prepare(
            "SELECT subkey_fingerprint, key_id, key_type, algorithm, bit_length
             FROM subkeys WHERE fingerprint = ?1 ORDER BY id",
        )?;
        let subkeys: Vec<SubkeySummary> = sk_stmt
            .query_map([fingerprint], |row| {
                let bit_length: Option<i64> = row.get(4)?;
                Ok(SubkeySummary {
                    fingerprint: row.get(0)?,
                    key_id: row.get(1)?,
                    key_type: row.get(2)?,
                    algorithm: row.get(3)?,
                    bit_length: bit_length.map(|n| n as usize),
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(sk_stmt);

        let (is_secret, primary_uid, cert_created_at, expiration_time, is_revoked, revocation_time) =
            primary;
        Ok(KeySummary {
            fingerprint: fingerprint.to_string(),
            is_secret: is_secret != 0,
            primary_uid,
            user_ids,
            subkeys,
            creation_time: cert_created_at.and_then(parse_rfc3339_utc),
            expiration_time: expiration_time.and_then(parse_rfc3339_utc),
            is_revoked: is_revoked != 0,
            revocation_time: revocation_time.and_then(parse_rfc3339_utc),
        })
    }
}

/// Parse an RFC 3339 timestamp string into a UTC `DateTime`. Returns
/// `None` on parse failure - v4-backfilled rows should always produce
/// valid timestamps, but a defensive None keeps one bad cache entry
/// from corrupting the whole list.
fn parse_rfc3339_utc(s: String) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(&s)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

/// A card-key association stored in the keystore.
#[derive(Debug, Clone)]
pub struct StoredCardKey {
    /// Card identifier ("MANUFACTURER:SERIAL")
    pub card_ident: String,
    /// Card serial number (hex)
    pub card_serial: String,
    /// Human-readable manufacturer name
    pub card_manufacturer: Option<String>,
    /// Slot name: "signature", "encryption", or "authentication"
    pub slot: String,
    /// Fingerprint of the key stored in this card slot (lowercase hex)
    pub slot_fingerprint: String,
    /// Timestamp when this association was last observed
    pub last_seen: String,
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
    let key_data = store.export_key(recipient_fingerprint)?;
    crate::encrypt::encrypt_bytes(&key_data, plaintext, armor)
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
    let keys: Vec<Vec<u8>> = recipient_fingerprints
        .iter()
        .map(|fp| store.export_key(fp))
        .collect::<Result<Vec<_>>>()?;

    let key_refs: Vec<&[u8]> = keys.iter().map(|c| c.as_slice()).collect();
    crate::encrypt::encrypt_bytes_to_multiple(&key_refs, plaintext, armor)
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
    let key_data = store.export_key(secret_key_fingerprint)?;
    crate::decrypt::decrypt_bytes(&key_data, ciphertext, password)
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
    let key_data = store.export_key(signer_fingerprint)?;
    crate::sign::sign_bytes(&key_data, data, password)
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
    let key_data = store.export_key(signer_fingerprint)?;
    crate::sign::sign_bytes_detached(&key_data, data, password)
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
    let key_data = store.export_key(signer_fingerprint)?;
    crate::verify::verify_bytes(&key_data, signed_message)
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
    let key_data = store.export_key(signer_fingerprint)?;
    crate::verify::verify_bytes_detached(&key_data, data, signature)
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
    let key_data = store.export_key(recipient_fingerprint)?;
    crate::encrypt::encrypt_file(&key_data, input, output, armor)
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
    let keys: Vec<Vec<u8>> = recipient_fingerprints
        .iter()
        .map(|fp| store.export_key(fp))
        .collect::<Result<Vec<_>>>()?;

    let key_refs: Vec<&[u8]> = keys.iter().map(|c| c.as_slice()).collect();
    crate::encrypt::encrypt_file_to_multiple(&key_refs, input, output, armor)
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
    let key_data = store.export_key(secret_key_fingerprint)?;
    crate::decrypt::decrypt_file(&key_data, input, output, password)
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
    let key_data = store.export_key(signer_fingerprint)?;
    crate::sign::sign_file(&key_data, input, output, password)
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
    let key_data = store.export_key(signer_fingerprint)?;
    crate::sign::sign_file_detached(&key_data, input, password)
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
    let key_data = store.export_key(signer_fingerprint)?;
    crate::verify::verify_file(&key_data, input)
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
    let key_data = store.export_key(signer_fingerprint)?;
    let sig_data = std::fs::read(sig_file.as_ref())?;
    crate::verify::verify_file_detached(&key_data, data_file, &sig_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_uid_email() {
        assert_eq!(
            extract_uid_email("Alice <alice@example.com>"),
            Some("alice@example.com".to_string())
        );
        assert_eq!(
            extract_uid_email("bob@example.com"),
            Some("bob@example.com".to_string())
        );
        assert_eq!(extract_uid_email("Just a Name"), None);
        // Bracketed form with incidental whitespace around the address
        // must trim - otherwise the value won't match against the
        // address that lands in the autocrypt header.
        assert_eq!(
            extract_uid_email("Alice < alice@example.com >"),
            Some("alice@example.com".to_string())
        );
        // Bare-address form with surrounding whitespace must trim.
        assert_eq!(
            extract_uid_email("  alice@example.com  "),
            Some("alice@example.com".to_string())
        );
        // Display name contains a `>` before the bracketed address: the
        // closing `>` must be searched AFTER the opening `<`, not the
        // first `>` in the whole UID. A naive `uid.find('>')` lands
        // before `<` and misses the address entirely.
        assert_eq!(
            extract_uid_email("A>lice <alice@example.com>"),
            Some("alice@example.com".to_string())
        );
        // Brackets containing a non-email token must NOT be returned -
        // otherwise the keystore email index and Autocrypt address
        // comparisons would accept garbage like "Name <not_an_email>"
        // or "Name <addr with space>".
        assert_eq!(extract_uid_email("Name <not_an_email>"), None);
        assert_eq!(extract_uid_email("Name <addr with space>"), None);
        // Non-space whitespace inside the address (tab, newline, NBSP)
        // is also rejected - an addr-spec can't contain any of these,
        // and they'd otherwise pollute the keystore email index.
        assert_eq!(extract_uid_email("Name <alice@\texample.com>"), None);
        assert_eq!(extract_uid_email("Name <alice@\nexample.com>"), None);
        assert_eq!(extract_uid_email("alice@\texample.com"), None);
    }

    #[test]
    fn test_keystore_open_in_memory() {
        let store = KeyStore::open_in_memory().unwrap();
        assert!(store.path().is_none());
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn test_keystore_get_key() {
        use crate::create_key_simple;

        let store = KeyStore::open_in_memory().unwrap();

        // Generate and import a key
        let key = create_key_simple("testpass", &["Test User <test@example.com>"]).unwrap();
        let fp = store.import_key(&key.secret_key).unwrap();

        // Get key returns both data and info
        let (key_data, info) = store.get_key(&fp).unwrap();

        // Verify the info is correct
        assert_eq!(info.fingerprint, fp);
        assert!(info.is_secret);
        assert_eq!(info.user_ids.len(), 1);
        assert!(info.user_ids[0].value.contains("Test User"));

        // Verify the key_data matches what was imported
        let exported = store.export_key(&fp).unwrap();
        assert_eq!(key_data, exported);

        // Verify get_key_info returns same info
        let info2 = store.get_key_info(&fp).unwrap();
        assert_eq!(info.fingerprint, info2.fingerprint);
        assert_eq!(info.is_secret, info2.is_secret);
        assert_eq!(info.user_ids, info2.user_ids);
    }

    /// `list_keys_summary` must return the same set of fingerprints
    /// as `list_keys`, and for each key carry the creation time, at
    /// least one UID, and at least one subkey - all without parsing
    /// the OpenPGP blob.
    #[test]
    fn test_list_keys_summary_matches_list_keys() {
        use crate::create_key_simple;

        let store = KeyStore::open_in_memory().unwrap();
        let a = create_key_simple("pw1", &["Alice <alice@example.com>"]).unwrap();
        let b = create_key_simple("pw2", &["Bob <bob@example.com>"]).unwrap();
        let fp_a = store.import_key(&a.secret_key).unwrap();
        let fp_b = store.import_key(&b.secret_key).unwrap();

        let summaries = store.list_keys_summary().unwrap();
        assert_eq!(summaries.len(), 2);
        let fps: std::collections::HashSet<_> =
            summaries.iter().map(|s| s.fingerprint.clone()).collect();
        assert!(fps.contains(&fp_a));
        assert!(fps.contains(&fp_b));

        for s in &summaries {
            assert!(s.creation_time.is_some(), "creation_time must be cached");
            assert!(!s.user_ids.is_empty(), "user_ids must not be empty");
            assert!(!s.subkeys.is_empty(), "subkeys must not be empty");
            // Every subkey row should carry cached algorithm+bit_length.
            for sk in &s.subkeys {
                assert!(sk.algorithm.is_some(), "algorithm cached");
                assert!(sk.bit_length.is_some(), "bit_length cached");
            }
        }

        // Single-key getter must agree with the list form.
        let one = store.get_key_summary(&fp_a).unwrap();
        assert_eq!(one.fingerprint, fp_a);
        assert!(one.user_ids.iter().any(|u| u.uid.contains("Alice")));
    }

    /// `list_all_card_keys` must return the same rows as calling
    /// `get_card_keys` for every fingerprint, in one query instead of
    /// N. This is what kills the desktop list view's per-key round
    /// trip.
    #[test]
    fn test_list_all_card_keys_matches_per_key_lookup() {
        use crate::create_key_simple;

        let store = KeyStore::open_in_memory().unwrap();
        let a = create_key_simple("pw1", &["Alice <a@x.org>"]).unwrap();
        let b = create_key_simple("pw2", &["Bob <b@x.org>"]).unwrap();
        let fp_a = store.import_key(&a.secret_key).unwrap();
        let fp_b = store.import_key(&b.secret_key).unwrap();

        // Link both keys to card slots.
        store
            .save_card_key(&fp_a, "FOO:1111", "1111", Some("Foo"), "signature", "SIGA")
            .unwrap();
        store
            .save_card_key(&fp_a, "FOO:1111", "1111", Some("Foo"), "encryption", "ENCA")
            .unwrap();
        store
            .save_card_key(&fp_b, "BAR:2222", "2222", Some("Bar"), "signature", "SIGB")
            .unwrap();

        // Reference: per-key lookup.
        let a_rows = store.get_card_keys(&fp_a).unwrap();
        let b_rows = store.get_card_keys(&fp_b).unwrap();
        assert_eq!(a_rows.len(), 2);
        assert_eq!(b_rows.len(), 1);

        // Bulk lookup must agree.
        let all = store.list_all_card_keys().unwrap();
        let a_from_all: Vec<&StoredCardKey> = all
            .iter()
            .filter(|(fp, _)| fp == &fp_a)
            .map(|(_, c)| c)
            .collect();
        let b_from_all: Vec<&StoredCardKey> = all
            .iter()
            .filter(|(fp, _)| fp == &fp_b)
            .map(|(_, c)| c)
            .collect();
        assert_eq!(a_from_all.len(), 2);
        assert_eq!(b_from_all.len(), 1);
        assert_eq!(all.len(), 3);
    }

    /// Re-importing an already-stored key must NOT drop its card linkage
    /// (tumpa-cli#32). `card_keys` has `ON DELETE CASCADE` on the key's
    /// fingerprint; the old `INSERT OR REPLACE` storage path deleted the
    /// existing `keys` row before re-inserting, firing that cascade and
    /// silently wiping the card association on every `tcli import`. The
    /// UPSERT storage path updates in place, so the association survives.
    #[test]
    fn test_reimport_preserves_card_keys() {
        use crate::create_key_simple;

        let store = KeyStore::open_in_memory().unwrap();
        let key = create_key_simple("pw", &["Carol <c@x.org>"]).unwrap();
        let fp = store.import_key(&key.secret_key).unwrap();

        // Link the key to a card slot.
        store
            .save_card_key(&fp, "FOO:1111", "1111", Some("Foo"), "signature", "SIGC")
            .unwrap();
        assert_eq!(store.get_card_keys(&fp).unwrap().len(), 1);

        // Re-import the very same cert (the "Unchanged - no new data" path in
        // tcli always calls import_key). The card linkage must persist.
        let fp2 = store.import_key(&key.secret_key).unwrap();
        assert_eq!(fp2, fp);
        assert_eq!(
            store.get_card_keys(&fp).unwrap().len(),
            1,
            "re-import must not wipe card linkage"
        );

        // Re-importing the public-only cert over the secret one must also
        // preserve the linkage.
        store.import_key(key.public_key.as_bytes()).unwrap();
        assert_eq!(
            store.get_card_keys(&fp).unwrap().len(),
            1,
            "public re-import must not wipe card linkage"
        );
    }

    #[test]
    fn test_keystore_get_key_not_found() {
        let store = KeyStore::open_in_memory().unwrap();

        // Try to get a non-existent key
        let result = store.get_key("NONEXISTENT1234567890");
        assert!(result.is_err());
    }

    /// Import a key that carries a cryptographically valid self-revocation.
    /// The cached `is_revoked` flag must be set and `revocation_time`
    /// populated, proving that valid revocations still land in the cache.
    #[test]
    fn test_import_revoked_key_caches_is_revoked() {
        use crate::{create_key_simple, revoke_key};

        let store = KeyStore::open_in_memory().unwrap();
        let key = create_key_simple("pw", &["Rev <rev@example.com>"]).unwrap();
        let revoked = revoke_key(&key.secret_key, "pw").unwrap();
        let fp = store.import_key(&revoked).unwrap();

        let summary = store.get_key_summary(&fp).unwrap();
        assert!(
            summary.is_revoked,
            "valid self-revocation must flip the flag"
        );
        assert!(
            summary.revocation_time.is_some(),
            "revocation_time must be populated for a revoked key"
        );
    }

    /// A KeyRevocation packet whose signature was produced by a different
    /// key is NOT a real revocation. The keystore must ignore it - if it
    /// trusted the packet-type tag alone, an attacker who slipped a
    /// forged revocation into a stored or transmitted key could trick
    /// the UI into refusing to use a valid key.
    #[test]
    fn test_import_forged_revocation_rejected() {
        use crate::create_key_simple;
        use crate::internal::parse_key;
        use pgp::composed::{SignedKeyDetails, SignedSecretKey};
        use pgp::packet::{self, SignatureConfig, SignatureType, Subpacket, SubpacketData};
        use pgp::ser::Serialize;
        use pgp::types::{KeyDetails as _, KeyVersion, Password, Timestamp};
        use rand::thread_rng;

        // Victim key - the one we want to falsely mark as revoked.
        let victim = create_key_simple("pw_v", &["Victim <v@example.com>"]).unwrap();
        // Attacker key - signs a bogus revocation over the victim.
        let attacker = create_key_simple("pw_a", &["Attacker <a@example.com>"]).unwrap();

        // Parse victim as secret key (so we can reserialize it with the
        // spliced-in bogus signature) and attacker as secret key (to
        // produce the signature).
        let victim_secret: SignedSecretKey = {
            use pgp::composed::Deserializable;
            let (parsed, _) = SignedSecretKey::from_armor_single(&victim.secret_key[..])
                .or_else(|_| {
                    SignedSecretKey::from_bytes(&victim.secret_key[..])
                        .map(|k| (k, Default::default()))
                })
                .expect("parse victim");
            parsed
        };
        let attacker_secret: SignedSecretKey = {
            use pgp::composed::Deserializable;
            let (parsed, _) = SignedSecretKey::from_armor_single(&attacker.secret_key[..])
                .or_else(|_| {
                    SignedSecretKey::from_bytes(&attacker.secret_key[..])
                        .map(|k| (k, Default::default()))
                })
                .expect("parse attacker");
            parsed
        };

        // Forge: attacker signs a KeyRevocation packet. The content of
        // the signature doesn't matter - what matters is that the
        // issuer is the *attacker's* primary key, so verifying it
        // against the *victim's* primary key will fail.
        let mut rng = thread_rng();
        let mut config = SignatureConfig::from_key(
            &mut rng,
            &attacker_secret.primary_key,
            SignatureType::KeyRevocation,
        )
        .expect("config");
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now())).unwrap(),
            Subpacket::regular(SubpacketData::IssuerFingerprint(
                attacker_secret.primary_key.fingerprint(),
            ))
            .unwrap(),
        ];
        if attacker_secret.primary_key.version() <= KeyVersion::V4 {
            config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
                attacker_secret.primary_key.legacy_key_id(),
            ))
            .unwrap()];
        }
        let forged: packet::Signature = config
            .sign_key(
                &attacker_secret.primary_key,
                &Password::from("pw_a"),
                attacker_secret.primary_key.public_key(),
            )
            .expect("sign forged revocation");

        // Splice the forged signature into the victim's revocation list
        // and re-serialize the victim key.
        let mut sigs = victim_secret.details.revocation_signatures.clone();
        sigs.push(forged);
        let new_details = SignedKeyDetails::new(
            sigs,
            victim_secret.details.direct_signatures.clone(),
            victim_secret.details.users.clone(),
            victim_secret.details.user_attributes.clone(),
        );
        let tampered = SignedSecretKey::new(
            victim_secret.primary_key.clone(),
            new_details,
            victim_secret.public_subkeys.clone(),
            victim_secret.secret_subkeys.clone(),
        );
        let tampered_bytes = tampered.to_bytes().expect("serialize tampered");

        // Sanity: rpgp's parser did accept the forged packet into
        // `revocation_signatures` (this is the vulnerability we're
        // defending against - the unverified find() would have set
        // `is_revoked = 1`).
        let (parsed, _) = parse_key(&tampered_bytes).unwrap();
        assert!(
            !parsed.details.revocation_signatures.is_empty(),
            "forged KeyRevocation packet must be present in revocation_signatures"
        );

        // Import - the cache must NOT flag this as revoked, because
        // the forged signature does not verify against the victim's
        // primary key.
        let store = KeyStore::open_in_memory().unwrap();
        let fp = store.import_key(&tampered_bytes).unwrap();
        let summary = store.get_key_summary(&fp).unwrap();
        assert!(
            !summary.is_revoked,
            "forged revocation (wrong issuer) must not flip is_revoked"
        );
        assert!(
            summary.revocation_time.is_none(),
            "forged revocation must not populate revocation_time"
        );
    }

    /// When a key in the store is later replaced with a revoked version
    /// via `update_key`, the cached `is_revoked` column must refresh -
    /// otherwise a user who revokes a key would still see it as live
    /// in the summary view.
    #[test]
    fn test_update_key_refreshes_is_revoked() {
        use crate::{create_key_simple, revoke_key};

        let store = KeyStore::open_in_memory().unwrap();
        let key = create_key_simple("pw", &["U <u@example.com>"]).unwrap();
        let fp = store.import_key(&key.secret_key).unwrap();
        assert!(!store.get_key_summary(&fp).unwrap().is_revoked);

        let revoked = revoke_key(&key.secret_key, "pw").unwrap();
        store.update_key(&fp, &revoked).unwrap();

        let summary = store.get_key_summary(&fp).unwrap();
        assert!(
            summary.is_revoked,
            "cached flag must refresh after update_key"
        );
        assert!(summary.revocation_time.is_some());
    }
}
