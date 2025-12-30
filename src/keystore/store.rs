//! KeyStore implementation.

use std::path::{Path, PathBuf};

use rusqlite::{params, Connection};

use crate::error::{Error, Result};
use crate::internal::{fingerprint_to_hex, keyid_to_hex, parse_cert, public_key_to_armored};
use crate::parse::parse_cert_bytes;
use crate::types::CertificateInfo;

use super::schema::init_schema;

/// SQLite-backed certificate storage.
pub struct KeyStore {
    conn: Connection,
    path: Option<PathBuf>,
}

impl KeyStore {
    /// Open or create a keystore at the given path.
    ///
    /// # Arguments
    /// * `path` - Path to the SQLite database file
    ///
    /// # Example
    /// ```ignore
    /// let store = KeyStore::open("~/.wecanencrypt/keys.db")?;
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

    /// Create an in-memory keystore (for testing).
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute("PRAGMA foreign_keys = ON", [])?;
        init_schema(&conn)?;

        Ok(Self { conn, path: None })
    }

    /// Import a certificate into the keystore.
    ///
    /// # Arguments
    /// * `cert_data` - Certificate data (armored or binary)
    ///
    /// # Returns
    /// The fingerprint of the imported certificate.
    pub fn import_cert(&self, cert_data: &[u8]) -> Result<String> {
        let (public_key, is_secret) = parse_cert(cert_data)?;
        let fingerprint = fingerprint_to_hex(&public_key.primary_key);

        // Get primary UID
        let primary_uid = public_key
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

        for user in &public_key.users {
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
                    sig.key_flags().map(|flags| {
                        if flags.encrypt_comms() || flags.encrypt_storage() {
                            "encryption"
                        } else if flags.sign() {
                            "signing"
                        } else if flags.authentication() {
                            "authentication"
                        } else {
                            "unknown"
                        }
                    })
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
    pub fn import_cert_file(&self, path: impl AsRef<Path>) -> Result<String> {
        let data = std::fs::read(path.as_ref())?;
        self.import_cert(&data)
    }

    /// Export a certificate by fingerprint.
    ///
    /// # Arguments
    /// * `fingerprint` - The certificate fingerprint
    ///
    /// # Returns
    /// The certificate data (binary).
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
    pub fn export_cert_armored(&self, fingerprint: &str) -> Result<String> {
        let data = self.export_cert(fingerprint)?;
        let (public_key, _) = parse_cert(&data)?;
        public_key_to_armored(&public_key)
    }

    /// Get certificate info by fingerprint.
    pub fn get_cert_info(&self, fingerprint: &str) -> Result<CertificateInfo> {
        let data = self.export_cert(fingerprint)?;
        parse_cert_bytes(&data, true)
    }

    /// Check if a key exists by fingerprint.
    pub fn contains(&self, fingerprint: &str) -> Result<bool> {
        let count: i32 = self.conn.query_row(
            "SELECT COUNT(*) FROM certificates WHERE fingerprint = ?1",
            [fingerprint],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Delete a certificate by fingerprint.
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
    pub fn count(&self) -> Result<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM certificates", [], |row| row.get(0))?;
        Ok(count as usize)
    }

    /// Get database path (None for in-memory).
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Find certificate by key ID.
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
pub fn verify_bytes_from_store(
    store: &KeyStore,
    signer_fingerprint: &str,
    signed_message: &[u8],
) -> Result<bool> {
    let cert_data = store.export_cert(signer_fingerprint)?;
    crate::verify::verify_bytes(&cert_data, signed_message)
}

/// Verify detached signature using a key from the store.
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
pub fn verify_file_from_store(
    store: &KeyStore,
    signer_fingerprint: &str,
    input: impl AsRef<std::path::Path>,
) -> Result<bool> {
    let cert_data = store.export_cert(signer_fingerprint)?;
    crate::verify::verify_file(&cert_data, input)
}

/// Verify a file with detached signature using a key from the store.
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
}
