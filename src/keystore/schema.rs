//! Database schema and migrations for the keystore.

use rusqlite::Connection;

/// Current schema version.
pub const SCHEMA_VERSION: u32 = 20251228;

/// Initialize the database schema.
pub fn init_schema(conn: &Connection) -> rusqlite::Result<()> {
    // Create version table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY
        )",
        [],
    )?;

    // Check current version
    let current_version: u32 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    if current_version < SCHEMA_VERSION {
        migrate(conn, current_version)?;
    }

    Ok(())
}

/// Run migrations from current version to latest.
fn migrate(conn: &Connection, from_version: u32) -> rusqlite::Result<()> {
    if from_version < 1 {
        migrate_v1(conn)?;
    }

    // Update version
    conn.execute("DELETE FROM schema_version", [])?;
    conn.execute(
        "INSERT INTO schema_version (version) VALUES (?1)",
        [SCHEMA_VERSION],
    )?;

    Ok(())
}

/// Migration to version 1 - initial schema.
fn migrate_v1(conn: &Connection) -> rusqlite::Result<()> {
    // Main certificates table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS certificates (
            fingerprint TEXT PRIMARY KEY,
            cert_data BLOB NOT NULL,
            is_secret INTEGER NOT NULL DEFAULT 0,
            primary_uid TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    )?;

    // User IDs table for searching
    conn.execute(
        "CREATE TABLE IF NOT EXISTS user_ids (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL,
            uid TEXT NOT NULL,
            email TEXT,
            FOREIGN KEY (fingerprint) REFERENCES certificates(fingerprint) ON DELETE CASCADE,
            UNIQUE(fingerprint, uid)
        )",
        [],
    )?;

    // Subkeys table for key ID lookups
    conn.execute(
        "CREATE TABLE IF NOT EXISTS subkeys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL,
            subkey_fingerprint TEXT NOT NULL UNIQUE,
            key_id TEXT NOT NULL,
            key_type TEXT NOT NULL,
            FOREIGN KEY (fingerprint) REFERENCES certificates(fingerprint) ON DELETE CASCADE
        )",
        [],
    )?;

    // Indexes for efficient searching
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_user_ids_email ON user_ids(email)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_user_ids_uid ON user_ids(uid)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_subkeys_key_id ON subkeys(key_id)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_certificates_is_secret ON certificates(is_secret)",
        [],
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_schema() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();

        // Verify tables exist
        let count: i32 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='certificates'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_schema_version() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();

        let version: u32 = conn
            .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }
}
