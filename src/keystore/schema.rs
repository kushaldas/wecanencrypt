//! Database schema and migrations for the keystore.

use rusqlite::Connection;

/// Current schema version.
pub const SCHEMA_VERSION: u32 = 20260416;

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
    if from_version < 20260413 {
        migrate_v2(conn)?;
    }
    if from_version < 20260416 {
        migrate_v3(conn)?;
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
///
/// Creates the original `certificates` table with a `cert_data` column.
/// Migration v3 (2026-04-16) renames the table to `keys` and the column
/// to `key_data`; keep this v1 migration creating the legacy names so
/// that any fresh install still runs v1→v2→v3 in sequence and existing
/// v1/v2 installs migrate forward correctly.
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

/// Migration to version 2 - add card_keys table for card-key associations.
fn migrate_v2(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS card_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL,
            card_ident TEXT NOT NULL,
            card_serial TEXT NOT NULL,
            card_manufacturer TEXT,
            slot TEXT NOT NULL,
            slot_fingerprint TEXT NOT NULL,
            last_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (fingerprint) REFERENCES certificates(fingerprint) ON DELETE CASCADE,
            UNIQUE(card_ident, slot)
        )",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_card_keys_fingerprint ON card_keys(fingerprint)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_card_keys_card_ident ON card_keys(card_ident)",
        [],
    )?;

    Ok(())
}

/// Migration to version 3 (2026-04-16) — rename `certificates` table
/// to `keys` and its `cert_data` column to `key_data`. The term
/// "certificate" in this codebase used to be a synonym for an OpenPGP
/// key bundle; now "key" is used consistently and "certification"
/// refers only to the OpenPGP signature type. SQLite ≥ 3.26 updates
/// foreign-key references to the renamed table automatically.
///
/// A pre-existing `keys` table may be present from the legacy
/// johnnycanencrypt schema (carried across the v0→v1 migration as
/// dead weight — nothing in this codebase ever reads it). That
/// legacy table, identified by its `keyvalue` column, is dropped
/// along with its old UID helper tables before the rename.
///
/// Idempotency: the migration must be safe to re-run if a prior
/// attempt died between statements (process crash, I/O error, etc.)
/// and left `schema_version` un-bumped. We therefore (a) only drop
/// `keys` when it has the JCE shape, never when it is our own
/// post-rename table, and (b) only rename `certificates` when it
/// still exists. Wrapped in a transaction so either all steps land
/// or none do.
fn migrate_v3(conn: &Connection) -> rusqlite::Result<()> {
    // Prefer modern ALTER TABLE semantics: rewrite foreign-key
    // references (from `REFERENCES certificates(fingerprint)`) to
    // point at `keys(fingerprint)` automatically. No-op on SQLite
    // < 3.26 (the pragma is silently ignored there).
    conn.execute("PRAGMA legacy_alter_table = OFF", [])?;

    let keys_exists = table_exists(conn, "keys")?;
    let keys_is_legacy_jce = keys_exists && column_exists(conn, "keys", "keyvalue")?;
    let certificates_exists = table_exists(conn, "certificates")?;

    let mut stmts = String::from("BEGIN;\n");

    if keys_is_legacy_jce {
        stmts.push_str(
            "DROP TABLE IF EXISTS uidemails;\n\
             DROP TABLE IF EXISTS uidnames;\n\
             DROP TABLE IF EXISTS uiduris;\n\
             DROP TABLE IF EXISTS uidvalues;\n\
             DROP TABLE keys;\n",
        );
    }

    if certificates_exists {
        stmts.push_str("ALTER TABLE certificates RENAME TO keys;\n");
        stmts.push_str("ALTER TABLE keys RENAME COLUMN cert_data TO key_data;\n");
    }

    stmts.push_str(
        "DROP INDEX IF EXISTS idx_certificates_is_secret;\n\
         CREATE INDEX IF NOT EXISTS idx_keys_is_secret ON keys(is_secret);\n\
         COMMIT;\n",
    );

    conn.execute_batch(&stmts)?;
    Ok(())
}

fn table_exists(conn: &Connection, name: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
        [name],
        |row| row.get(0),
    )
}

fn column_exists(conn: &Connection, table: &str, column: &str) -> rusqlite::Result<bool> {
    // pragma_table_info is a table-valued function; the table name
    // cannot be bound as a parameter but is safely interpolated here
    // because callers only pass static identifiers.
    let sql = format!(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('{}') WHERE name=?1)",
        table.replace('\'', "''")
    );
    conn.query_row(&sql, [column], |row| row.get(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_schema() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();

        // Verify tables exist (schema v3 renamed `certificates` -> `keys`).
        let count: i32 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='keys'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);

        // The old `certificates` table name must not linger after migration.
        let legacy: i32 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='certificates'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(legacy, 0);
    }

    #[test]
    fn test_schema_upgrade_v2_to_v3() {
        // Build a v2 database by hand, then reopen via init_schema and
        // confirm the v3 migration renames the table and column without
        // losing data or FK integrity.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute("PRAGMA foreign_keys = ON", []).unwrap();
        migrate_v1(&conn).unwrap();
        migrate_v2(&conn).unwrap();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO schema_version (version) VALUES (?1)",
            [20260413u32],
        )
        .unwrap();

        // Seed a row via the legacy column name so we can verify
        // it survives the rename.
        conn.execute(
            "INSERT INTO certificates (fingerprint, cert_data, is_secret, primary_uid)
             VALUES ('ABCD', x'DEADBEEF', 0, 'alice')",
            [],
        )
        .unwrap();

        init_schema(&conn).unwrap();

        let data: Vec<u8> = conn
            .query_row(
                "SELECT key_data FROM keys WHERE fingerprint = 'ABCD'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(data, vec![0xDE, 0xAD, 0xBE, 0xEF]);

        let v: u32 = conn
            .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
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

    /// Regression: before the idempotency fix, `migrate_v3` unconditionally
    /// ran `DROP TABLE IF EXISTS keys` at the top of the batch. If a prior
    /// run had completed the `ALTER TABLE certificates RENAME TO keys` but
    /// died before `schema_version` was bumped, the retry would wipe the
    /// user's (already-migrated) keys table and then fail on the rename.
    /// The migration must be safe to re-run at any intermediate point.
    #[test]
    fn test_migrate_v3_idempotent_after_partial_retry() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute("PRAGMA foreign_keys = ON", []).unwrap();

        // Simulate a v2 DB that successfully ran ALTER TABLE and
        // RENAME COLUMN but never recorded a bumped schema_version
        // (e.g., crash between the batch and the version insert).
        migrate_v1(&conn).unwrap();
        migrate_v2(&conn).unwrap();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO schema_version (version) VALUES (?1)",
            [20260413u32],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO certificates (fingerprint, cert_data, is_secret, primary_uid)
             VALUES ('ABCD', x'DEADBEEF', 0, 'alice')",
            [],
        )
        .unwrap();

        // Hand-run the table rename + column rename (the part that
        // would have completed before the hypothetical crash), then
        // leave schema_version stuck at v2. The dropped legacy index
        // and new index are intentionally skipped to mimic a mid-batch
        // failure.
        conn.execute_batch(
            "ALTER TABLE certificates RENAME TO keys;\n\
             ALTER TABLE keys RENAME COLUMN cert_data TO key_data;",
        )
        .unwrap();
        assert_eq!(
            conn.query_row("SELECT version FROM schema_version", [], |row| row
                .get::<_, u32>(0))
                .unwrap(),
            20260413u32,
        );

        // Now init_schema runs again. The buggy pre-fix code would
        // DROP the `keys` table and fail on `ALTER TABLE certificates
        // RENAME TO keys` because `certificates` is gone. The fixed
        // code should no-op the drop (not a JCE legacy table), skip
        // the rename (`certificates` doesn't exist), create the
        // index, and bump the version.
        init_schema(&conn).unwrap();

        // Data must still be there.
        let data: Vec<u8> = conn
            .query_row(
                "SELECT key_data FROM keys WHERE fingerprint = 'ABCD'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(data, vec![0xDE, 0xAD, 0xBE, 0xEF]);

        // Schema version bumped.
        let version: u32 = conn
            .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);

        // Index exists.
        let idx_count: i32 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_keys_is_secret'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(idx_count, 1);

        // A third init_schema call must also be a no-op (fully idempotent).
        init_schema(&conn).unwrap();
        let data_again: Vec<u8> = conn
            .query_row(
                "SELECT key_data FROM keys WHERE fingerprint = 'ABCD'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(data_again, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    /// Companion check: after v2→v3 upgrade, foreign-key references in
    /// `user_ids` / `subkeys` / `card_keys` must point at the renamed
    /// `keys` table so ON DELETE CASCADE still fires. With
    /// `legacy_alter_table = ON` (SQLite default on some older builds)
    /// the FK refs would still name `certificates` and INSERTs against
    /// the new table would fail with obscure errors.
    #[test]
    fn test_migrate_v3_rewrites_foreign_keys() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute("PRAGMA foreign_keys = ON", []).unwrap();

        init_schema(&conn).unwrap();

        // INSERT into the renamed `keys` table, then into child tables
        // — the FKs must resolve to `keys(fingerprint)`.
        conn.execute(
            "INSERT INTO keys (fingerprint, key_data, is_secret, primary_uid)
             VALUES ('FEED', x'BEEF', 0, 'bob')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO user_ids (fingerprint, uid, email) VALUES ('FEED', 'bob', 'b@e.x')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO subkeys (fingerprint, subkey_fingerprint, key_id, key_type)
             VALUES ('FEED', 'SUBFEED', 'ID', 'signing')",
            [],
        )
        .unwrap();

        // And a FK-violating insert must be rejected.
        let bad = conn.execute(
            "INSERT INTO user_ids (fingerprint, uid, email)
             VALUES ('NOPE', 'x', 'x@x.x')",
            [],
        );
        assert!(
            bad.is_err(),
            "FK reference to keys(fingerprint) must reject unknown fingerprints"
        );

        // ON DELETE CASCADE still fires after the rename.
        conn.execute("DELETE FROM keys WHERE fingerprint = 'FEED'", [])
            .unwrap();
        let uid_count: i32 = conn
            .query_row("SELECT COUNT(*) FROM user_ids", [], |row| row.get(0))
            .unwrap();
        assert_eq!(uid_count, 0);
    }
}
