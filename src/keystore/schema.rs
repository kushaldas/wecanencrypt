//! Database schema and migrations for the keystore.

use pgp::types::KeyDetails;
use rusqlite::{params, Connection};

use crate::internal::{
    get_algorithm_name, get_key_bit_size, get_key_expiration, parse_key, system_time_to_datetime,
    verified_primary_revocation,
};

/// Current schema version.
///
/// - `20260421` (v4, 2026-04-21): cache summary-view fields on `keys`
///   (`is_revoked`, `revocation_time`, `expiration_time`,
///   `cert_created_at`) and on `subkeys` (`algorithm`, `bit_length`),
///   so callers that only need the list view can avoid re-parsing the
///   OpenPGP blob on every row.
pub const SCHEMA_VERSION: u32 = 20260421;

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
    if from_version < 20260421 {
        migrate_v4(conn)?;
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

/// Migration to version 3 (2026-04-16) - rename `certificates` table
/// to `keys` and its `cert_data` column to `key_data`. The term
/// "certificate" in this codebase used to be a synonym for an OpenPGP
/// key bundle; now "key" is used consistently and "certification"
/// refers only to the OpenPGP signature type. SQLite ≥ 3.26 updates
/// foreign-key references to the renamed table automatically.
///
/// A pre-existing `keys` table may be present from the legacy
/// johnnycanencrypt schema (carried across the v0→v1 migration as
/// dead weight - nothing in this codebase ever reads it). That
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

/// Migration to version 4 (2026-04-21) - cache summary-view fields so
/// callers that only need the list view can avoid re-parsing the
/// OpenPGP blob for every key.
///
/// Adds to `keys`:
/// - `is_revoked INTEGER NOT NULL DEFAULT 0`
/// - `revocation_time TEXT` (ISO-8601 UTC, nullable)
/// - `expiration_time TEXT` (ISO-8601 UTC, nullable)
/// - `cert_created_at TEXT` (the cert's primary-key creation
///   timestamp; distinct from `created_at`, which is the SQLite row
///   insert time)
///
/// Adds to `subkeys`:
/// - `algorithm TEXT` (e.g. `RSA`, `EdDSA`, `ECDH`)
/// - `bit_length INTEGER`
///
/// Backfill: for each existing row, parse the blob once and populate
/// the new columns. If a row fails to parse (corrupt blob, unknown
/// algorithm, etc.) we skip it - the columns stay NULL/default, and
/// downstream summary readers should treat NULL as "unknown" rather
/// than bailing. This keeps the migration from turning a cold app
/// start into a hard failure because of one bad key.
///
/// Idempotency: `ALTER TABLE … ADD COLUMN` errors if the column
/// already exists, so we gate each add on `column_exists`. The
/// backfill is rerun regardless; populating already-populated columns
/// is a no-op.
///
/// Atomicity: wrapped in a single transaction (matching `migrate_v3`)
/// so a crash mid-migration leaves the database either fully upgraded
/// or fully untouched, not in a partial state where some rows are
/// backfilled and others aren't.
fn migrate_v4(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute("BEGIN", [])?;
    if let Err(e) = migrate_v4_body(conn) {
        // Best-effort rollback; if ROLLBACK itself fails there's
        // nothing useful we can do, so return the original error.
        let _ = conn.execute("ROLLBACK", []);
        return Err(e);
    }
    conn.execute("COMMIT", [])?;
    Ok(())
}

fn migrate_v4_body(conn: &Connection) -> rusqlite::Result<()> {
    // Keys-table columns.
    if !column_exists(conn, "keys", "is_revoked")? {
        conn.execute(
            "ALTER TABLE keys ADD COLUMN is_revoked INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    if !column_exists(conn, "keys", "revocation_time")? {
        conn.execute("ALTER TABLE keys ADD COLUMN revocation_time TEXT", [])?;
    }
    if !column_exists(conn, "keys", "expiration_time")? {
        conn.execute("ALTER TABLE keys ADD COLUMN expiration_time TEXT", [])?;
    }
    if !column_exists(conn, "keys", "cert_created_at")? {
        conn.execute("ALTER TABLE keys ADD COLUMN cert_created_at TEXT", [])?;
    }

    // Subkeys-table columns.
    if !column_exists(conn, "subkeys", "algorithm")? {
        conn.execute("ALTER TABLE subkeys ADD COLUMN algorithm TEXT", [])?;
    }
    if !column_exists(conn, "subkeys", "bit_length")? {
        conn.execute("ALTER TABLE subkeys ADD COLUMN bit_length INTEGER", [])?;
    }

    backfill_v4(conn)?;
    Ok(())
}

/// Backfill the v4 columns by parsing each stored blob once. Unparseable
/// rows are skipped (a log line is the only side-effect) so a single
/// corrupt key can't block the migration.
fn backfill_v4(conn: &Connection) -> rusqlite::Result<()> {
    let mut stmt = conn.prepare("SELECT fingerprint, key_data FROM keys")?;
    let rows: Vec<(String, Vec<u8>)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .filter_map(|r| r.ok())
        .collect();
    drop(stmt);

    for (fingerprint, key_data) in rows {
        let (public_key, _is_secret) = match parse_key(&key_data) {
            Ok(pk) => pk,
            Err(e) => {
                log::warn!(
                    "v4 backfill: skipping unparseable key {}: {}",
                    fingerprint,
                    e
                );
                continue;
            }
        };

        // Primary key: creation + expiration + revocation.
        let cert_created_at =
            system_time_to_datetime(public_key.primary_key.created_at().into()).to_rfc3339();

        let expiration_time = get_key_expiration(&public_key)
            .map(system_time_to_datetime)
            .map(|dt| dt.to_rfc3339());

        // Verify the revocation signature cryptographically - rpgp parses
        // KeyRevocation packets into `revocation_signatures` without
        // verifying them, so a forged packet in a stored blob would
        // otherwise flip `is_revoked` to 1 on backfill.
        let revocation_sig = verified_primary_revocation(&public_key);
        let is_revoked = revocation_sig.is_some();
        let revocation_time = revocation_sig.and_then(|sig| sig.created()).map(|ts| {
            let st: std::time::SystemTime = ts.into();
            system_time_to_datetime(st).to_rfc3339()
        });

        conn.execute(
            "UPDATE keys
               SET is_revoked       = ?1,
                   revocation_time  = ?2,
                   expiration_time  = ?3,
                   cert_created_at  = ?4
             WHERE fingerprint = ?5",
            params![
                is_revoked as i32,
                revocation_time,
                expiration_time,
                cert_created_at,
                &fingerprint,
            ],
        )?;

        // Subkeys: algorithm + bit_length. Primary is also stored in
        // `subkeys` (with key_type = 'certification' per import_key),
        // so patch that row too.
        let primary_algorithm = get_algorithm_name(&public_key.primary_key);
        let primary_bit_length = get_key_bit_size(&public_key.primary_key) as i64;
        conn.execute(
            "UPDATE subkeys SET algorithm = ?1, bit_length = ?2
              WHERE fingerprint = ?3 AND subkey_fingerprint = ?3",
            params![&primary_algorithm, primary_bit_length, &fingerprint],
        )?;

        for subkey in &public_key.public_subkeys {
            let subkey_fp = crate::internal::fingerprint_to_hex(&subkey.key);
            let algorithm = get_algorithm_name(&subkey.key);
            let bit_length = get_key_bit_size(&subkey.key) as i64;
            conn.execute(
                "UPDATE subkeys SET algorithm = ?1, bit_length = ?2
                  WHERE subkey_fingerprint = ?3",
                params![&algorithm, bit_length, &subkey_fp],
            )?;
        }
    }

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

    /// v4 adds summary-view columns (`is_revoked`, `revocation_time`,
    /// `expiration_time`, `cert_created_at` on `keys`; `algorithm`,
    /// `bit_length` on `subkeys`). The migration must add the columns
    /// on top of a pre-existing v3 database AND backfill every row
    /// that was imported before v4 existed - otherwise the summary
    /// reader would see NULL columns for legacy rows.
    #[test]
    fn test_migrate_v4_adds_columns_and_backfills() {
        use crate::create_key_simple;

        let conn = Connection::open_in_memory().unwrap();
        conn.execute("PRAGMA foreign_keys = ON", []).unwrap();

        // Stand up a v1→v2→v3 database by hand so the test controls
        // exactly where the pre-v4 starting point is, then mark it at
        // v3 so v4 (and only v4) runs on the next init.
        migrate_v1(&conn).unwrap();
        migrate_v2(&conn).unwrap();
        migrate_v3(&conn).unwrap();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY)",
            [],
        )
        .unwrap();
        conn.execute("DELETE FROM schema_version", []).unwrap();
        conn.execute(
            "INSERT INTO schema_version (version) VALUES (?1)",
            [20260416u32],
        )
        .unwrap();

        // Insert a legacy key via the raw SQL path - mimicking a row
        // that was written by an older binary before v4 existed, so
        // the new columns are NULL/default.
        let generated = create_key_simple("testpass", &["Alice <alice@example.com>"]).unwrap();
        let (public_key, _) = parse_key(&generated.secret_key).unwrap();
        let fingerprint = crate::internal::fingerprint_to_hex(&public_key.primary_key);
        let secret_bytes: Vec<u8> = generated.secret_key.to_vec();
        conn.execute(
            "INSERT INTO keys (fingerprint, key_data, is_secret, primary_uid)
             VALUES (?1, ?2, 1, ?3)",
            params![&fingerprint, &secret_bytes, "Alice <alice@example.com>"],
        )
        .unwrap();
        // Minimal subkeys row so we can check the algorithm backfill.
        let primary_key_id = crate::internal::keyid_to_hex(&public_key.primary_key);
        conn.execute(
            "INSERT INTO subkeys (fingerprint, subkey_fingerprint, key_id, key_type)
             VALUES (?1, ?1, ?2, 'certification')",
            params![&fingerprint, &primary_key_id],
        )
        .unwrap();
        for subkey in &public_key.public_subkeys {
            let subkey_fp = crate::internal::fingerprint_to_hex(&subkey.key);
            let key_id = crate::internal::keyid_to_hex(&subkey.key);
            conn.execute(
                "INSERT INTO subkeys (fingerprint, subkey_fingerprint, key_id, key_type)
                 VALUES (?1, ?2, ?3, 'encryption')",
                params![&fingerprint, &subkey_fp, &key_id],
            )
            .unwrap();
        }

        // Run the full migration machinery - it should see v3 and run
        // v4 forward without re-running v1/v2/v3.
        init_schema(&conn).unwrap();

        // New columns exist.
        assert!(column_exists(&conn, "keys", "is_revoked").unwrap());
        assert!(column_exists(&conn, "keys", "revocation_time").unwrap());
        assert!(column_exists(&conn, "keys", "expiration_time").unwrap());
        assert!(column_exists(&conn, "keys", "cert_created_at").unwrap());
        assert!(column_exists(&conn, "subkeys", "algorithm").unwrap());
        assert!(column_exists(&conn, "subkeys", "bit_length").unwrap());

        // Legacy row was backfilled.
        let (is_revoked, cert_created_at): (i32, Option<String>) = conn
            .query_row(
                "SELECT is_revoked, cert_created_at FROM keys WHERE fingerprint = ?1",
                [&fingerprint],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(is_revoked, 0);
        assert!(
            cert_created_at.is_some(),
            "v4 backfill must populate cert_created_at for legacy rows"
        );

        // And the subkey rows got algorithm/bit_length too.
        let populated: i32 = conn
            .query_row(
                "SELECT COUNT(*) FROM subkeys
                 WHERE fingerprint = ?1 AND algorithm IS NOT NULL AND bit_length IS NOT NULL",
                [&fingerprint],
                |row| row.get(0),
            )
            .unwrap();
        let total: i32 = conn
            .query_row(
                "SELECT COUNT(*) FROM subkeys WHERE fingerprint = ?1",
                [&fingerprint],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(populated, total, "all subkey rows must be backfilled");

        // Schema version bumped.
        let v: u32 = conn
            .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
    }

    /// After v4, a fresh `import_key` must populate the summary
    /// columns inline so the summary reader never encounters NULLs on
    /// new rows.
    #[test]
    fn test_import_key_populates_v4_columns() {
        use crate::create_key_simple;
        use crate::KeyStore;

        let store = KeyStore::open_in_memory().unwrap();
        let key = create_key_simple("pw", &["Bob <bob@example.com>"]).unwrap();
        let fp = store.import_key(&key.secret_key).unwrap();

        // Primary-key summary columns on `keys`.
        let conn = Connection::open_in_memory().unwrap(); // for type hints only
        let _ = conn; // suppress unused warning
        let (is_revoked, cert_created_at, expiration_time): (i32, Option<String>, Option<String>) =
            store
                .raw_conn_for_test()
                .query_row(
                    "SELECT is_revoked, cert_created_at, expiration_time FROM keys
                     WHERE fingerprint = ?1",
                    [&fp],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
        assert_eq!(is_revoked, 0);
        assert!(cert_created_at.is_some());
        // `create_key_simple` produces a non-expiring key, so this
        // should be None - but the column just needs to exist.
        let _ = expiration_time;

        // Subkey rows.
        let missing: i32 = store
            .raw_conn_for_test()
            .query_row(
                "SELECT COUNT(*) FROM subkeys
                 WHERE fingerprint = ?1 AND (algorithm IS NULL OR bit_length IS NULL)",
                [&fp],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            missing, 0,
            "all subkey rows from a fresh import_key must have algorithm + bit_length set"
        );
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
        // - the FKs must resolve to `keys(fingerprint)`.
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
