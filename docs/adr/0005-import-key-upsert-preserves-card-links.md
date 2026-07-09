# ADR 0005: `import_key` Updates In Place to Preserve Card Links

## Status

Accepted

## Date

2026-06-06

## Context

The keystore stores each OpenPGP key as one row in the `keys` table,
keyed by `fingerprint` (PRIMARY KEY). Three child tables hang off it,
each with `ON DELETE CASCADE` on that fingerprint so that deleting a
key cleans up its dependent rows automatically:

- `user_ids` (UIDs + emails)
- `subkeys` (per-subkey cache)
- `card_keys` (which hardware card slot holds the key - written by
  `save_card_key`, read by `get_card_keys` / `list_all_card_keys`)

The connection runs with `PRAGMA foreign_keys = ON`
(`store.rs::open` / `open_in_memory`), so those cascades are live.

`KeyStore::import_key` stored the key with **`INSERT OR REPLACE INTO
keys`**. In SQLite, the REPLACE conflict-resolution algorithm does not
update the conflicting row in place - it **DELETEs the pre-existing row
and INSERTs a fresh one** (SQLite docs, "ON CONFLICT", REPLACE). When
foreign keys are enabled, that implicit DELETE fires every dependent
`ON DELETE CASCADE`.

`import_key` masked this for two of the three children by explicitly
re-populating them right after the insert: it `DELETE`s and re-`INSERT`s
`user_ids`, and `DELETE`s then rebuilds `subkeys`. It never touched
`card_keys`. So on every re-import of an already-present key, the
REPLACE silently deleted that key's card associations and nothing put
them back.

This surfaced as **tumpa-cli#32**: a user runs `tcli card link` (writes
`card_keys`), then later re-imports the same cert with
`gpg --export | tcli import -`. tumpa-cli's import path
(`merge_and_reimport`) calls `import_key` unconditionally - even on the
"Unchanged - no new data" branch, where `merge_keys` correctly returns
byte-identical material. The user saw `Unchanged … - no new data`,
believed nothing happened, yet their card linkage was gone and signing
fell back to (or failed without) the software key until they re-ran
`tcli card link`. Silent loss of a hardware-key association is a
data-integrity bug, not a cosmetic one.

This is distinct from, and downstream of, ADR 0002's secret-key-aware
merge: the merge layer was doing the right thing (secret material
preserved). The loss happened one layer lower, in how the storage layer
writes the row.

## Decision

### `import_key` uses an UPSERT, not REPLACE

The `INSERT OR REPLACE INTO keys (…)` statement becomes an explicit
UPSERT that updates the existing row in place:

```sql
INSERT INTO keys ( … ) VALUES ( … )
ON CONFLICT(fingerprint) DO UPDATE SET
    key_data        = excluded.key_data,
    is_secret       = excluded.is_secret,
    primary_uid     = excluded.primary_uid,
    is_revoked      = excluded.is_revoked,
    revocation_time = excluded.revocation_time,
    expiration_time = excluded.expiration_time,
    cert_created_at = excluded.cert_created_at,
    updated_at      = CURRENT_TIMESTAMP
```

An `ON CONFLICT … DO UPDATE` mutates the row in place: no DELETE is
issued, so no cascade fires, so `card_keys` survives a re-import. The
existing explicit rebuild of `user_ids` and `subkeys` further down
`import_key` is unchanged and still correct - those tables are
intentionally rewritten from the freshly parsed cert on every import.

`fingerprint` is the table's PRIMARY KEY, which is exactly the unique
index `ON CONFLICT(fingerprint)` targets. UPSERT is available on every
SQLite ≥ 3.24.0 (2018-06-04); the crate already requires far newer
(schema migration v3 relies on `PRAGMA legacy_alter_table`, 3.26+), so
this introduces no new floor.

### Scope: only the `keys` write changes

The sibling `INSERT OR REPLACE INTO subkeys` inside the same function is
deliberately left as-is. `subkeys` has no child tables cascading off
it, and `import_key` rebuilds it wholesale anyway, so REPLACE there
deletes nothing that is not immediately rewritten. `save_card_key`'s own
`INSERT OR REPLACE INTO card_keys` (keyed on `(card_ident, slot)`) is
also untouched - its REPLACE updates a `last_seen` timestamp and has no
cascading children, which is the intended behaviour.

### Regression test

`store.rs::test_reimport_preserves_card_keys`: import a secret key,
`save_card_key`, re-import the same cert, assert `get_card_keys` still
returns the row; then re-import the public-only form and assert the row
still survives. This fails on the old `INSERT OR REPLACE` path (the
cascade wipes the row) and passes on the UPSERT path.

## Consequences

### Positive

- Re-importing a key never drops its card linkage. tumpa-cli#32 is
  fixed at the storage layer, so every consumer (`tcli`, the desktop
  app, the ops socket) gets the correct behaviour with no change of
  their own.
- The fix is invisible to callers - `import_key`'s signature and return
  value are unchanged.
- An in-place UPDATE writes one row instead of delete-plus-insert, and
  skips firing (and the engine skips bookkeeping for) the three
  cascades - marginally less work per re-import.

### Negative / Neutral

- The named-column `DO UPDATE SET` list must be kept in sync with the
  insert column list. If a future schema migration adds a summary-cache
  column to `keys`, it has to be added in both places (as already true
  of the `INSERT` itself). A row that is re-imported but whose new
  column is left out of the `SET` clause would keep its stale cached
  value. Mitigated by the column list living inline in one function.
- Behavioural change on conflict: the row's implicit `rowid` is now
  preserved across a re-import rather than being reallocated. Nothing in
  the schema keys off `keys.rowid`, so this is benign, but it is a real
  difference from REPLACE for anyone who assumed otherwise.

## Alternatives Considered

### Re-populate `card_keys` after the REPLACE, like `user_ids`/`subkeys`

Symmetrical with how the other two children are handled, but
unworkable: `import_key` parses only the OpenPGP cert bytes, which carry
no card-association data. There is nothing in its inputs to rebuild
`card_keys` from - the associations live only in the database. It would
have to snapshot `card_keys` before the write and replay it after,
which is strictly more code and more fragile than simply not deleting
the rows.

### Drop `ON DELETE CASCADE` from `card_keys`

Would stop the cascade, but at the cost of leaking orphaned `card_keys`
rows when a key is genuinely deleted - trading a re-import bug for a
delete bug. The cascade is correct for real deletions; the fix belongs
on the write that should not have been a deletion in the first place.

### Skip the re-import in tumpa-cli when the merge is a no-op

`merge_and_reimport` could avoid calling `import_key` when the merged
bytes equal the stored bytes, sidestepping the "Unchanged" case. This
is a reasonable optimization but does **not** fix the bug: the
"Updated - merged new signatures" path still re-imports and would still
wipe the linkage. The defect is in the storage primitive, so the fix
has to be there. (The tumpa-cli no-op skip may still be added later as
an independent write-reduction, not as a correctness fix.)

### Wrap `import_key` in a transaction that saves/restores `card_keys`

Correct but baroque: it preserves the destructive REPLACE and bolts a
backup/restore around it. The UPSERT achieves the same invariant by not
destroying the data in the first place, with less code and no extra
round-trips.

## References

- tumpa-cli#32 - "linked secret key disappears when re-importing the
  public key": the reported bug this ADR fixes.
- SQLite docs, "ON CONFLICT" - REPLACE deletes the conflicting row
  (firing delete triggers and foreign-key actions) before inserting:
  https://www.sqlite.org/lang_conflict.html
- SQLite docs, "UPSERT" - `ON CONFLICT … DO UPDATE` semantics and the
  `excluded.` pseudo-table: https://www.sqlite.org/lang_upsert.html
- SQLite docs, "Foreign Key Actions" - `ON DELETE CASCADE` fires for the
  implicit delete performed by REPLACE:
  https://www.sqlite.org/foreignkeys.html#fk_actions
- `store.rs::import_key` - the changed write.
- `schema.rs` migration v2/v3 - `card_keys` table + its FK rewired from
  `certificates(fingerprint)` to `keys(fingerprint)`.
- ADR 0002: Key-merge semantics - the merge layer that (correctly)
  preserves secret material; this ADR fixes the storage layer beneath
  it.
