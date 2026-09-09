//! The turso store: connection, schema, and the conventions every module
//! queries through.

use std::path::Path;

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use turso::{Builder, Connection, Row};

use crate::secret::{self, Key};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database: {0}")]
    Backend(String),
    #[error("corrupt row: {0}")]
    Corrupt(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// A value a panel form offered is against the stored rules — the
    /// caller turns it into the page's refusal, never a database problem.
    #[error("{0}")]
    Invalid(String),
    /// The write is well-formed but the row belongs to someone else — the
    /// web layer answers 409, not 400.
    #[error("{0}")]
    Conflict(String),
}

pub type Result<T, E = StoreError> = std::result::Result<T, E>;

pub(crate) fn backend<E: std::fmt::Display>(e: E) -> StoreError {
    StoreError::Backend(e.to_string())
}

/// The schema, authoritative. Every table is `IF NOT EXISTS` so `migrate()`
/// is idempotent and safe to run on every boot.
pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  totp_secret BLOB,
  totp_confirmed INTEGER NOT NULL DEFAULT 0,
  admin INTEGER NOT NULL DEFAULT 0,
  disabled INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  photo_mime TEXT,
  photo_version INTEGER NOT NULL DEFAULT 0,
  theme TEXT NOT NULL DEFAULT 'light',
  language TEXT NOT NULL DEFAULT 'en',
  ui TEXT NOT NULL DEFAULT 'instrument',
  timezone TEXT NOT NULL DEFAULT 'UTC+03:00'
);
CREATE TABLE IF NOT EXISTS invites (
  token TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  invited_by TEXT,
  admin INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  accepted_at TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  ip TEXT,
  agent TEXT,
  seen_at TEXT
);
CREATE TABLE IF NOT EXISTS oidc_clients (
  client_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  secret_hash TEXT NOT NULL,
  redirect_uris TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_codes (
  code_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES oidc_clients(client_id),
  user_id TEXT NOT NULL REFERENCES users(id),
  redirect_uri TEXT NOT NULL,
  nonce TEXT,
  code_challenge TEXT NOT NULL,
  session_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  client_id TEXT NOT NULL REFERENCES oidc_clients(client_id),
  session_hash TEXT NOT NULL REFERENCES sessions(token_hash),
  expires_at TEXT NOT NULL,
  revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS signing_keys (
  kid TEXT PRIMARY KEY,
  private_der_enc BLOB NOT NULL,
  public_der BLOB NOT NULL,
  created_at TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS app_sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  client_id TEXT NOT NULL REFERENCES oidc_clients(client_id),
  session_hash TEXT NOT NULL REFERENCES sessions(token_hash),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY,
  at TEXT NOT NULL,
  kind TEXT NOT NULL,
  actor TEXT,
  detail TEXT
);
CREATE TABLE IF NOT EXISTS reset_links (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT
);
CREATE TABLE IF NOT EXISTS email_changes (
  old_token_hash TEXT PRIMARY KEY,
  new_token_hash TEXT NOT NULL UNIQUE,
  user_id TEXT NOT NULL REFERENCES users(id),
  old_email TEXT NOT NULL,
  new_email TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  confirmed_old_at TEXT,
  confirmed_new_at TEXT,
  used_at TEXT
);
CREATE TABLE IF NOT EXISTS login_attempts (
  key TEXT NOT NULL,
  at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS login_attempts_key ON login_attempts(key, at);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS services (
  key TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  url TEXT NOT NULL,
  position INTEGER NOT NULL,
  owner TEXT,
  client_id TEXT,
  storage_limit_bytes INTEGER
);
";

/// One database handle with the at-rest key beside it. Turso is a
/// single-writer engine; one connection per store, like izlek-core.
pub struct Store {
    pub(crate) conn: tokio::sync::Mutex<Connection>,
    pub(crate) key: Key,
    /// The directory profile photos live in, one file per user, named by the
    /// user id — the same contract izlek-core's storage tree keeps: the
    /// database keeps the facts, this tree keeps the bytes, back the two up
    /// together.
    pub(crate) photos_dir: std::path::PathBuf,
}

impl Store {
    /// Opens (creating if needed) the database at `path` and runs the schema
    /// migration. `:memory:` gives a test store with a fresh throwaway key.
    pub async fn open(path: &Path) -> Result<Store> {
        // The tree goes in before anything else — every writer past this
        // point assumes the directory is there to write into.
        let photos_dir = photos_dir(path);
        std::fs::create_dir_all(&photos_dir).map_err(|e| {
            StoreError::Backend(format!(
                "creating photos directory {}: {e}",
                photos_dir.display()
            ))
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&photos_dir, std::fs::Permissions::from_mode(0o700)).map_err(
                |e| StoreError::Backend(format!("restricting {}: {e}", photos_dir.display())),
            )?;
        }
        let raw = path
            .to_str()
            .ok_or_else(|| StoreError::Corrupt("path is not utf-8".into()))?;
        let db = Builder::new_local(raw).build().await.map_err(backend)?;
        let conn = db.connect().map_err(backend)?;
        let store = Store {
            conn: tokio::sync::Mutex::new(conn),
            key: load_key(path)?,
            photos_dir,
        };
        store.migrate().await?;
        crate::photos::sweep_orphan_files(&store).await;
        Ok(store)
    }

    /// Applies the schema inside one immediate transaction; safe to re-run.
    pub async fn migrate(&self) -> Result<()> {
        // One guard for the whole transaction — nothing interleaves with a
        // schema write.
        let conn = self.conn.lock().await;
        conn.execute("BEGIN IMMEDIATE", ()).await.map_err(backend)?;
        let outcome = async {
            conn.execute_batch(SCHEMA).await.map_err(backend)?;
            // Columns born after databases already existed: the CREATE above
            // is `IF NOT EXISTS`, so an old table never sees them from it.
            // Each goes in with its own guarded ALTER — a boot either adds
            // the column or finds it there, and re-boot is a no-op.
            if !has_column(&conn, "users", "photo_mime").await? {
                conn.execute("ALTER TABLE users ADD COLUMN photo_mime TEXT", ())
                    .await
                    .map_err(backend)?;
            }
            // How many times the profile photo has changed: the URL cache
            // buster (`/photo/{id}?v=`), kept in the row so every process
            // and every sibling app reads the same one. Databases born
            // before photos carried versions grow it here; every existing
            // row reads 0, and the first upload after the move bumps it.
            if !has_column(&conn, "users", "photo_version").await? {
                conn.execute(
                    "ALTER TABLE users ADD COLUMN photo_version INTEGER NOT NULL DEFAULT 0",
                    (),
                )
                .await
                .map_err(backend)?;
            }
            // Per-user display preferences (theme/language/ui): databases
            // born before these columns grow them here — TEXT NOT NULL with
            // a DEFAULT so every existing row reads the default.
            if !has_column(&conn, "users", "theme").await? {
                conn.execute(
                    "ALTER TABLE users ADD COLUMN theme TEXT NOT NULL DEFAULT 'light'",
                    (),
                )
                .await
                .map_err(backend)?;
            }
            if !has_column(&conn, "users", "language").await? {
                conn.execute(
                    "ALTER TABLE users ADD COLUMN language TEXT NOT NULL DEFAULT 'en'",
                    (),
                )
                .await
                .map_err(backend)?;
            }
            if !has_column(&conn, "users", "ui").await? {
                conn.execute(
                    "ALTER TABLE users ADD COLUMN ui TEXT NOT NULL DEFAULT 'instrument'",
                    (),
                )
                .await
                .map_err(backend)?;
            }
            // The family rows' client linkage (the merge of the panel's
            // services and clients sections): a `POST /family/register`
            // stamps the authenticated client's id beside its row, so the
            // panel can show the wordmark and its credential as one thing.
            // ALTER over the owner precedent: databases born before the
            // column get it here, and every existing row reads NULL until
            // its app re-registers.
            // The display timezone (iz's fixed-offset spelling): the
            // DEFAULT backfills every existing row to UTC+03:00.
            if !has_column(&conn, "users", "timezone").await? {
                conn.execute(
                    "ALTER TABLE users ADD COLUMN timezone TEXT NOT NULL DEFAULT 'UTC+03:00'",
                    (),
                )
                .await
                .map_err(backend)?;
            }
            if !has_column(&conn, "services", "client_id").await? {
                conn.execute("ALTER TABLE services ADD COLUMN client_id TEXT", ())
                    .await
                    .map_err(backend)?;
            }
            // The per-service storage cap: the panel's limit on how many
            // bytes a sibling that stores (in's Files) may hold. Served to
            // the family over `/family` as `limit_bytes`; NULL states no
            // limit, and the sibling's own default stands.
            if !has_column(&conn, "services", "storage_limit_bytes").await? {
                conn.execute(
                    "ALTER TABLE services ADD COLUMN storage_limit_bytes INTEGER",
                    (),
                )
                .await
                .map_err(backend)?;
            }
            if !has_column(&conn, "sessions", "ip").await? {
                conn.execute("ALTER TABLE sessions ADD COLUMN ip TEXT", ())
                    .await
                    .map_err(backend)?;
            }
            if !has_column(&conn, "sessions", "agent").await? {
                conn.execute("ALTER TABLE sessions ADD COLUMN agent TEXT", ())
                    .await
                    .map_err(backend)?;
            }
            if !has_column(&conn, "sessions", "seen_at").await? {
                conn.execute("ALTER TABLE sessions ADD COLUMN seen_at TEXT", ())
                    .await
                    .map_err(backend)?;
            }
            Ok(())
        }
        .await;
        match outcome {
            Ok(()) => {
                conn.execute("COMMIT", ()).await.map_err(backend)?;
            }
            Err(e) => {
                let _ = conn.execute("ROLLBACK", ()).await;
                return Err(e);
            }
        }
        Ok(())
    }

    /// The at-rest encryption key for this database.
    pub(crate) fn key(&self) -> &Key {
        &self.key
    }

    /// Seals a small value for a cookie (the pending-login marker), so its
    /// contents are neither readable nor forgeable client-side.
    pub fn seal_value(&self, plaintext: &[u8]) -> String {
        secret::seal(&self.key, plaintext)
    }

    /// Reverses [`Store::seal_value`]; `None` for anything we did not seal.
    pub fn open_value(&self, sealed: &str) -> Option<Vec<u8>> {
        secret::open(&self.key, sealed)
    }
}

/// The directory a database's profile photos live in: a `storage/photos`
/// tree beside the database file, so a backup that takes the database takes
/// the photos with it. `:memory:` has no directory to anchor to — its tree
/// is a fresh tempdir, as throwaway as the database itself.
fn photos_dir(path: &Path) -> std::path::PathBuf {
    if path.as_os_str() == ":memory:" {
        return std::env::temp_dir().join(format!("im-storage-{}", ulid::Ulid::new()));
    }
    path.parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join("storage")
        .join("photos")
}

/// Whether `table` carries `column` — the migration's guard for ALTERs that
/// must be no-ops on databases already carrying them. Both names are
/// literals from this module, never request data.
async fn has_column(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut rows = conn
        .query(format!("PRAGMA table_info({table})"), ())
        .await
        .map_err(backend)?;
    while let Some(row) = rows.next().await.map_err(backend)? {
        if row.get::<String>(1).map_err(backend)? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The key for `path`'s database. `:memory:` has no directory to anchor a
/// sibling file to, so it gets a key generated fresh in memory — every
/// in-memory store is its own, unrelated encryption domain.
fn load_key(path: &Path) -> Result<Key> {
    if path.as_os_str() == ":memory:" {
        let mut key = [0u8; secret::KEY_BYTES];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut key);
        return Ok(key);
    }
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    secret::load_or_create_key(&dir.join("im.key")).map_err(StoreError::Io)
}

pub(crate) fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

pub(crate) fn stamp(at: OffsetDateTime) -> Result<String> {
    at.format(&Rfc3339)
        .map_err(|e| StoreError::Corrupt(format!("timestamp: {e}")))
}

pub(crate) fn parse_stamp(raw: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(raw, &Rfc3339)
        .map_err(|e| StoreError::Corrupt(format!("timestamp {raw:?}: {e}")))
}

pub(crate) fn text(row: &Row, idx: usize) -> Result<String> {
    row.get::<String>(idx).map_err(backend)
}

pub(crate) fn opt_text(row: &Row, idx: usize) -> Result<Option<String>> {
    row.get::<Option<String>>(idx).map_err(backend)
}
pub(crate) fn int(row: &Row, idx: usize) -> Result<i64> {
    row.get::<i64>(idx).map_err(backend)
}
pub(crate) fn opt_int(row: &Row, idx: usize) -> Result<Option<i64>> {
    row.get::<Option<i64>>(idx).map_err(backend)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn migrate_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("im.db");
        let store = Store::open(&path).await.unwrap();
        store.migrate().await.unwrap();
        store.migrate().await.unwrap();
        let conn = store.conn.lock().await;
        let mut rows = conn
            .query("SELECT name FROM sqlite_master WHERE type = 'table'", ())
            .await
            .unwrap();
        let mut tables = Vec::new();
        while let Some(row) = rows.next().await.unwrap() {
            tables.push(text(&row, 0).unwrap());
        }
        for expected in [
            "users",
            "invites",
            "sessions",
            "oidc_clients",
            "auth_codes",
            "refresh_tokens",
            "signing_keys",
            "reset_links",
            "email_changes",
            "login_attempts",
        ] {
            assert!(tables.contains(&expected.to_string()), "missing {expected}");
        }
    }

    #[tokio::test]
    async fn key_file_lives_beside_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("im.db");
        let _store = Store::open(&path).await.unwrap();
        assert!(dir.path().join("im.key").exists());
    }

    #[tokio::test]
    async fn an_old_shaped_services_table_grows_the_limit_column() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("im.db");
        // The previous generation's services table, before the storage
        // limit was a thing. `Store::open` creates the rest of the schema
        // around it and ALTERs the column in without touching the row.
        {
            let db = turso::Builder::new_local(path.to_str().unwrap())
                .build()
                .await
                .unwrap();
            let conn = db.connect().unwrap();
            conn.execute_batch(
                "CREATE TABLE services (
                    key TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    url TEXT NOT NULL,
                    position INTEGER NOT NULL,
                    owner TEXT
                );
                INSERT INTO services (key, name, url, position, owner)
                    VALUES ('in', 'Files', 'http://127.0.0.1:7655', 0, NULL);",
            )
            .await
            .unwrap();
            drop(conn);
            drop(db);
        }
        let store = Store::open(&path).await.unwrap();
        let rows = crate::services::list(&store).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].storage_limit_bytes, None,
            "a pre-limit row reads no limit"
        );
        crate::services::edit(
            &store,
            "in",
            "Files",
            "http://127.0.0.1:7655",
            Some(512 * 1024 * 1024),
        )
        .await
        .unwrap();
        // A re-boot on the already-migrated table is the guarded no-op,
        // and the stored value survives it.
        let store = Store::open(&path).await.unwrap();
        assert_eq!(
            crate::services::list(&store).await.unwrap()[0].storage_limit_bytes,
            Some(512 * 1024 * 1024)
        );
    }
}
