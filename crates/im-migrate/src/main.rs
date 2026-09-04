//! im-migrate: one-time import of İzlek accounts into an im database.
//!
//! ```sh
//! im-migrate --izlek /path/izlek.db --im /path/im.db [--mapping /path/out.csv]
//! ```
//!
//! İzlek's `user` table keeps `password_hash` NULL for a member who never
//! signed in; those rows are skipped and reported, because there is no
//! password to migrate and the SSO's invite flow is their way in. Everyone
//! else crosses with the argon2 PHC string verbatim — it verifies unchanged.
//!
//! The mapping CSV (`izlek_user_id,im_sub`) is what İzlek's follow-up batch
//! uses to link its local rows to SSO subject ids. It covers every user that
//! exists in im afterwards, imported this run or already present.

use std::path::{Path, PathBuf};

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use turso::Builder;

/// im's schema, duplicated literally from im-core's `store::SCHEMA` — the
/// tool stays dependency-free of im-core so a build of this binary never
/// drags the argon2/rsa tree along. When im-core's schema changes, change
/// this in the same diff: a drifted copy once produced a database the
/// server could not read, and every login answered "bad_login".
const IM_SCHEMA: &str = "
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
  theme TEXT NOT NULL DEFAULT 'light',
  language TEXT NOT NULL DEFAULT 'en',
  ui TEXT NOT NULL DEFAULT 'instrument'
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
CREATE TABLE IF NOT EXISTS login_attempts (
  key TEXT NOT NULL,
  at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS login_attempts_key ON login_attempts(key, at);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
";

#[derive(Debug)]
struct Args {
    izlek: PathBuf,
    im: PathBuf,
    mapping: PathBuf,
}

#[derive(Debug, thiserror::Error)]
enum MigrateError {
    #[error("{0}")]
    Usage(String),
    #[error("database: {0}")]
    Backend(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

type Result<T, E = MigrateError> = std::result::Result<T, E>;

fn backend<E: std::fmt::Display>(e: E) -> MigrateError {
    MigrateError::Backend(e.to_string())
}

fn parse_args() -> Result<Args> {
    let mut izlek = None;
    let mut im = None;
    let mut mapping = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--izlek" => izlek = args.next().map(PathBuf::from),
            "--im" => im = args.next().map(PathBuf::from),
            "--mapping" => mapping = args.next().map(PathBuf::from),
            other => {
                return Err(MigrateError::Usage(format!(
                    "unknown option {other}\nusage: im-migrate --izlek <izlek.db> --im <im.db> [--mapping out.csv]"
                )));
            }
        }
    }
    match (izlek, im) {
        (Some(izlek), Some(im)) => Ok(Args {
            izlek,
            im,
            mapping: mapping.unwrap_or_else(|| PathBuf::from("im-migrate-mapping.csv")),
        }),
        _ => Err(MigrateError::Usage(
            "usage: im-migrate --izlek <izlek.db> --im <im.db> [--mapping out.csv]".into(),
        )),
    }
}

/// One İzlek user row worth migrating.
struct IzlekUser {
    id: String,
    email: String,
    name: String,
    password_hash: String,
}

async fn read_izlek_users(path: &Path) -> Result<(Vec<IzlekUser>, usize)> {
    let db = Builder::new_local(path.to_str().unwrap())
        .build()
        .await
        .map_err(backend)?;
    let conn = db.connect().map_err(backend)?;
    let mut rows = conn
        .query(
            "SELECT id, email, display_name, password_hash FROM user ORDER BY created_at",
            (),
        )
        .await
        .map_err(backend)?;
    let mut users = Vec::new();
    let mut skipped_no_password = 0;
    while let Some(row) = rows.next().await.map_err(backend)? {
        let hash: Option<String> = row.get(3).map_err(backend)?;
        let Some(hash) = hash else {
            skipped_no_password += 1;
            continue;
        };
        users.push(IzlekUser {
            id: row.get(0).map_err(backend)?,
            email: row.get(1).map_err(backend)?,
            name: row.get(2).map_err(backend)?,
            password_hash: hash,
        });
    }
    Ok((users, skipped_no_password))
}

struct Report {
    imported: usize,
    already_present: usize,
    skipped_no_password: usize,
}

async fn run(args: &Args) -> Result<Report> {
    let (users, skipped_no_password) = read_izlek_users(&args.izlek).await?;

    let db = Builder::new_local(args.im.to_str().unwrap())
        .build()
        .await
        .map_err(backend)?;
    let conn = db.connect().map_err(backend)?;
    conn.execute_batch(IM_SCHEMA).await.map_err(backend)?;

    let mut report = Report {
        imported: 0,
        already_present: 0,
        skipped_no_password,
    };
    let mut mapping = String::from("izlek_user_id,im_sub\n");

    conn.execute("BEGIN IMMEDIATE", ()).await.map_err(backend)?;
    let outcome = async {
        for user in &users {
            let mut existing = conn
                .query(
                    "SELECT id FROM users WHERE email = ?1 COLLATE NOCASE",
                    turso::params![user.email.clone()],
                )
                .await
                .map_err(backend)?;
            if let Some(row) = existing.next().await.map_err(backend)? {
                let sub: String = row.get(0).map_err(backend)?;
                report.already_present += 1;
                mapping.push_str(&format!("{},{sub}\n", user.id));
                continue;
            }
            let sub = ulid::Ulid::new().to_string();
            conn.execute(
                "INSERT INTO users (id, email, name, password_hash, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                turso::params![
                    sub.clone(),
                    user.email.clone(),
                    user.name.clone(),
                    user.password_hash.clone(),
                    OffsetDateTime::now_utc()
                        .format(&Rfc3339)
                        .map_err(backend)?,
                ],
            )
            .await
            .map_err(backend)?;
            report.imported += 1;
            mapping.push_str(&format!("{},{sub}\n", user.id));
        }
        Ok::<_, MigrateError>(())
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

    std::fs::write(&args.mapping, mapping)?;
    Ok(report)
}

#[tokio::main]
async fn main() {
    let args = match parse_args() {
        Ok(args) => args,
        Err(MigrateError::Usage(text)) => {
            eprintln!("{text}");
            std::process::exit(2);
        }
        Err(e) => {
            eprintln!("im-migrate: {e}");
            std::process::exit(1);
        }
    };
    match run(&args).await {
        Ok(report) => {
            println!(
                "im-migrate  {} -> {}",
                args.izlek.display(),
                args.im.display()
            );
            println!(
                "  {} imported, {} already present, {} skipped (never set a password)",
                report.imported, report.already_present, report.skipped_no_password
            );
            println!("  mapping  {}", args.mapping.display());
        }
        Err(e) => {
            eprintln!("im-migrate: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn seed_izlek(path: &Path) {
        let db = Builder::new_local(path.to_str().unwrap())
            .build()
            .await
            .unwrap();
        let conn = db.connect().unwrap();
        conn.execute_batch(
            "CREATE TABLE user (
               id TEXT PRIMARY KEY,
               workspace_id TEXT NOT NULL,
               email TEXT NOT NULL,
               display_name TEXT NOT NULL,
               role TEXT NOT NULL,
               password_hash TEXT,
               created_at TEXT NOT NULL
             );",
        )
        .await
        .unwrap();
        conn.execute(
            "INSERT INTO user VALUES ('iz-1', 'w1', 'ann@example.com', 'Ann', 'admin', \
             '$argon2id$v=19$m=19456,t=2,p=1$0JjUMrLBpJG7lzg5bxZhMQ$iGpGXBNDAaHV9jqDxDcCyuIEIV33kJ1IAPt0XCh753Q', '2026-01-01T00:00:00Z')",
            (),
        )
        .await
        .unwrap();
        conn.execute(
            "INSERT INTO user VALUES ('iz-2', 'w1', 'bob@example.com', 'Bob', 'member', NULL, '2026-01-02T00:00:00Z')",
            (),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn import_is_verbatim_and_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let izlek = dir.path().join("izlek.db");
        let im = dir.path().join("im.db");
        let mapping = dir.path().join("mapping.csv");
        seed_izlek(&izlek).await;

        let args = Args {
            izlek: izlek.clone(),
            im: im.clone(),
            mapping: mapping.clone(),
        };
        let first = run(&args).await.unwrap();
        assert_eq!(first.imported, 1);
        assert_eq!(first.skipped_no_password, 1);

        // Re-running imports nothing and still maps every user.
        let second = run(&args).await.unwrap();
        assert_eq!(second.imported, 0);
        assert_eq!(second.already_present, 1);

        let csv = std::fs::read_to_string(&mapping).unwrap();
        assert!(csv.contains("iz-1,"), "mapping covers the imported user");

        let db = Builder::new_local(im.to_str().unwrap())
            .build()
            .await
            .unwrap();
        let conn = db.connect().unwrap();
        let mut rows = conn
            .query(
                "SELECT email, name, password_hash, totp_confirmed, disabled FROM users",
                (),
            )
            .await
            .unwrap();
        let row = rows.next().await.unwrap().unwrap();
        let email: String = row.get(0).unwrap();
        let hash: String = row.get(2).unwrap();
        assert_eq!(email, "ann@example.com");
        assert_eq!(
            hash,
            "$argon2id$v=19$m=19456,t=2,p=1$0JjUMrLBpJG7lzg5bxZhMQ$iGpGXBNDAaHV9jqDxDcCyuIEIV33kJ1IAPt0XCh753Q",
            "the PHC string crosses verbatim"
        );
        assert_eq!(row.get::<i64>(3).unwrap(), 0);
        assert_eq!(row.get::<i64>(4).unwrap(), 0);
        assert!(rows.next().await.unwrap().is_none(), "exactly one row");
    }
}
