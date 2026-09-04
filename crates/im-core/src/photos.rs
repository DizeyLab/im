//! Profile photos: the row keeps the mime type, the storage tree keeps the
//! bytes — one file per user at `<storage>/photos/<user id>`, the same
//! split izlek-core keeps. The web layer caps the upload (5 MiB) and sniffs
//! the mime before anything here runs; this module trusts both, the way
//! `accounts` trusts the password rules were checked.
//!
//! Writes order themselves so a crash leaves stale bytes, never destroyed
//! ones: `set_photo` stages the new file under a name no row wears, commits
//! the row, and only then renames over the old photo; `clear_photo` commits
//! the row first and unlinks best-effort. Whatever a crash strands — staged
//! files, files no row names — the boot sweep collects (see
//! [`sweep_orphan_files`], run from `Store::open`).

use crate::model::UserId;
use crate::store::{Result, Store, StoreError, backend};

/// Where `user_id`'s photo lives inside the store's photos directory. Named
/// by the user id the store minted — never by anything an upload carried —
/// so a path here is always exactly one store-named file deep.
fn photo_file(store: &Store, user_id: &str) -> std::path::PathBuf {
    store.photos_dir.join(user_id)
}

/// Writes `bytes` to `path` through a temporary file in the same directory
/// and a rename: a crash or a full disk mid-write leaves whatever file was
/// there before intact, never a truncated one under the real name.
fn write_file_atomic(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let tmp = path.with_extension(format!("{}.tmp", ulid::Ulid::new()));
    let mut file = std::fs::File::create(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&tmp, path)
}

/// Stores the photo's bytes and mime type, replacing any previous one.
pub async fn set_photo(store: &Store, user: &UserId, bytes: &[u8], mime: &str) -> Result<()> {
    let id = user.to_string();
    let path = photo_file(store, &id);
    // The new bytes stage under a name no row wears, the row commits, and
    // only then does the rename put them over the old photo: a failed update
    // leaves the committed photo exactly as it was, and a crash between
    // commit and rename serves the old bytes next to a staged file the boot
    // sweep collects — stale, never destroyed.
    let staged = path.with_extension(format!("incoming-{}", ulid::Ulid::new()));
    write_file_atomic(&staged, bytes).map_err(|e| StoreError::Backend(e.to_string()))?;
    let written = {
        let conn = store.conn.lock().await;
        conn.execute(
            "UPDATE users SET photo_mime = ?1 WHERE id = ?2",
            turso::params![mime, id.clone()],
        )
        .await
    };
    if let Err(e) = written {
        let _ = std::fs::remove_file(&staged);
        return Err(backend(e));
    }
    std::fs::rename(&staged, &path).map_err(|e| StoreError::Backend(e.to_string()))?;
    Ok(())
}

/// Clears the photo. The row goes first: the file may only follow a delete
/// that committed, or a crash in between would leave a row whose photo is
/// gone. The unlink is best-effort — a file that survives it is orphaned
/// bytes the boot sweep collects.
pub async fn clear_photo(store: &Store, user: &UserId) -> Result<()> {
    let id = user.to_string();
    {
        let conn = store.conn.lock().await;
        conn.execute(
            "UPDATE users SET photo_mime = NULL WHERE id = ?1",
            turso::params![id.clone()],
        )
        .await
        .map_err(backend)?;
    }
    let _ = std::fs::remove_file(photo_file(store, &id));
    Ok(())
}

/// The photo's bytes and mime type, or `None` when none is set. A row whose
/// file went missing is reported at boot; the read answers "nothing to
/// serve" rather than failing the page.
pub async fn photo(store: &Store, user: &UserId) -> Result<Option<(Vec<u8>, String)>> {
    let id = user.to_string();
    let mime = {
        let conn = store.conn.lock().await;
        let mut rows = conn
            .query(
                "SELECT photo_mime FROM users WHERE id = ?1",
                turso::params![id.clone()],
            )
            .await
            .map_err(backend)?;
        match rows.next().await.map_err(backend)? {
            Some(row) => crate::store::opt_text(&row, 0)?,
            None => return Ok(None),
        }
    };
    let Some(mime) = mime else {
        return Ok(None);
    };
    match std::fs::read(photo_file(store, &id)) {
        Ok(bytes) => Ok(Some((bytes, mime))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(StoreError::Backend(e.to_string())),
    }
}

/// Sets the photos tree against the database, once per boot. The two are
/// halves of one state, and a crash between a row write and its file write —
/// either order — leaves exactly one half behind: a file no row names goes
/// (staged `incoming-*` and `*.tmp` leftovers first), and a row whose file
/// is missing is reported. Never fails the boot — a sweep that cannot read
/// its own directory has nothing safe to delete anyway.
pub(crate) async fn sweep_orphan_files(store: &Store) {
    let known: std::collections::HashSet<String> = {
        let conn = store.conn.lock().await;
        let mut rows = match conn
            .query("SELECT id FROM users WHERE photo_mime IS NOT NULL", ())
            .await
        {
            Ok(rows) => rows,
            Err(e) => {
                eprintln!(
                    "im photos: could not list photo rows for the sweep: {}",
                    backend(e)
                );
                return;
            }
        };
        let mut ids = std::collections::HashSet::new();
        loop {
            match rows.next().await {
                Ok(Some(row)) => match crate::store::text(&row, 0) {
                    Ok(id) => {
                        ids.insert(id);
                    }
                    Err(e) => {
                        eprintln!("im photos: sweep could not read a user id: {e}");
                        return;
                    }
                },
                Ok(None) => break,
                Err(e) => {
                    eprintln!("im photos: sweep could not read photo rows: {}", backend(e));
                    return;
                }
            }
        }
        ids
    };
    // Rows whose file went missing: reported, never failed — the photo read
    // already answers "nothing to serve" for them.
    for id in &known {
        if !store.photos_dir.join(id).is_file() {
            eprintln!("im photos: {id} has a photo row but no file");
        }
    }
    let entries = match std::fs::read_dir(&store.photos_dir) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!(
                "im photos: could not sweep {}: {e}",
                store.photos_dir.display()
            );
            return;
        }
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let staged = name.contains(".incoming-") || name.contains(".tmp");
        if (staged || !known.contains(&name))
            && let Err(e) = std::fs::remove_file(entry.path())
        {
            eprintln!("im photos: could not delete orphaned file {name}: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::{create_invite, create_user_from_invite, user_by_id};
    use std::path::Path;

    async fn fixture() -> (Store, UserId) {
        let store = Store::open(Path::new(":memory:")).await.unwrap();
        let invite = create_invite(&store, "ann@example.com", None, false)
            .await
            .unwrap();
        let user = create_user_from_invite(&store, invite.expose(), "Ann", "tDLr9!mZQ2xv")
            .await
            .unwrap();
        (store, user.id)
    }

    #[tokio::test]
    async fn photo_roundtrip() {
        let (store, user_id) = fixture().await;
        assert!(photo(&store, &user_id).await.unwrap().is_none());
        assert!(
            !user_by_id(&store, &user_id)
                .await
                .unwrap()
                .unwrap()
                .has_photo
        );

        set_photo(&store, &user_id, b"\x89PNG-fake", "image/png")
            .await
            .unwrap();
        let (bytes, mime) = photo(&store, &user_id).await.unwrap().unwrap();
        assert_eq!(bytes, b"\x89PNG-fake");
        assert_eq!(mime, "image/png");
        assert!(
            user_by_id(&store, &user_id)
                .await
                .unwrap()
                .unwrap()
                .has_photo
        );
        // The bytes are a file named by the user id — never a column.
        let file = photo_file(&store, &user_id.to_string());
        assert_eq!(std::fs::read(&file).unwrap(), b"\x89PNG-fake");

        // A second upload replaces, it does not append.
        set_photo(&store, &user_id, b"\xff\xd8\xff", "image/jpeg")
            .await
            .unwrap();
        let (bytes, mime) = photo(&store, &user_id).await.unwrap().unwrap();
        assert_eq!(bytes, b"\xff\xd8\xff");
        assert_eq!(mime, "image/jpeg");

        clear_photo(&store, &user_id).await.unwrap();
        assert!(photo(&store, &user_id).await.unwrap().is_none());
        assert!(
            !user_by_id(&store, &user_id)
                .await
                .unwrap()
                .unwrap()
                .has_photo
        );
        assert!(!file.exists());
    }

    #[tokio::test]
    async fn a_row_without_its_file_reads_as_no_photo() {
        let (store, user_id) = fixture().await;
        set_photo(&store, &user_id, b"\x89PNG-fake", "image/png")
            .await
            .unwrap();
        std::fs::remove_file(photo_file(&store, &user_id.to_string())).unwrap();
        assert!(photo(&store, &user_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn the_boot_sweep_collects_orphans_and_staged_files() {
        let (store, user_id) = fixture().await;
        set_photo(&store, &user_id, b"\x89PNG-fake", "image/png")
            .await
            .unwrap();
        let real = photo_file(&store, &user_id.to_string());
        let staged = real.with_extension("incoming-deadbeef");
        let stranger = store.photos_dir.join("01STRANGERXXXXXXXXXXXXXXXXX0");
        std::fs::write(&staged, b"half an upload").unwrap();
        std::fs::write(&stranger, b"no row names me").unwrap();

        sweep_orphan_files(&store).await;

        assert!(real.is_file());
        assert!(!staged.exists());
        assert!(!stranger.exists());
    }
}
