//! `im-web pack` / `im-web unpack` — the family's backup, and its restore.
//!
//! One 0600 gzipped tar carries every service tree the deployment holds:
//! the database with its WAL sidecars, the config directory, the signing
//! key, and the object store. A `manifest.json` rides as the first member
//! and names what went in, so a restore can check before it overwrites.
//!
//! The keys come from im's services table plus im itself — the archive
//! follows the family as it grows, and no key is ever spelled out here.
//!
//! Like every CLI arm this runs while the server is stopped: Turso is a
//! single-writer engine, and a database packed under a live writer is not
//! a backup.

use std::fs::{self, File, OpenOptions};
use std::io::Read as _;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::Config;

/// The manifest at the archive's root: which keys ride inside and which
/// files each brought, and when it was packed. `version` gates the
/// restore — a shape this binary does not know refuses itself instead of
/// guessing.
#[derive(Serialize, Deserialize)]
struct Manifest {
    version: u32,
    packed_at: String,
    services: Vec<PackedService>,
}

#[derive(Serialize, Deserialize)]
struct PackedService {
    key: String,
    /// Paths relative to the pack root — the form the manifest names and
    /// the restore writes back: `<key>/<key>.db`, `<key>/config/x.toml`.
    files: Vec<String>,
}

const MANIFEST_NAME: &str = "manifest.json";

/// Every family tree worth packing, one key each: the services table's
/// rows plus im's own key. The row for im normally stands on that table —
/// `register_self` writes it on every boot — but a database too young or
/// too emptied to hold it does not keep im's tree out of the archive.
pub async fn family_keys(config: &Config) -> Vec<String> {
    let store = im_core::store::Store::open(&config.database)
        .await
        .expect("failed to open the database");
    let services = im_core::services::list(&store)
        .await
        .expect("failed to read the services table");
    drop(store);

    let mut keys = vec![im_core::services::SELF_OWNER.to_string()];
    for service in services {
        if !keys.contains(&service.key) {
            keys.push(service.key);
        }
    }
    keys
}

/// `im-web pack [--root DIR] [--out FILE]`. `--root` is the directory the
/// family trees sit under; without it, the parent of the working
/// directory — on the server, `$HOME` with `$HOME/im`, `$HOME/in`, …
/// inside. Without `--out`, a stamped name in the working directory.
pub async fn pack_command(config: &Config, root: Option<&str>, out: Option<&str>) {
    let keys = family_keys(config).await;
    let root = root.map(PathBuf::from).unwrap_or_else(default_root);
    let out = out.map(PathBuf::from).unwrap_or_else(archive_name);
    println!(
        "im      packing {} service tree(s) from {}",
        keys.len(),
        root.display()
    );
    match pack(&root, &keys, &out) {
        Ok(()) => println!("im      packed {}", out.display()),
        Err(problem) => {
            eprintln!("im: {problem}");
            std::process::exit(1);
        }
    }
}

/// `im-web unpack FILE [--root DIR] [--force]`. Without `--force` an
/// existing target database stops the restore before anything moves.
pub fn unpack_command(archive: &str, root: Option<&str>, force: bool) {
    let root = root.map(PathBuf::from).unwrap_or_else(default_root);
    println!("im      restoring {archive} into {}", root.display());
    match unpack(Path::new(archive), &root, force) {
        Ok(restored) => println!("im      restored {restored} file(s)"),
        Err(problem) => {
            eprintln!("im: {problem}");
            std::process::exit(1);
        }
    }
}

/// Packs each key's tree — the database trio, the signing key, `config/`,
/// `storage/` — into one 0600 gzipped tar. A missing piece is a line on
/// stderr, not a failure: a tree without a `storage/` is normal, and the
/// pack's job is to take what is there.
pub fn pack(root: &Path, keys: &[String], out: &Path) -> Result<(), String> {
    let mut packed = Vec::new();
    for key in keys {
        let home = root.join(key);
        if !home.is_dir() {
            eprintln!("im      {key}: no tree at {}, skipping", home.display());
            continue;
        }
        let mut files = Vec::new();
        // The database travels with its WAL sidecars or not at all — a
        // checkpointed tree legitimately carries neither.
        for name in [
            format!("{key}.db"),
            format!("{key}.db-wal"),
            format!("{key}.db-shm"),
            format!("{key}.key"),
        ] {
            if home.join(&name).is_file() {
                files.push(format!("{key}/{name}"));
            } else {
                eprintln!("im      {key}: {name} not present, skipped");
            }
        }
        for dir in ["config", "storage"] {
            let tree = home.join(dir);
            if !tree.exists() {
                eprintln!("im      {key}: {dir}/ not present, skipped");
                continue;
            }
            if !tree.is_dir() {
                return Err(format!("{} is not a directory", tree.display()));
            }
            files.extend(walk(&tree, root)?);
        }
        if files.is_empty() {
            eprintln!("im      {key}: nothing to pack, skipped");
            continue;
        }
        files.sort();
        packed.push(PackedService {
            key: key.clone(),
            files,
        });
    }
    if packed.is_empty() {
        return Err("nothing to pack: none of the family trees holds a file".into());
    }

    let manifest = Manifest {
        version: 1,
        packed_at: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "unknown".into()),
        services: packed,
    };
    let manifest_body = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| format!("failed to write the manifest: {e}"))?;

    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
        }
    }
    // 0600 from the first byte: the archive carries signing keys, so
    // there is no window where it reads wider.
    let file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(out)
        .map_err(|e| format!("failed to create {}: {e}", out.display()))?;
    let mut tar = tar::Builder::new(flate2::write::GzEncoder::new(
        file,
        flate2::Compression::default(),
    ));
    let mut header = tar::Header::new_gnu();
    header.set_size(manifest_body.len() as u64);
    header.set_mode(0o600);
    header.set_cksum();
    tar.append_data(&mut header, MANIFEST_NAME, manifest_body.as_slice())
        .map_err(|e| format!("failed to add {MANIFEST_NAME}: {e}"))?;
    for service in &manifest.services {
        for relative in &service.files {
            let path = root.join(relative);
            tar.append_path_with_name(&path, relative)
                .map_err(|e| format!("failed to add {relative}: {e}"))?;
        }
    }
    tar.into_inner()
        .map_err(|e| format!("failed to seal {PART}: {e}", PART = out.display()))?
        .finish()
        .map_err(|e| format!("failed to seal {}: {e}", out.display()))?;
    Ok(())
}

/// Restores an archive under `root`. Refuses when a target database is
/// already there — unless `force` says an overwrite is meant — and lands
/// every config, keys file, and signing key at 0600, whatever the packing
/// machine's modes were. Answers the number of files restored.
pub fn unpack(archive: &Path, root: &Path, force: bool) -> Result<usize, String> {
    let manifest = read_manifest(archive)?;
    if manifest.version != 1 {
        return Err(format!(
            "archive manifest version {} is not understood here",
            manifest.version
        ));
    }
    if !force {
        let in_the_way: Vec<&str> = manifest
            .services
            .iter()
            .filter(|service| {
                root.join(&service.key)
                    .join(format!("{}.db", service.key))
                    .is_file()
            })
            .map(|service| service.key.as_str())
            .collect();
        if !in_the_way.is_empty() {
            return Err(format!(
                "refusing to overwrite an existing database for {} — pass --force to unpack over it",
                in_the_way.join(", ")
            ));
        }
    }

    let file = File::open(archive).map_err(|e| format!("failed to open {}: {e}", archive.display()))?;
    let mut restored = 0;
    for entry in tar::Archive::new(flate2::read::GzDecoder::new(file))
        .entries()
        .map_err(|e| format!("failed to read {}: {e}", archive.display()))?
    {
        let mut entry =
            entry.map_err(|e| format!("{} is damaged: {e}", archive.display()))?;
        let name = entry
            .path()
            .map_err(|e| format!("{} is damaged: {e}", archive.display()))?
            .to_path_buf();
        let Some(relative) = safe_relative(&name) else {
            return Err(format!(
                "archive member {name:?} is not a safe relative path"
            ));
        };
        if relative == Path::new(MANIFEST_NAME) {
            continue;
        }
        // Directories are made as their files need them; anything else a
        // member could be — a link, a device — is not something this
        // archive has business carrying.
        if !entry.header().entry_type().is_file() {
            return Err(format!("archive member {relative:?} is not a regular file"));
        }
        let destination = root.join(relative);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
        }
        entry
            .unpack(&destination)
            .map_err(|e| format!("failed to restore {}: {e}", destination.display()))?;
        if let Some(secret) = secret_mode(&destination) {
            fs::set_permissions(&destination, fs::Permissions::from_mode(secret))
                .map_err(|e| format!("failed to tighten {}: {e}", destination.display()))?;
        }
        restored += 1;
    }
    Ok(restored)
}

/// Walks `dir` for regular files, each named relative to `root` — the
/// form the manifest names and the restore writes back. Symlinks are
/// refused rather than followed: the archive is the bytes of the tree,
/// not where its links point.
fn walk(dir: &Path, root: &Path) -> Result<Vec<String>, String> {
    let mut files = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let entries = fs::read_dir(&current)
            .map_err(|e| format!("failed to read {}: {e}", current.display()))?;
        for entry in entries {
            let entry = entry
                .map_err(|e| format!("failed to read {}: {e}", current.display()))?;
            let path = entry.path();
            let kind = entry
                .file_type()
                .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
            if kind.is_dir() {
                stack.push(path);
            } else if kind.is_file() {
                let relative = path
                    .strip_prefix(root)
                    .map_err(|e| format!("failed to name {}: {e}", path.display()))?
                    .to_string_lossy()
                    .into_owned();
                files.push(relative);
            } else {
                eprintln!("im      skipping {}: not a regular file", path.display());
            }
        }
    }
    Ok(files)
}

/// The archive member as a path that stays under the restore root —
/// `None` for the absolute, upward-traversing, or empty names an archive
/// has no business carrying.
fn safe_relative(name: &Path) -> Option<&Path> {
    if name.is_absolute() || name.as_os_str().is_empty() {
        return None;
    }
    for component in name.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            _ => return None,
        }
    }
    Some(name)
}

/// The mode a restored file is held to: 0600 for the things that carry
/// secrets — config toml, `*.keys`, the signing keys — and `None` for
/// everything else.
fn secret_mode(path: &Path) -> Option<u32> {
    let shown = path.to_string_lossy();
    if shown.ends_with(".toml") || shown.ends_with(".keys") || shown.ends_with(".key") {
        Some(0o600)
    } else {
        None
    }
}

/// Reads the archive's manifest, its first member — the pass that decides
/// whether the restore may start at all.
fn read_manifest(archive: &Path) -> Result<Manifest, String> {
    let file =
        File::open(archive).map_err(|e| format!("failed to open {}: {e}", archive.display()))?;
    for entry in tar::Archive::new(flate2::read::GzDecoder::new(file))
        .entries()
        .map_err(|e| format!("failed to read {}: {e}", archive.display()))?
    {
        let mut entry =
            entry.map_err(|e| format!("{} is damaged: {e}", archive.display()))?;
        let is_manifest = entry
            .path()
            .map_err(|e| format!("{} is damaged: {e}", archive.display()))?
            == Path::new(MANIFEST_NAME);
        if is_manifest {
            let mut body = String::new();
            entry
                .read_to_string(&mut body)
                .map_err(|e| format!("failed to read {MANIFEST_NAME}: {e}"))?;
            return serde_json::from_str(&body)
                .map_err(|e| format!("{}'s manifest does not parse: {e}", archive.display()));
        }
    }
    Err(format!("{} carries no {MANIFEST_NAME}", archive.display()))
}

/// The parent of the working directory: on the server the trees sit under
/// `$HOME`, the deploy directory the process runs from inside it.
fn default_root() -> PathBuf {
    let cwd = match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(e) => {
            eprintln!("im: cannot read the working directory: {e}");
            std::process::exit(2);
        }
    };
    match cwd.parent() {
        Some(parent) => parent.to_path_buf(),
        None => {
            eprintln!("im: no family root above {}", cwd.display());
            eprintln!("usage: pass --root DIR");
            std::process::exit(2);
        }
    }
}

/// The archive's default name: stamped, in the working directory.
fn archive_name() -> PathBuf {
    const STAMP: &[time::format_description::BorrowedFormatItem<'static>] =
        time::macros::format_description!(
            "im-pack-[year][month][day]-[hour][minute][second].tar.gz"
        );
    PathBuf::from(
        time::OffsetDateTime::now_utc()
            .format(STAMP)
            .unwrap_or_else(|_| "im-pack.tar.gz".into()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A throwaway tree under the OS temp dir, gone with the test.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> TempDir {
            let path = std::env::temp_dir()
                .join(format!("im-pack-{label}-{}", ulid::Ulid::generate()));
            fs::create_dir_all(&path).unwrap();
            TempDir(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write(path: &Path, bytes: &[u8]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// The data-driven gate: the keys are whatever the caller hands over —
    /// here `im` and a fixture sibling `xy` that is not in/iz — and the
    /// roundtrip treats them identically. Also the standing refusals: the
    /// archive lands 0600, secrets restore 0600, and a second unpack
    /// stops at the existing database unless --force names the overwrite.
    #[test]
    fn roundtrip_im_and_xy() {
        let source = TempDir::new("src");
        // im: the full tree — database trio, signing key, config, storage.
        write(&source.0.join("im/im.db"), b"im-db");
        write(&source.0.join("im/im.db-wal"), b"im-wal");
        write(&source.0.join("im/im.db-shm"), b"im-shm");
        write(&source.0.join("im/im.key"), b"im-key");
        write(&source.0.join("im/config/im.toml"), b"listen = \"127.0.0.1:7650\"\n");
        write(&source.0.join("im/storage/a/blob"), b"im-blob");
        // xy: a bare sibling — database and config only. `zz` has no tree
        // at all; its pack is a stderr line, not a failure.
        write(&source.0.join("xy/xy.db"), b"xy-db");
        write(&source.0.join("xy/config/xy.toml"), b"listen = \"127.0.0.1:8000\"\n");

        let keys = ["im".to_string(), "xy".to_string(), "zz".to_string()];
        let out = source.0.join("pack.tar.gz");
        pack(&source.0, &keys, &out).expect("pack succeeds");
        assert!(out.is_file());
        assert_eq!(mode_of(&out), 0o600, "the archive lands 0600");

        let destination = TempDir::new("dest");
        unpack(&out, &destination.0, false).expect("unpack into an empty root");
        for (relative, bytes) in [
            ("im/im.db", &b"im-db"[..]),
            ("im/im.db-wal", b"im-wal"),
            ("im/im.db-shm", b"im-shm"),
            ("im/im.key", b"im-key"),
            ("im/config/im.toml", b"listen = \"127.0.0.1:7650\"\n"),
            ("im/storage/a/blob", b"im-blob"),
            ("xy/xy.db", b"xy-db"),
            ("xy/config/xy.toml", b"listen = \"127.0.0.1:8000\"\n"),
        ] {
            assert_eq!(
                fs::read(destination.0.join(relative)).unwrap(),
                bytes,
                "{relative} must roundtrip"
            );
        }
        for secret in ["im/im.key", "im/config/im.toml", "xy/config/xy.toml"] {
            assert_eq!(
                mode_of(&destination.0.join(secret)),
                0o600,
                "{secret} must land 0600"
            );
        }

        // Without --force, a target database stops the restore before
        // anything moves.
        let problem = unpack(&out, &destination.0, false)
            .expect_err("an existing database must refuse the unpack");
        assert!(problem.contains("--force"), "the refusal names the way out: {problem}");
        assert_eq!(
            fs::read(destination.0.join("im/im.db")).unwrap(),
            b"im-db",
            "the refused unpack left the tree alone"
        );
        unpack(&out, &destination.0, true).expect("--force unpacks over it");
        assert_eq!(fs::read(destination.0.join("im/im.db")).unwrap(), b"im-db");
    }

    /// A member whose name climbs out of the restore root is refused, not
    /// extracted — a tampered archive cannot write past the root. The
    /// tar library refuses to *write* such a name, so the hostile archive
    /// is ustar bytes laid by hand, the way an attacker would.
    #[test]
    fn unpack_refuses_escaping_names() {
        use std::io::Write as _;

        let source = TempDir::new("evil-src");
        let archive = source.0.join("evil.tar.gz");

        let mut tar = Vec::new();
        raw_member(
            &mut tar,
            MANIFEST_NAME,
            br#"{"version":1,"packed_at":"now","services":[{"key":"xy","files":[]}]}"#,
        );
        raw_member(&mut tar, "../escape", b"gotcha");
        tar.extend_from_slice(&[0u8; 1024]);
        let mut gz = flate2::write::GzEncoder::new(
            File::create(&archive).unwrap(),
            flate2::Compression::default(),
        );
        gz.write_all(&tar).unwrap();
        gz.finish().unwrap();

        let destination = TempDir::new("evil-dest");
        let problem = unpack(&archive, &destination.0, false)
            .expect_err("an escaping member must refuse the unpack");
        assert!(problem.contains("safe relative"), "{problem}");
        assert!(
            !destination.0.parent().unwrap().join("escape").exists(),
            "nothing may land outside the root"
        );
    }

    /// One raw ustar member: header block, body, padding — no library
    /// path validation, so a hostile name travels through untouched.
    fn raw_member(tar: &mut Vec<u8>, name: &str, body: &[u8]) {
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[124..136].copy_from_slice(format!("{:011o}\0", body.len()).as_bytes());
        header[136..148].copy_from_slice(b"00000000000\0");
        header[148..156].copy_from_slice(b"        ");
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let sum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        tar.extend_from_slice(&header);
        tar.extend_from_slice(body);
        tar.extend(std::iter::repeat_n(0u8, (512 - body.len() % 512) % 512));
    }

    /// An archive whose manifest names a shape this binary does not know
    /// refuses itself instead of guessing.
    #[test]
    fn unpack_refuses_a_future_manifest() {
        let source = TempDir::new("future-src");
        let archive = source.0.join("future.tar.gz");
        let file = File::create(&archive).unwrap();
        let mut tar = tar::Builder::new(flate2::write::GzEncoder::new(
            file,
            flate2::Compression::default(),
        ));
        let manifest = br#"{"version":99,"packed_at":"tomorrow","services":[]}"#;
        let mut header = tar::Header::new_gnu();
        header.set_size(manifest.len() as u64);
        header.set_cksum();
        tar.append_data(&mut header, MANIFEST_NAME, &manifest[..]).unwrap();
        tar.into_inner().unwrap().finish().unwrap();

        let destination = TempDir::new("future-dest");
        let problem = unpack(&archive, &destination.0, false)
            .expect_err("an unknown manifest version must refuse");
        assert!(problem.contains("version"), "{problem}");
    }
}
