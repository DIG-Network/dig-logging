//! The byte-cap janitor (SPEC §4).
//!
//! `tracing-appender`'s daily rotation + `max_log_files` bounds the file COUNT, but a runaway-error
//! day can still balloon a single file past any reasonable disk budget. The janitor adds a
//! total-bytes cap per service dir: while the directory's `.jsonl.*` files exceed the cap, the
//! oldest (by modified time) is deleted. The current day's file is protected so live logging never
//! loses its active file. Runs once at init and hourly thereafter.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// The env var overriding the retention day count (`tracing-appender` `max_log_files`), default 7.
pub const ENV_RETENTION_DAYS: &str = "DIG_LOG_RETENTION_DAYS";

/// The env var overriding the per-service-dir byte cap, default 50 MiB.
pub const ENV_MAX_BYTES: &str = "DIG_LOG_MAX_BYTES";

/// Default retained daily files (SPEC §4).
pub const DEFAULT_RETENTION_DAYS: usize = 7;

/// Default per-service byte cap: 50 MiB (SPEC §4).
pub const DEFAULT_MAX_BYTES: u64 = 50 * 1024 * 1024;

/// Read a `usize` env override via an injected getter, falling back to `default` when unset/invalid.
pub fn retention_days<G: Fn(&str) -> Option<String>>(get: G) -> usize {
    get(ENV_RETENTION_DAYS)
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|days| *days > 0)
        .unwrap_or(DEFAULT_RETENTION_DAYS)
}

/// Read the byte cap env override via an injected getter, falling back to [`DEFAULT_MAX_BYTES`].
pub fn max_bytes<G: Fn(&str) -> Option<String>>(get: G) -> u64 {
    get(ENV_MAX_BYTES)
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|bytes| *bytes > 0)
        .unwrap_or(DEFAULT_MAX_BYTES)
}

/// A log file with the facts the janitor sorts + prunes on.
struct Entry {
    path: PathBuf,
    bytes: u64,
    modified: SystemTime,
}

/// List the service's rotated log files (`<service>.jsonl.*`), newest excluded from deletion by the
/// caller. Unreadable entries are skipped (best-effort cleanup must never fail logging).
fn list_log_files(dir: &Path, service: &str) -> Vec<Entry> {
    let prefix = format!("{service}.jsonl");
    let mut entries: Vec<Entry> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|dirent| {
            let path = dirent.path();
            let name = path.file_name()?.to_string_lossy().into_owned();
            if !name.starts_with(&prefix) {
                return None;
            }
            let meta = dirent.metadata().ok()?;
            Some(Entry {
                path,
                bytes: meta.len(),
                modified: meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            })
        })
        .collect();
    // Oldest first, so deletion walks from the front.
    entries.sort_by_key(|entry| entry.modified);
    entries
}

/// Enforce the byte cap on `dir` for `service`: delete oldest files while the total exceeds
/// `max_bytes`, never deleting the newest (the live) file. Returns the number of files deleted.
/// Pure with respect to its inputs (a real directory) — table-testable against a temp dir.
pub fn enforce_byte_cap(dir: &Path, service: &str, max_bytes: u64) -> usize {
    let entries = list_log_files(dir, service);
    let mut total: u64 = entries.iter().map(|entry| entry.bytes).sum();
    let mut deleted = 0;
    // Protect the newest file: iterate all-but-last, oldest first.
    let prunable = entries.len().saturating_sub(1);
    for entry in entries.iter().take(prunable) {
        if total <= max_bytes {
            break;
        }
        if fs::remove_file(&entry.path).is_ok() {
            total -= entry.bytes;
            deleted += 1;
        }
    }
    deleted
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::thread::sleep;
    use std::time::Duration;

    fn write_file(dir: &Path, name: &str, bytes: usize) {
        let mut file = fs::File::create(dir.join(name)).unwrap();
        file.write_all(&vec![b'x'; bytes]).unwrap();
    }

    #[test]
    fn env_overrides_parse_or_fall_back() {
        assert_eq!(retention_days(|_| Some("14".into())), 14);
        assert_eq!(
            retention_days(|_| Some("junk".into())),
            DEFAULT_RETENTION_DAYS
        );
        assert_eq!(retention_days(|_| None), DEFAULT_RETENTION_DAYS);
        assert_eq!(max_bytes(|_| Some("1024".into())), 1024);
        assert_eq!(max_bytes(|_| None), DEFAULT_MAX_BYTES);
    }

    #[test]
    fn prunes_oldest_until_under_cap_and_keeps_newest() {
        let dir = tempfile::tempdir().unwrap();
        // Three 1 KiB files, distinct mtimes; cap at 1.5 KiB should leave the newest only.
        for (i, name) in [
            "dig-node.jsonl.2026-07-14",
            "dig-node.jsonl.2026-07-15",
            "dig-node.jsonl.2026-07-16",
        ]
        .iter()
        .enumerate()
        {
            write_file(dir.path(), name, 1024);
            if i < 2 {
                sleep(Duration::from_millis(20));
            }
        }
        let deleted = enforce_byte_cap(dir.path(), "dig-node", 1536);
        assert_eq!(deleted, 2);
        assert!(
            dir.path().join("dig-node.jsonl.2026-07-16").exists(),
            "newest is protected"
        );
        assert!(!dir.path().join("dig-node.jsonl.2026-07-14").exists());
    }

    #[test]
    fn under_cap_deletes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "dig-dns.jsonl.2026-07-16", 100);
        assert_eq!(
            enforce_byte_cap(dir.path(), "dig-dns", DEFAULT_MAX_BYTES),
            0
        );
    }

    #[test]
    fn ignores_foreign_files() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "unrelated.txt", 10_000);
        write_file(dir.path(), "dig-node.jsonl.2026-07-16", 100);
        // Even a tiny cap must not touch a non-matching file.
        enforce_byte_cap(dir.path(), "dig-node", 1);
        assert!(dir.path().join("unrelated.txt").exists());
    }
}
