//! The redacted log bundle (SPEC §8.3).
//!
//! A `logs bundle` produces a zip of REDACTED log files plus a `manifest.json`, safe to attach to a
//! bug report. It NEVER contains config files, key material, or un-redacted logs — every file is run
//! through [`redact`](crate::redact) on the way in.

use std::io::{Cursor, Write};
use std::path::Path;

use serde::Serialize;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

use crate::error::Result;
use crate::redact;

/// A file recorded in the bundle manifest.
#[derive(Debug, Serialize)]
pub struct ManifestFile {
    /// The archive-relative name (`<service>/<file>` under `--all`).
    pub name: String,
    /// The redacted byte length written to the archive.
    pub bytes: u64,
}

/// The bundle manifest (SPEC §8.3), written to `manifest.json` at the archive root.
#[derive(Debug, Serialize)]
pub struct Manifest {
    /// Manifest schema version.
    pub schema: u32,
    /// The service the bundle was produced for (or `all`).
    pub service: String,
    /// The producing binary's version.
    pub service_version: String,
    /// The host OS (`std::env::consts::OS`).
    pub os: String,
    /// The host arch (`std::env::consts::ARCH`).
    pub arch: String,
    /// Bundle creation time, RFC 3339 UTC.
    pub created_at: String,
    /// The redaction rule-set version applied to every file (SPEC §8.2).
    pub redaction_rules_version: u32,
    /// The redacted files included.
    pub files: Vec<ManifestFile>,
}

/// A named log file's raw text, before redaction.
pub struct SourceFile {
    /// The archive-relative name.
    pub name: String,
    /// The raw file contents.
    pub contents: String,
}

/// Write a redacted zip bundle of `sources` to an in-memory buffer, returning the zip bytes.
///
/// Kept buffer-based (not path-based) so it is unit-testable without a filesystem: the CLI reads the
/// log dir into [`SourceFile`]s, calls this, and writes the bytes to the chosen output path.
pub fn build(
    service: &str,
    service_version: &str,
    created_at: &str,
    sources: &[SourceFile],
) -> Result<Vec<u8>> {
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    let mut manifest_files = Vec::with_capacity(sources.len());
    for source in sources {
        let redacted = redact::text(&source.contents);
        zip.start_file(&source.name, options)?;
        zip.write_all(redacted.as_bytes())?;
        manifest_files.push(ManifestFile {
            name: source.name.clone(),
            bytes: redacted.len() as u64,
        });
    }

    let manifest = Manifest {
        schema: 1,
        service: service.to_string(),
        service_version: service_version.to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        created_at: created_at.to_string(),
        redaction_rules_version: redact::RULES_VERSION,
        files: manifest_files,
    };
    zip.start_file("manifest.json", options)?;
    zip.write_all(serde_json::to_vec_pretty(&manifest)?.as_slice())?;

    Ok(zip.finish()?.into_inner())
}

/// Read a service's rotated log files from `dir` into [`SourceFile`]s (raw, pre-redaction). Skips
/// unreadable entries; names are the bare file names for a single-service bundle.
pub fn read_service_dir(dir: &Path, service: &str) -> Vec<SourceFile> {
    let prefix = format!("{service}.jsonl");
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|dirent| {
            let path = dirent.path();
            let name = path.file_name()?.to_string_lossy().into_owned();
            if !name.starts_with(&prefix) {
                return None;
            }
            let contents = std::fs::read_to_string(&path).ok()?;
            Some(SourceFile { name, contents })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn bundle_round_trips_redacted_with_manifest() {
        let seed =
            "abandon ability able about above absent absorb abstract absurd abuse access accident";
        let sources = vec![SourceFile {
            name: "dig-node.jsonl.2026-07-16".into(),
            contents: format!(r#"{{"message":"seed {seed}","store":"abc123"}}"#),
        }];
        let bytes = build("dig-node", "1.0.0", "2026-07-16T00:00:00Z", &sources).unwrap();

        let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
        // Manifest present + correct.
        let mut manifest = String::new();
        archive
            .by_name("manifest.json")
            .unwrap()
            .read_to_string(&mut manifest)
            .unwrap();
        assert!(manifest.contains("\"redaction_rules_version\": 1"));
        // Log file present, secret gone, public id kept.
        let mut log = String::new();
        archive
            .by_name("dig-node.jsonl.2026-07-16")
            .unwrap()
            .read_to_string(&mut log)
            .unwrap();
        assert!(!log.contains("abandon"), "secret must be absent: {log}");
        assert!(log.contains("[REDACTED:mnemonic]"));
        assert!(log.contains("abc123"), "store id kept");
    }
}
