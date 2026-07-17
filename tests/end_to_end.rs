//! End-to-end: a real `init()` writes schema-conformant JSONL to the resolved file, honoring the
//! `DIG_LOG_DIR` override and the level env precedence. A subscriber is global + install-once, so
//! this single test drives the whole live path in one process.

use std::path::PathBuf;

use dig_logging::{init, RunContext, Service};
use serde_json::Value;

/// Poll for the rolling file to appear + contain our line — the writer thread is asynchronous.
fn read_when_ready(dir: &std::path::Path) -> String {
    let prefix = "dig-node.jsonl";
    for _ in 0..50 {
        if let Some(path) = std::fs::read_dir(dir)
            .ok()
            .into_iter()
            .flatten()
            .flatten()
            .map(|d| d.path())
            .find(|p| {
                p.file_name()
                    .map(|n| n.to_string_lossy().starts_with(prefix))
                    .unwrap_or(false)
            })
        {
            let contents = std::fs::read_to_string(&path).unwrap_or_default();
            if contents.contains("hello from the test") {
                return contents;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!(
        "log file with the expected line never appeared in {}",
        dir.display()
    );
}

#[test]
fn init_writes_conformant_jsonl_to_override_dir() {
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("DIG_LOG_DIR", tmp.path());
    std::env::set_var("DIG_LOG", "debug");

    let guard = init(Service {
        name: "dig-node",
        version: "9.9.9",
        run_context: RunContext::Service,
    })
    .expect("init once");

    let service_dir: PathBuf = tmp.path().join("dig-node");
    assert_eq!(
        guard.log_dir(),
        service_dir,
        "override dir joined with service"
    );

    tracing::info!(peer = "203.0.113.7", "hello from the test");

    let contents = read_when_ready(&service_dir);
    let line = contents
        .lines()
        .find(|l| l.contains("hello from the test"))
        .expect("our line is present");

    let record: Value = serde_json::from_str(line).expect("valid JSON line");
    assert_eq!(record["schema"], 1);
    assert_eq!(record["level"], "INFO");
    assert_eq!(record["service"], "dig-node");
    assert_eq!(record["service_version"], "9.9.9");
    assert_eq!(record["run_context"], "service");
    assert_eq!(record["message"], "hello from the test");
    assert_eq!(record["peer"], "203.0.113.7");
    assert!(record["run_id"].as_str().is_some(), "run_id stamped");
    assert!(
        record["ts"].as_str().unwrap().ends_with('Z'),
        "ts is UTC RFC3339"
    );

    std::env::remove_var("DIG_LOG_DIR");
    std::env::remove_var("DIG_LOG");
}
