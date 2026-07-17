//! Exercise the shared `logs` verbs end-to-end against a `DIG_LOG_DIR` temp root: `path`, `level`
//! (show + persist), `tail` (level filter), and `bundle` (single + `--all`, redacted). No global
//! subscriber is installed, so these run in one process without clashing with the init path.

use std::fs;

use dig_logging::logs;
use dig_logging::{RunContext, Service};

const SVC: Service = Service {
    name: "dig-node",
    version: "1.2.3",
    run_context: RunContext::Service,
};

const SEED12: &str =
    "abandon ability able about above absent absorb abstract absurd abuse access accident";

fn seed_logs(root: &std::path::Path) {
    let dir = root.join("dig-node");
    fs::create_dir_all(&dir).unwrap();
    let error_line = format!(
        r#"{{"schema":1,"ts":"2026-07-16T00:00:03Z","level":"ERROR","target":"c","message":"seed {SEED12}","store":"abc123"}}"#
    );
    let lines = format!(
        "{}\n{}\n{}\n",
        r#"{"schema":1,"ts":"2026-07-16T00:00:01Z","level":"INFO","target":"a","message":"boot","run_id":"r"}"#,
        r#"{"schema":1,"ts":"2026-07-16T00:00:02Z","level":"WARN","target":"b","message":"slow"}"#,
        error_line,
    );
    fs::write(dir.join("dig-node.jsonl.2026-07-16"), lines).unwrap();
}

fn run(args: &[&str]) {
    let app = clap::Command::new("dig-node").subcommand(logs::command());
    let matches = app.get_matches_from(std::iter::once("dig-node").chain(args.iter().copied()));
    let (_, sub) = matches.subcommand().unwrap();
    logs::run(&SVC, sub).expect("logs verb runs");
}

#[test]
fn verbs_cover_path_level_tail_and_bundle() {
    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("DIG_LOG_DIR", tmp.path());
    std::env::remove_var("DIG_LOG");
    std::env::remove_var("RUST_LOG");
    seed_logs(tmp.path());
    let service_dir = tmp.path().join("dig-node");

    // path (both renderings).
    run(&["logs", "path"]);
    run(&["logs", "path", "--json"]);

    // tail with a level filter (renders human; ERROR+WARN pass, INFO drops — just must not error).
    run(&["logs", "tail", "-n", "10", "--level", "warn"]);
    run(&["logs", "tail", "--json", "-n", "1"]);

    // level: persist then show.
    run(&["logs", "level", "debug,hyper=warn"]);
    assert_eq!(
        dig_logging::resolve_filter(
            fs::read_to_string(service_dir.join("level"))
                .ok()
                .as_deref(),
            None,
            None,
        ),
        "debug,hyper=warn",
        "persisted level round-trips",
    );
    run(&["logs", "level", "--json"]);

    // bundle (single service) — redacted zip on disk, secret gone.
    let out = tmp.path().join("bundle.zip");
    run(&["logs", "bundle", "-o", out.to_str().unwrap()]);
    let zip_bytes = fs::read(&out).unwrap();
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(zip_bytes)).unwrap();
    let mut log = String::new();
    use std::io::Read;
    archive
        .by_name("dig-node.jsonl.2026-07-16")
        .unwrap()
        .read_to_string(&mut log)
        .unwrap();
    assert!(!log.contains("abandon"), "mnemonic redacted in bundle");
    assert!(log.contains("abc123"), "store id kept in bundle");

    // bundle --all — nests under <service>/.
    let out_all = tmp.path().join("all.zip");
    run(&["logs", "bundle", "--all", "-o", out_all.to_str().unwrap()]);
    let archive_all =
        zip::ZipArchive::new(std::io::Cursor::new(fs::read(&out_all).unwrap())).unwrap();
    assert!(
        archive_all
            .file_names()
            .any(|n| n == "dig-node/dig-node.jsonl.2026-07-16"),
        "--all nests per service",
    );

    std::env::remove_var("DIG_LOG_DIR");
}
