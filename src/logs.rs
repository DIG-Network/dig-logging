//! The reusable `logs` CLI verb set (SPEC §8.1).
//!
//! Every DIG binary mounts this verbatim so `<bin> logs path|tail|level|bundle` behaves identically
//! everywhere: `command()` returns the `logs` clap subcommand to add, and `run()` dispatches it. The
//! rendering/selection logic is factored into pure helpers so it is unit-testable without a terminal.

use std::io::Write;
use std::path::Path;

use clap::{Arg, ArgAction, ArgMatches, Command};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::{Date, Duration, OffsetDateTime};

use crate::error::Result;
use crate::{bundle, dirs, filter, Service};

/// The `logs` subcommand a consumer adds to its clap app (SPEC §8.1).
pub fn command() -> Command {
    Command::new("logs")
        .about("Inspect, tune, and bundle this service's logs")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("path")
                .about("Print the resolved log directory")
                .arg(json_flag()),
        )
        .subcommand(
            Command::new("tail")
                .about("Print the most recent log lines (human by default)")
                .arg(
                    Arg::new("follow")
                        .short('f')
                        .long("follow")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("lines")
                        .short('n')
                        .long("lines")
                        .default_value("50"),
                )
                .arg(Arg::new("level").long("level"))
                .arg(json_flag()),
        )
        .subcommand(
            Command::new("level")
                .about("Show or persist the log level filter")
                .arg(Arg::new("filter").index(1))
                .arg(json_flag()),
        )
        .subcommand(
            Command::new("bundle")
                .about("Write a redacted zip of the logs for a bug report")
                .arg(
                    Arg::new("out")
                        .short('o')
                        .long("out")
                        .default_value("dig-logs.zip"),
                )
                .arg(Arg::new("all").long("all").action(ArgAction::SetTrue))
                .arg(
                    Arg::new("since")
                        .long("since")
                        .help("Limit to files no older than a duration, e.g. 24h or 7d"),
                ),
        )
}

fn json_flag() -> Arg {
    Arg::new("json")
        .long("json")
        .action(ArgAction::SetTrue)
        .help("Emit machine-readable JSON")
}

/// Dispatch a matched `logs` subcommand for `service` (SPEC §8.1).
pub fn run(service: &Service, matches: &ArgMatches) -> Result<()> {
    let dir = dirs::log_dir(service.name);
    match matches.subcommand() {
        Some(("path", m)) => run_path(&dir, m.get_flag("json")),
        Some(("tail", m)) => run_tail(&dir, service.name, m),
        Some(("level", m)) => run_level(&dir, m),
        Some(("bundle", m)) => run_bundle(service, &dir, m),
        _ => Ok(()),
    }
}

fn run_path(dir: &Path, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::json!({ "dir": dir.to_string_lossy() }));
    } else {
        println!("{}", dir.display());
    }
    Ok(())
}

fn run_tail(dir: &Path, service: &str, m: &ArgMatches) -> Result<()> {
    let n: usize = m
        .get_one::<String>("lines")
        .and_then(|v| v.parse().ok())
        .unwrap_or(50);
    let min_level = m.get_one::<String>("level").map(String::as_str);
    let json = m.get_flag("json");

    let Some(file) = newest_log_file(dir, service) else {
        return Ok(()); // no logs yet
    };
    let contents = std::fs::read_to_string(&file).unwrap_or_default();
    for line in select_tail(&contents, n, min_level) {
        let out = if json {
            line.to_string()
        } else {
            render_human(line)
        };
        println!("{out}");
    }
    if m.get_flag("follow") {
        follow(&file, min_level, json)?;
    }
    Ok(())
}

fn run_level(dir: &Path, m: &ArgMatches) -> Result<()> {
    if let Some(directive) = m.get_one::<String>("filter") {
        filter::write_persisted_level(dir, directive)?;
    }
    let effective = filter::resolve_filter_from_env(filter::read_persisted_level(dir).as_deref());
    if m.get_flag("json") {
        println!("{}", serde_json::json!({ "filter": effective }));
    } else {
        println!("{effective}");
    }
    Ok(())
}

fn run_bundle(service: &Service, dir: &Path, m: &ArgMatches) -> Result<()> {
    let out = m
        .get_one::<String>("out")
        .map(String::as_str)
        .unwrap_or("dig-logs.zip");
    let all = m.get_flag("all");
    let now = OffsetDateTime::now_utc();
    let created_at = now.format(&Rfc3339).unwrap_or_default();
    let since = m
        .get_one::<String>("since")
        .and_then(|s| since_cutoff(s, now.date()));

    let sources = if all {
        // `--all`: every service under the shared root (SPEC §8.1) — nested `<service>/<file>`.
        let root = dir.parent().unwrap_or(dir).to_path_buf();
        collect_all_services(&root, since)
    } else {
        bundle::read_service_dir(dir, service.name, since)
    };
    let service_label = if all { "all" } else { service.name };
    let bytes = bundle::build(service_label, service.version, &created_at, &sources)?;
    std::fs::File::create(out)?.write_all(&bytes)?;
    println!("Wrote redacted bundle: {out} ({} file(s))", sources.len());
    Ok(())
}

/// Read every `<service>/` subdir under the shared log `root`, prefixing archive names with the
/// service so an `--all` bundle keeps services separated. `since` narrows each service's files to the
/// `--since` window (SPEC §8.1).
fn collect_all_services(root: &Path, since: Option<Date>) -> Vec<bundle::SourceFile> {
    let mut sources = Vec::new();
    let dirents = std::fs::read_dir(root).into_iter().flatten().flatten();
    for dirent in dirents {
        if !dirent.path().is_dir() {
            continue;
        }
        let service = dirent.file_name().to_string_lossy().into_owned();
        for mut file in bundle::read_service_dir(&dirent.path(), &service, since) {
            file.name = format!("{service}/{}", file.name);
            sources.push(file);
        }
    }
    sources
}

/// Resolve a `--since` duration (`24h`, `7d`) to the OLDEST rotation date to include, relative to
/// `today`. Sub-day units round UP to whole days (files rotate daily, §4.3). An unparseable value
/// yields `None` (no filtering) so a typo never silently drops logs from a bug report.
fn since_cutoff(spec: &str, today: Date) -> Option<Date> {
    let spec = spec.trim();
    let split = spec.find(|c: char| !c.is_ascii_digit())?;
    let (num, unit) = spec.split_at(split);
    let n: i64 = num.parse().ok()?;
    let days = match unit {
        "d" => n,
        "h" => (n + 23) / 24,
        _ => return None,
    };
    Some(today.saturating_sub(Duration::days(days)))
}

/// The newest rotated log file for `service` in `dir`, by name (dates sort lexically), if any.
fn newest_log_file(dir: &Path, service: &str) -> Option<std::path::PathBuf> {
    let prefix = format!("{service}.jsonl");
    std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|d| d.path())
        .filter(|p| {
            p.file_name()
                .map(|n| n.to_string_lossy().starts_with(&prefix))
                .unwrap_or(false)
        })
        .max()
}

/// The last `n` lines of `contents`, optionally filtered to records at or above `min_level`.
fn select_tail<'a>(contents: &'a str, n: usize, min_level: Option<&str>) -> Vec<&'a str> {
    let filtered: Vec<&str> = contents
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter(|line| {
            min_level
                .map(|min| level_at_least(line, min))
                .unwrap_or(true)
        })
        .collect();
    let start = filtered.len().saturating_sub(n);
    filtered[start..].to_vec()
}

/// Does a JSONL `line`'s level rank at or above `min`? (Unparseable/level-less lines pass.)
fn level_at_least(line: &str, min: &str) -> bool {
    let Some(level) = parse_level(line) else {
        return true;
    };
    level_rank(&level) >= level_rank(&min.to_ascii_uppercase())
}

fn parse_level(line: &str) -> Option<String> {
    serde_json::from_str::<Value>(line)
        .ok()?
        .get("level")?
        .as_str()
        .map(str::to_string)
}

/// Severity rank (ERROR highest) so `--level warn` keeps WARN + ERROR.
fn level_rank(level: &str) -> u8 {
    match level {
        "ERROR" => 5,
        "WARN" => 4,
        "INFO" => 3,
        "DEBUG" => 2,
        "TRACE" => 1,
        _ => 0,
    }
}

/// Render one JSONL line as compact human text: `TS  LEVEL target: message  {extra fields}`.
fn render_human(line: &str) -> String {
    let Ok(Value::Object(mut record)) = serde_json::from_str::<Value>(line) else {
        return line.to_string(); // not our JSON — show it raw
    };
    let take = |m: &mut serde_json::Map<String, Value>, k: &str| {
        m.remove(k)
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default()
    };
    let ts = take(&mut record, "ts");
    let level = take(&mut record, "level");
    let target = take(&mut record, "target");
    let message = take(&mut record, "message");
    for reserved in [
        "schema",
        "service",
        "service_version",
        "run_context",
        "run_id",
    ] {
        record.remove(reserved);
    }
    let extra = if record.is_empty() {
        String::new()
    } else {
        format!("  {}", Value::Object(record))
    };
    format!("{ts}  {level:5} {target}: {message}{extra}")
}

/// Follow a growing log file, rendering new lines as they arrive (SPEC §8.1 `-f`).
fn follow(file: &Path, min_level: Option<&str>, json: bool) -> Result<()> {
    use std::io::{BufRead, BufReader, Seek, SeekFrom};
    let mut reader = BufReader::new(std::fs::File::open(file)?);
    reader.seek(SeekFrom::End(0))?;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            std::thread::sleep(std::time::Duration::from_millis(250));
            continue;
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty()
            || !min_level
                .map(|m| level_at_least(trimmed, m))
                .unwrap_or(true)
        {
            continue;
        }
        println!(
            "{}",
            if json {
                trimmed.to_string()
            } else {
                render_human(trimmed)
            }
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = r#"{"schema":1,"ts":"2026-07-16T00:00:01Z","level":"INFO","target":"a","message":"one","run_id":"r"}"#;
    const B: &str = r#"{"schema":1,"ts":"2026-07-16T00:00:02Z","level":"WARN","target":"b","message":"two","peer":"1.2.3.4"}"#;
    const C: &str = r#"{"schema":1,"ts":"2026-07-16T00:00:03Z","level":"ERROR","target":"c","message":"three"}"#;

    #[test]
    fn tail_takes_last_n() {
        let contents = [A, B, C].join("\n");
        assert_eq!(select_tail(&contents, 2, None), vec![B, C]);
    }

    #[test]
    fn tail_filters_by_level() {
        let contents = [A, B, C].join("\n");
        // warn+ drops the INFO line.
        assert_eq!(select_tail(&contents, 10, Some("warn")), vec![B, C]);
    }

    #[test]
    fn human_render_shows_core_fields_and_extras() {
        let rendered = render_human(B);
        assert!(rendered.contains("WARN"));
        assert!(rendered.contains("b: two"));
        assert!(rendered.contains("peer"), "extra fields shown: {rendered}");
        assert!(
            !rendered.contains("schema"),
            "reserved fields hidden: {rendered}"
        );
    }

    #[test]
    fn command_builds_with_all_verbs() {
        let cmd = command();
        let names: Vec<_> = cmd.get_subcommands().map(|c| c.get_name()).collect();
        assert!(names.contains(&"path") && names.contains(&"tail"));
        assert!(names.contains(&"level") && names.contains(&"bundle"));
    }

    #[test]
    fn since_cutoff_parses_days_and_hours() {
        use time::Month;
        let today = Date::from_calendar_date(2026, Month::July, 16).unwrap();
        assert_eq!(
            since_cutoff("7d", today),
            Date::from_calendar_date(2026, Month::July, 9).ok()
        );
        // 24h → 1 day; 25h rounds up to 2 days.
        assert_eq!(
            since_cutoff("24h", today),
            Date::from_calendar_date(2026, Month::July, 15).ok()
        );
        assert_eq!(
            since_cutoff("25h", today),
            Date::from_calendar_date(2026, Month::July, 14).ok()
        );
        // Garbage → no filtering, never silently drops logs.
        assert_eq!(since_cutoff("nonsense", today), None);
        assert_eq!(since_cutoff("7w", today), None);
    }
}
