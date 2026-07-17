//! Level-filter resolution (SPEC §5).
//!
//! One `EnvFilter` drives both sinks. Its directive is chosen by a fixed precedence — a persisted
//! operator choice, then the ecosystem-common `DIG_LOG`, then the Rust-conventional `RUST_LOG`, then
//! a noise-trimmed default. The choice is a PURE function of its four inputs so the precedence is
//! table-testable without the process environment.

/// The env var carrying an operator-set filter (ecosystem-common name), checked before `RUST_LOG`.
pub const ENV_DIG_LOG: &str = "DIG_LOG";

/// The Rust-conventional filter env var, kept working as the lowest-priority env source.
pub const ENV_RUST_LOG: &str = "RUST_LOG";

/// The baked-in default: `info`, with the chattiest transport crates trimmed to `warn`.
pub const DEFAULT_DIRECTIVE: &str = "info,hyper=warn,rustls=warn,h2=warn,tower=warn";

/// Resolve the effective filter directive by precedence (SPEC §5): the first non-empty of
/// `persisted` > `dig_log` > `rust_log`, else [`DEFAULT_DIRECTIVE`]. Whitespace-only inputs count as
/// empty (an exported-but-blank env var must not silence logging).
pub fn resolve_filter(
    persisted: Option<&str>,
    dig_log: Option<&str>,
    rust_log: Option<&str>,
) -> String {
    [persisted, dig_log, rust_log]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|value| !value.is_empty())
        .unwrap_or(DEFAULT_DIRECTIVE)
        .to_string()
}

/// Resolve the directive from the real environment given an optional persisted choice.
pub fn resolve_filter_from_env(persisted: Option<&str>) -> String {
    let dig_log = std::env::var(ENV_DIG_LOG).ok();
    let rust_log = std::env::var(ENV_RUST_LOG).ok();
    resolve_filter(persisted, dig_log.as_deref(), rust_log.as_deref())
}

/// The file (inside the service log dir) an operator's persisted `logs level` choice is stored in.
pub const LEVEL_FILE: &str = "level";

/// Read the persisted level directive from a service log `dir`, if any (`None` when absent/blank).
pub fn read_persisted_level(dir: &std::path::Path) -> Option<String> {
    std::fs::read_to_string(dir.join(LEVEL_FILE))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Persist an operator's level directive into a service log `dir` (SPEC §5 / §8.1 `logs level`).
pub fn write_persisted_level(dir: &std::path::Path, directive: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join(LEVEL_FILE), directive.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_beats_everything() {
        assert_eq!(
            resolve_filter(Some("debug"), Some("trace"), Some("warn")),
            "debug"
        );
    }

    #[test]
    fn dig_log_beats_rust_log() {
        assert_eq!(resolve_filter(None, Some("trace"), Some("warn")), "trace");
    }

    #[test]
    fn rust_log_used_when_only_source() {
        assert_eq!(resolve_filter(None, None, Some("error")), "error");
    }

    #[test]
    fn default_when_all_absent_or_blank() {
        assert_eq!(resolve_filter(None, None, None), DEFAULT_DIRECTIVE);
        assert_eq!(
            resolve_filter(Some("  "), Some(""), None),
            DEFAULT_DIRECTIVE
        );
    }

    #[test]
    fn persisted_level_round_trips_and_blank_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_persisted_level(dir.path()), None);
        write_persisted_level(dir.path(), "  debug,h2=warn  ").unwrap();
        assert_eq!(
            read_persisted_level(dir.path()),
            Some("debug,h2=warn".to_string())
        );
        write_persisted_level(dir.path(), "   ").unwrap();
        assert_eq!(
            read_persisted_level(dir.path()),
            None,
            "blank persisted level reads as unset"
        );
    }
}
