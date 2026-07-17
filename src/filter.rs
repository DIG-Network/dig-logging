//! Level-filter resolution (SPEC §5).
//!
//! One `EnvFilter` drives both sinks. Its directive is chosen by a fixed precedence — a persisted
//! operator choice, then the ecosystem-common `DIG_LOG`, then the Rust-conventional `RUST_LOG`, then
//! a noise-trimmed default. The choice is a PURE function of its inputs so the precedence is
//! table-testable without the process environment.
//!
//! Every candidate directive is VALIDATED against [`EnvFilter`](tracing_subscriber::EnvFilter)
//! before it is chosen (#726). A directive that does not parse is skipped, and resolution falls
//! through to the next valid source — ultimately the always-valid [`DEFAULT_DIRECTIVE`]. This is
//! load-bearing: the persisted `level` file survives restarts, so a single bad `logs level`
//! directive would otherwise make `init` fail on EVERY subsequent start and leave the service with
//! NO structured logging. Logging is NEVER disabled because a bad directive was persisted.

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

/// Does a directive parse as a valid [`EnvFilter`](tracing_subscriber::EnvFilter)? Pure — parsing a
/// directive string does not read the process environment, so this stays table-testable.
fn directive_is_valid(directive: &str) -> bool {
    tracing_subscriber::EnvFilter::try_new(directive).is_ok()
}

/// Resolve the effective directive by precedence AND validity (SPEC §5, #726): the first source
/// that is both non-empty AND parses as a valid `EnvFilter`, else the always-valid
/// [`DEFAULT_DIRECTIVE`]. A garbage persisted/env directive is thus SKIPPED rather than propagated —
/// logging is never disabled because a bad directive was supplied.
pub fn resolve_valid_filter(
    persisted: Option<&str>,
    dig_log: Option<&str>,
    rust_log: Option<&str>,
) -> String {
    [persisted, dig_log, rust_log]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|value| !value.is_empty() && directive_is_valid(value))
        .unwrap_or(DEFAULT_DIRECTIVE)
        .to_string()
}

/// Resolve the directive from the real environment given an optional persisted choice. Validates
/// every candidate ([`resolve_valid_filter`]) so the returned directive always parses (#726).
pub fn resolve_filter_from_env(persisted: Option<&str>) -> String {
    let dig_log = std::env::var(ENV_DIG_LOG).ok();
    let rust_log = std::env::var(ENV_RUST_LOG).ok();
    resolve_valid_filter(persisted, dig_log.as_deref(), rust_log.as_deref())
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
///
/// Rejects an invalid directive up-front ([`std::io::ErrorKind::InvalidInput`]) so garbage is never
/// persisted (#726) — a typo in `logs level` fails loudly at write time instead of silently
/// breaking logging on the next start. The read path ([`resolve_valid_filter`]) is the belt-and-
/// braces backstop for any directive persisted before this validation existed.
pub fn write_persisted_level(dir: &std::path::Path, directive: &str) -> std::io::Result<()> {
    let directive = directive.trim();
    if !directive_is_valid(directive) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid log filter directive: {directive:?}"),
        ));
    }
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join(LEVEL_FILE), directive)
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

    // --- #726: a persisted GARBAGE directive must never disable logging ---

    /// REGRESSION (#726): a garbage persisted directive is INVALID for `EnvFilter`. With no env
    /// override, resolution must fall back to the known-valid [`DEFAULT_DIRECTIVE`] — NEVER return
    /// the garbage (which would make `init` error and the consumer serve with NO structured log).
    #[test]
    fn garbage_persisted_falls_back_to_default() {
        // An invalid LEVEL name after `=` is what `EnvFilter::try_new` rejects.
        assert_eq!(
            resolve_valid_filter(Some("target=boguslevel"), None, None),
            DEFAULT_DIRECTIVE
        );
    }

    /// A garbage persisted directive is SKIPPED in favour of a still-valid lower-precedence source
    /// (a valid `RUST_LOG`), rather than collapsing straight to the default.
    #[test]
    fn garbage_persisted_falls_through_to_valid_env() {
        assert_eq!(
            resolve_valid_filter(Some("info,bad=notalevel"), None, Some("debug")),
            "debug"
        );
    }

    /// A VALID persisted directive still wins by precedence (validation must not change the happy path).
    #[test]
    fn valid_persisted_still_wins() {
        assert_eq!(
            resolve_valid_filter(Some("debug,h2=warn"), Some("trace"), None),
            "debug,h2=warn"
        );
    }

    /// `resolve_filter_from_env` reading a garbage persisted `level` file yields a VALID directive
    /// (the default), so `EnvFilter::try_new` on it always succeeds and `init` never fails.
    #[test]
    fn from_env_with_garbage_persisted_is_valid() {
        let resolved = resolve_filter_from_env(Some("app=verboze"));
        assert!(
            tracing_subscriber::EnvFilter::try_new(&resolved).is_ok(),
            "resolved directive must parse: {resolved}"
        );
    }

    /// `write_persisted_level` rejects an invalid directive up-front so garbage is never persisted.
    #[test]
    fn write_rejects_invalid_directive() {
        let dir = tempfile::tempdir().unwrap();
        assert!(write_persisted_level(dir.path(), "target=boguslevel").is_err());
        assert_eq!(
            read_persisted_level(dir.path()),
            None,
            "nothing should have been persisted"
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
