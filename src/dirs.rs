//! Log-directory resolution (SPEC §3).
//!
//! One machine-wide log root, one subdirectory per service, SYSTEM/root-writable and
//! **user-readable** — deliberately unlike the owner-only #501 state dirs, because logs are operator
//! diagnostics (secrets are barred at source and redacted at bundle). Resolution precedence:
//!
//! 1. `DIG_LOG_DIR` — its value is the log ROOT; the service dir is `$DIG_LOG_DIR/<service>`.
//! 2. the per-OS machine root, when that service dir can be created + written (a privileged run).
//! 3. the per-user dev fallback, when the machine root is not creatable/writable (an unprivileged
//!    `cargo run`), mirroring dig-node's #501 dev-fallback pattern.
//!
//! The CLI and the service resolve identically, so `<bin> logs path` names the directory the service
//! writes to. Resolution is a PURE function of an injected env-getter + a "can this dir be created?"
//! probe, so every branch is table-testable without touching the real filesystem or environment.

use std::path::PathBuf;

/// The env var that overrides the log ROOT outright (tests, custom deploys).
pub const ENV_LOG_DIR: &str = "DIG_LOG_DIR";

/// Resolve the log directory for `service` from an injected env-getter and a dir-creatable probe.
///
/// `get` reads an env var (`None`/blank = unset). `can_create` answers "can this exact directory be
/// created and written?" — the caller wires it to the real filesystem in [`log_dir`], and tests
/// inject a closure to exercise the machine-root vs dev-fallback branch deterministically.
pub fn resolve_log_dir<G, C>(service: &str, get: G, can_create: C) -> PathBuf
where
    G: Fn(&str) -> Option<String>,
    C: Fn(&std::path::Path) -> bool,
{
    let read = |key: &str| {
        get(key)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    };

    // 1. Explicit override wins unconditionally.
    if let Some(root) = read(ENV_LOG_DIR) {
        return PathBuf::from(root).join(service);
    }

    // 2. Machine root when its service dir is creatable; 3. else the per-user dev fallback.
    let machine = machine_root(&read).join(service);
    if can_create(&machine) {
        return machine;
    }
    dev_root(&read).join(service)
}

/// The resolved service log directory for this process, wiring the real environment + a filesystem
/// creatable-probe into [`resolve_log_dir`].
pub fn log_dir(service: &str) -> PathBuf {
    resolve_log_dir(
        service,
        |key| std::env::var(key).ok(),
        |path| std::fs::create_dir_all(path).is_ok(),
    )
}

/// The machine-wide log root (SPEC §3): `%PROGRAMDATA%\DigNetwork\logs` on Windows,
/// `/Library/Logs/DigNetwork` on macOS, `/var/log/dig` on Linux.
#[cfg(windows)]
fn machine_root<R: Fn(&str) -> Option<String>>(read: &R) -> PathBuf {
    let base = read("ProgramData").unwrap_or_else(|| r"C:\ProgramData".to_string());
    PathBuf::from(base).join("DigNetwork").join("logs")
}

#[cfg(target_os = "macos")]
fn machine_root<R: Fn(&str) -> Option<String>>(_read: &R) -> PathBuf {
    PathBuf::from("/Library/Logs/DigNetwork")
}

#[cfg(all(unix, not(target_os = "macos")))]
fn machine_root<R: Fn(&str) -> Option<String>>(_read: &R) -> PathBuf {
    PathBuf::from("/var/log/dig")
}

/// The per-user dev-fallback log root (SPEC §3): `%LOCALAPPDATA%\DigNetwork\logs` on Windows,
/// `~/Library/Logs/DigNetwork` on macOS, `${XDG_STATE_HOME:-~/.local/state}/dig/logs` on Linux.
#[cfg(windows)]
fn dev_root<R: Fn(&str) -> Option<String>>(read: &R) -> PathBuf {
    let base = read("LOCALAPPDATA")
        .or_else(|| read("ProgramData"))
        .unwrap_or_else(|| r"C:\ProgramData".to_string());
    PathBuf::from(base).join("DigNetwork").join("logs")
}

#[cfg(target_os = "macos")]
fn dev_root<R: Fn(&str) -> Option<String>>(read: &R) -> PathBuf {
    let home = read("HOME").unwrap_or_else(|| "/tmp".to_string());
    PathBuf::from(home)
        .join("Library")
        .join("Logs")
        .join("DigNetwork")
}

#[cfg(all(unix, not(target_os = "macos")))]
fn dev_root<R: Fn(&str) -> Option<String>>(read: &R) -> PathBuf {
    if let Some(state) = read("XDG_STATE_HOME") {
        return PathBuf::from(state).join("dig").join("logs");
    }
    let home = read("HOME").unwrap_or_else(|| "/tmp".to_string());
    PathBuf::from(home)
        .join(".local")
        .join("state")
        .join("dig")
        .join("logs")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::Path;

    /// Build an env-getter over a fixed map, so a test names exactly the vars it sets.
    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |key| map.get(key).cloned()
    }

    #[test]
    fn override_wins_and_joins_service() {
        let dir = resolve_log_dir("dig-node", env(&[(ENV_LOG_DIR, "/custom/root")]), |_| true);
        assert_eq!(dir, Path::new("/custom/root").join("dig-node"));
    }

    #[test]
    fn blank_override_is_ignored() {
        // A blank override must NOT shadow the machine root (a common empty-env-var footgun).
        let dir = resolve_log_dir("dig-dns", env(&[(ENV_LOG_DIR, "   ")]), |_| true);
        assert!(dir.ends_with(Path::new("dig-dns")));
        assert!(!dir.starts_with("/custom"));
    }

    #[test]
    fn machine_root_used_when_creatable() {
        let dir = resolve_log_dir("dig-updater", env(&[]), |_| true);
        assert!(dir.ends_with(Path::new("dig-updater")));
        #[cfg(all(unix, not(target_os = "macos")))]
        assert_eq!(dir, Path::new("/var/log/dig/dig-updater"));
        #[cfg(target_os = "macos")]
        assert_eq!(dir, Path::new("/Library/Logs/DigNetwork/dig-updater"));
    }

    #[test]
    fn dev_fallback_when_machine_root_not_creatable() {
        // Simulate an unprivileged run: the machine root cannot be created, so we fall back.
        let dir = resolve_log_dir(
            "dig-node",
            env(&[
                ("HOME", "/home/dev"),
                ("XDG_STATE_HOME", "/home/dev/.state"),
                ("LOCALAPPDATA", r"C:\Users\dev\AppData\Local"),
            ]),
            |path: &Path| path.to_string_lossy().contains("dev"),
        );
        assert!(dir.ends_with(Path::new("dig-node")));
        #[cfg(all(unix, not(target_os = "macos")))]
        assert_eq!(dir, Path::new("/home/dev/.state/dig/logs/dig-node"));
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn linux_dev_fallback_without_xdg_uses_local_state() {
        let dir = resolve_log_dir("dig-dns", env(&[("HOME", "/home/dev")]), |_| false);
        assert_eq!(dir, Path::new("/home/dev/.local/state/dig/logs/dig-dns"));
    }
}
