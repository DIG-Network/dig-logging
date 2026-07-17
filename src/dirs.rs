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
//!
//! **Operator read on Windows (#728).** The machine root lives under `%ProgramData%\DigNetwork`,
//! which dig-installer #715 locks to a protected, non-inheriting DACL of `{SYSTEM:F, Administrators:F}`
//! (`icacls /inheritance:r`). The `logs\<service>` subtree therefore inherits NO non-admin read from
//! that root. To keep logs operator-readable (SPEC §3), dig-logging follows the #715 adopter rule — a
//! child needing non-admin read sets its OWN explicit ACE — and grants `BUILTIN\Users` a read+execute
//! ACE on the machine service dir. This never loosens the #715 root DACL (a sibling subtree gets its
//! own ACE; the root is untouched). Applied ONLY to the machine-root branch: the `DIG_LOG_DIR` override
//! and the per-user dev fallback are caller-chosen / already user-owned and are left alone.

use std::path::PathBuf;

/// The env var that overrides the log ROOT outright (tests, custom deploys).
pub const ENV_LOG_DIR: &str = "DIG_LOG_DIR";

/// The `BUILTIN\Users` group SID — locale-independent, granted operator read on the machine log dir
/// (#728). A well-known SID (not a localized name) so the `icacls` grant works on any Windows locale.
const SID_USERS: &str = "S-1-5-32-545";

/// Which resolution branch produced a log directory (SPEC §3). Distinguishes the machine root — the
/// only branch under the #715-locked `%ProgramData%\DigNetwork` tree, and thus the only one needing an
/// explicit operator-read ACE — from the caller-owned override and dev-fallback branches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogDirSource {
    /// The `DIG_LOG_DIR` override (a caller-chosen root).
    Override,
    /// The per-OS machine root (privileged run) — under the #715-locked root on Windows.
    MachineRoot,
    /// The per-user dev fallback (unprivileged run) — already owned by the running user.
    DevFallback,
}

/// A resolved log directory plus the branch that produced it (see [`LogDirSource`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedLogDir {
    /// The service log directory (`<root>/<service>`).
    pub path: PathBuf,
    /// The resolution branch that chose `path`.
    pub source: LogDirSource,
}

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
    resolve_log_dir_detailed(service, get, can_create).path
}

/// Resolve the log directory AND the branch that produced it (see [`resolve_log_dir`] for precedence).
///
/// Callers that must know whether the machine root was chosen — the only branch under the
/// #715-locked Windows root — use this to decide whether to apply the operator-read ACE (#728).
pub fn resolve_log_dir_detailed<G, C>(service: &str, get: G, can_create: C) -> ResolvedLogDir
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
        return ResolvedLogDir {
            path: PathBuf::from(root).join(service),
            source: LogDirSource::Override,
        };
    }

    // 2. Machine root when its service dir is creatable; 3. else the per-user dev fallback.
    let machine = machine_root(&read).join(service);
    if can_create(&machine) {
        return ResolvedLogDir {
            path: machine,
            source: LogDirSource::MachineRoot,
        };
    }
    ResolvedLogDir {
        path: dev_root(&read).join(service),
        source: LogDirSource::DevFallback,
    }
}

/// The resolved service log directory for this process, wiring the real environment + a filesystem
/// creatable-probe into [`resolve_log_dir_detailed`]. When the machine-root branch is taken on Windows,
/// grants operators (`BUILTIN\Users`) read on the freshly-created dir (#728) — see the module docs.
pub fn log_dir(service: &str) -> PathBuf {
    let resolved = resolve_log_dir_detailed(
        service,
        |key| std::env::var(key).ok(),
        |path| std::fs::create_dir_all(path).is_ok(),
    );

    #[cfg(windows)]
    if resolved.source == LogDirSource::MachineRoot {
        // Best-effort: a failed grant must never stop the service from logging. The dir already
        // exists (the creatable-probe made it); we only relax read for operators.
        grant_operator_read(&resolved.path);
    }

    resolved.path
}

/// The `icacls` argv that grants `BUILTIN\Users` a read+execute ACE, inheritable to child files/dirs,
/// on `dir` (#728). By SID so it is locale-independent; `/grant:r` ADDS the ACE without replacing the
/// DACL, so the inherited `{SYSTEM,Admins}` full-control from #715 (if any survives) stays intact.
/// Pure, so the exact grant is unit-tested without touching the filesystem.
pub fn windows_operator_read_args(dir: &str) -> Vec<String> {
    vec![
        dir.to_string(),
        "/grant:r".to_string(),
        format!("*{SID_USERS}:(OI)(CI)RX"),
        "/T".to_string(),
        "/C".to_string(),
        "/Q".to_string(),
    ]
}

/// Grant operators (`BUILTIN\Users`) read on the machine log dir via `icacls` (#728). Best-effort:
/// any failure is swallowed, because losing operator read is a diagnostic inconvenience, never a
/// reason to stop the service logging.
#[cfg(windows)]
fn grant_operator_read(dir: &std::path::Path) {
    let Some(dir) = dir.to_str() else { return };
    let _ = std::process::Command::new("icacls")
        .args(windows_operator_read_args(dir))
        .output();
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

    #[test]
    fn override_reports_override_source() {
        let resolved =
            resolve_log_dir_detailed("dig-node", env(&[(ENV_LOG_DIR, "/custom")]), |_| true);
        assert_eq!(resolved.source, LogDirSource::Override);
    }

    #[test]
    fn creatable_machine_root_reports_machine_source() {
        // The machine root is the ONLY branch under the #715-locked Windows root, so it is the only
        // one that later earns the operator-read ACE (#728).
        let resolved = resolve_log_dir_detailed("dig-node", env(&[]), |_| true);
        assert_eq!(resolved.source, LogDirSource::MachineRoot);
    }

    #[test]
    fn uncreatable_machine_root_reports_dev_fallback_source() {
        let resolved =
            resolve_log_dir_detailed("dig-node", env(&[("HOME", "/home/dev")]), |_| false);
        assert_eq!(resolved.source, LogDirSource::DevFallback);
    }

    #[test]
    fn operator_read_grant_targets_users_sid_read_execute_inheritable() {
        // #728: a non-replacing (`/grant:r`) read+execute ACE for BUILTIN\Users by SID, inheritable
        // to child files/dirs — so operators can read logs without loosening the #715 root DACL.
        let args = windows_operator_read_args(r"C:\ProgramData\DigNetwork\logs\dig-node");
        assert_eq!(args[0], r"C:\ProgramData\DigNetwork\logs\dig-node");
        assert!(args.iter().any(|a| a == "/grant:r"));
        assert!(args.iter().any(|a| a == "*S-1-5-32-545:(OI)(CI)RX"));
        // Never a DACL-replacing flag — the inherited {SYSTEM,Admins} full-control must survive.
        assert!(!args.iter().any(|a| a == "/inheritance:r" || a == "/reset"));
    }
}
