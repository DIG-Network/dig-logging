//! # dig-logging
//!
//! The shared logging + log-collection building block for the DIG service binaries (`dig-node`,
//! `dig-dns`, `dig-updater`; later `dig-relay`, `digstore`). It is the ONE place those binaries get
//! their logging from, so the sink layout, directory convention, JSONL schema, rotation policy,
//! level control, correlation ids, redaction rules, and `logs` CLI verbs are byte-identical across
//! every binary. `SPEC.md` is the normative contract.
//!
//! It is a thin composition over [`tracing`], [`tracing_subscriber`], and [`tracing_appender`] — it
//! builds ON `tracing`, it does not replace it.
//!
//! ## Quick start
//!
//! ```no_run
//! let _guard = dig_logging::init(dig_logging::Service {
//!     name: "dig-node",
//!     version: env!("CARGO_PKG_VERSION"),
//!     run_context: dig_logging::RunContext::Service,
//! })?;
//! tracing::info!(peer = "203.0.113.7", "serving");
//! # Ok::<(), dig_logging::Error>(())
//! ```
//!
//! `init` installs a dual sink — a structured JSONL file (rolling daily, byte-capped, non-blocking
//! and lossy under backpressure) plus compact human text on `stderr` — behind one reloadable level
//! filter, and stamps a per-run `run_id` (+ `op_id`/`parent_op_id` correlation). Hold the returned
//! [`LogGuard`] for the process lifetime.
//!
//! ## Collection
//!
//! Consumers mount the reusable [`logs`] verbs (`path`/`tail`/`level`/`bundle`) and the [`redact`]
//! engine gives a `logs bundle` a safe, secret-scrubbed zip for a bug report.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod bundle;
mod correlation;
mod dirs;
mod error;
mod filter;
mod init;
mod janitor;
mod layer;
mod schema;
mod writer;

pub mod logs;
pub mod redact;

pub use error::{Error, Result};
pub use init::{init, LogGuard};

// The pure building blocks worth exposing for consumers + conformance tests (SPEC §9).
pub use correlation::{new_run_id, parent_op_id, ENV_DIG_OP_ID, OP_ID_FIELD};
pub use dirs::{
    log_dir, resolve_log_dir, resolve_log_dir_detailed, windows_operator_read_args, LogDirSource,
    ResolvedLogDir, ENV_LOG_DIR,
};
pub use filter::{resolve_filter, DEFAULT_DIRECTIVE, ENV_DIG_LOG, ENV_RUST_LOG};
pub use janitor::{ENV_MAX_BYTES, ENV_RETENTION_DAYS};

/// A binary's identity, passed to [`init`] and the [`logs`] verbs.
#[derive(Debug, Clone, Copy)]
pub struct Service {
    /// The service name — one of `dig-node`, `dig-dns`, `dig-updater`, … . Names the log subdir.
    pub name: &'static str,
    /// The binary's semver, stamped on every record (typically `env!("CARGO_PKG_VERSION")`).
    pub version: &'static str,
    /// Whether this is an OS-service run or an interactive CLI run.
    pub run_context: RunContext,
}

/// How the binary is running — stamped as the `run_context` field (SPEC §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunContext {
    /// An OS-service / daemon run (Windows service, systemd, launchd).
    Service,
    /// An interactive or CLI invocation.
    Cli,
}

impl RunContext {
    /// The wire string for the `run_context` field (SPEC §2).
    pub fn as_str(self) -> &'static str {
        match self {
            RunContext::Service => "service",
            RunContext::Cli => "cli",
        }
    }
}
