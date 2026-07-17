//! The crate's public error type.

use std::io;
use std::path::PathBuf;

/// Everything that can go wrong initializing logging or running a `logs` verb.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The resolved log directory could not be created or written.
    #[error("could not create or write the log directory {path}: {source}")]
    LogDir {
        /// The directory dig-logging tried to use.
        path: PathBuf,
        /// The underlying filesystem error.
        source: io::Error,
    },

    /// The rolling file appender could not be built for the resolved directory.
    #[error("could not open the rolling log file in {path}: {source}")]
    Appender {
        /// The directory the appender targeted.
        path: PathBuf,
        /// The underlying appender error.
        source: tracing_appender::rolling::InitError,
    },

    /// A level-filter directive (default, env, persisted, or a runtime reload) was not valid.
    #[error("invalid log filter directive {directive:?}: {message}")]
    Filter {
        /// The rejected directive text.
        directive: String,
        /// Why it was rejected.
        message: String,
    },

    /// A global subscriber was already installed (init called twice, or another crate set one).
    #[error("a tracing subscriber is already installed; dig_logging::init must be called once")]
    AlreadyInitialized,

    /// A `logs` verb hit a plain I/O error (reading a log file, writing a bundle).
    #[error(transparent)]
    Io(#[from] io::Error),

    /// Serializing a bundle manifest failed.
    #[error("could not serialize the bundle manifest: {0}")]
    Manifest(#[from] serde_json::Error),

    /// Writing the bundle zip archive failed.
    #[error("could not write the log bundle: {0}")]
    Bundle(#[from] zip::result::ZipError),
}

/// The crate's result alias.
pub type Result<T> = std::result::Result<T, Error>;
