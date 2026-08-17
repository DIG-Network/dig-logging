//! [`init`] — the one entry point that installs the DIG logging stack (SPEC §1).
//!
//! It resolves the log directory, opens the rolling file appender, wires the JSONL file sink + the
//! human stderr sink behind one reloadable level filter, stamps the correlation ids, and spawns the
//! hourly maintenance task (byte-cap janitor + dropped-line reporter). It returns a [`LogGuard`] the
//! caller holds for the process lifetime; dropping it flushes the file writer.
//!
//! **The file sink degrades; it never silences the process.** A log directory the process cannot
//! write to — on Windows, a `%ProgramData%` service dir owned by the SERVICE account and opened by an
//! interactive run — used to fail `init` outright, so the console sink was never installed either and
//! the binary ran with NO subscriber at all. That turns every downstream bug into a mystery: a broken
//! subsystem looks dead rather than broken. Now a file-sink failure installs the console sink anyway,
//! prints ONE warning naming the path and the reason, and reports itself via [`LogGuard::file_error`].

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tracing_appender::rolling::{Builder as AppenderBuilder, Rotation};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{reload, EnvFilter, Layer};

use crate::error::{Error, Result};
use crate::layer::{DigJsonLayer, OwnedStatics};
use crate::writer::{LossyWriter, WriterGuard};
use crate::{correlation, dirs, filter, janitor, Service};

/// How often the maintenance task enforces the byte cap + reports dropped lines.
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(3600);

/// A type-erased live-filter swapper capturing the `reload` handle (SPEC §5 runtime reload).
type FilterSetter = Box<dyn Fn(&str) -> Result<()> + Send + Sync>;

/// Held by the caller for the life of the process. Dropping it flushes the file writer (SPEC §4.4);
/// it also exposes runtime level control (SPEC §5) and whether the file sink degraded.
pub struct LogGuard {
    _writer: Option<WriterGuard>,
    dir: PathBuf,
    file_error: Option<String>,
    set_filter: FilterSetter,
}

impl LogGuard {
    /// The resolved log directory this run is writing to. When [`file_error`](Self::file_error) is
    /// set, nothing is being written there — the directory is the one that could NOT be opened.
    pub fn log_dir(&self) -> &std::path::Path {
        &self.dir
    }

    /// Why the JSONL file sink is disabled, or `None` when it is live. Console logging is installed
    /// either way; a consumer that surfaces logging health reports this rather than treating it as
    /// a fatal `init` failure.
    pub fn file_error(&self) -> Option<&str> {
        self.file_error.as_deref()
    }

    /// Swap the live level filter (SPEC §5 runtime reload). The consumer's control plane calls this.
    pub fn set_filter(&self, directive: &str) -> Result<()> {
        (self.set_filter)(directive)
    }
}

/// The live JSONL file sink: the layer to install, the flush guard, and the writer the maintenance
/// task watches for dropped lines.
struct FileSink {
    layer: DigJsonLayer<LossyWriter>,
    guard: WriterGuard,
    writer: LossyWriter,
}

/// Install the DIG logging stack for `service` (SPEC §1). Call ONCE at process start; a second call
/// returns [`Error::AlreadyInitialized`].
///
/// Only two conditions still fail: a subscriber already installed, and — impossible in practice,
/// since [`filter`] falls back to a known-good directive — an unparseable filter. An unwritable log
/// directory does NOT fail; it degrades to console-only logging with a warning on stderr.
pub fn init(service: Service) -> Result<LogGuard> {
    init_with_console(service, dirs::log_dir(service.name), std::io::stderr)
}

/// The testable core of [`init`]: the log directory and the console sink are injected, so the
/// degraded path can be exercised without touching the real environment or the real stderr.
fn init_with_console<W>(service: Service, dir: PathBuf, console: W) -> Result<LogGuard>
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    let max_bytes = janitor::max_bytes(|key: &str| std::env::var(key).ok());

    let (file_sink, file_error) = match open_file_sink(&dir, service, max_bytes) {
        Ok(sink) => (Some(sink), None),
        Err(error) => {
            warn_file_logging_disabled(&console, &dir, &error);
            (None, Some(error.to_string()))
        }
    };

    let directive = filter::resolve_filter_from_env(filter::read_persisted_level(&dir).as_deref());
    let env_filter = EnvFilter::try_new(&directive).map_err(|e| Error::Filter {
        directive: directive.clone(),
        message: e.to_string(),
    })?;
    let (filter_layer, reload_handle) = reload::Layer::new(env_filter);

    let (json_layer, writer_guard, file_writer) = match file_sink {
        Some(sink) => (Some(sink.layer), Some(sink.guard), Some(sink.writer)),
        None => (None, None, None),
    };
    let console_layer = tracing_subscriber::fmt::layer()
        .with_writer(console)
        .compact();

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(json_layer)
        .with(console_layer.boxed())
        .try_init()
        .map_err(|_| Error::AlreadyInitialized)?;

    if let Some(writer) = file_writer {
        spawn_maintenance(dir.clone(), service.name, max_bytes, writer);
    }

    let set_filter = Box::new(move |directive: &str| -> Result<()> {
        let new = EnvFilter::try_new(directive).map_err(|e| Error::Filter {
            directive: directive.to_string(),
            message: e.to_string(),
        })?;
        reload_handle.reload(new).map_err(|e| Error::Filter {
            directive: directive.to_string(),
            message: e.to_string(),
        })
    });

    Ok(LogGuard {
        _writer: writer_guard,
        dir,
        file_error,
        set_filter,
    })
}

/// Create the log directory, enforce the byte cap, and open the rolling JSONL appender behind the
/// non-blocking writer. Every failure here is recoverable by the caller: it costs the file sink, not
/// the process's logging.
fn open_file_sink(
    dir: &Path,
    service: Service,
    max_bytes: u64,
) -> std::result::Result<FileSink, Error> {
    std::fs::create_dir_all(dir).map_err(|source| Error::LogDir {
        path: dir.to_path_buf(),
        source,
    })?;

    let retention = janitor::retention_days(|key: &str| std::env::var(key).ok());
    janitor::enforce_byte_cap(dir, service.name, max_bytes);

    let appender = AppenderBuilder::new()
        .rotation(Rotation::DAILY)
        .filename_prefix(format!("{}.jsonl", service.name))
        .max_log_files(retention)
        .build(dir)
        .map_err(|source| Error::Appender {
            path: dir.to_path_buf(),
            source,
        })?;
    let (writer, guard) = crate::writer::spawn(appender);

    let statics = OwnedStatics {
        service: service.name.to_string(),
        service_version: service.version.to_string(),
        run_context: service.run_context.as_str().to_string(),
        run_id: correlation::new_run_id(),
        parent_op_id: correlation::parent_op_id_from_env(),
    };

    Ok(FileSink {
        layer: DigJsonLayer::new(statics, writer.clone()),
        guard,
        writer,
    })
}

/// Tell the operator, on the console sink itself, that file logging is off and why. A SILENT degrade
/// is only marginally better than a silent failure: whoever later looks for the JSONL file must be
/// able to see that it was never written, and which path failed.
fn warn_file_logging_disabled<W>(console: &W, dir: &Path, error: &Error)
where
    W: for<'w> MakeWriter<'w>,
{
    // Pre-subscriber, so this cannot be a `tracing` event — it is written straight to the sink.
    let _ = writeln!(
        console.make_writer(),
        "WARN dig-logging: file logging is DISABLED for {} ({}). Console logging continues; set \
         DIG_LOG_DIR to a writable directory to restore JSONL log files.",
        dir.display(),
        error
    );
}

/// Spawn the hourly maintenance task: enforce the byte cap, and emit a `WARN` whenever the file
/// writer has dropped new lines under backpressure (SPEC §4/§4.4).
fn spawn_maintenance(dir: PathBuf, service: &'static str, max_bytes: u64, writer: LossyWriter) {
    std::thread::Builder::new()
        .name("dig-logging-maintenance".into())
        .spawn(move || {
            let mut last_dropped = 0u64;
            loop {
                std::thread::sleep(MAINTENANCE_INTERVAL);
                janitor::enforce_byte_cap(&dir, service, max_bytes);
                let dropped = writer.dropped();
                if dropped > last_dropped {
                    tracing::warn!(
                        target: "dig_logging",
                        dropped,
                        "log lines dropped under backpressure since start"
                    );
                    last_dropped = dropped;
                }
            }
        })
        .expect("spawn dig-logging maintenance thread");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// A console sink that keeps every byte, so a test can read what an operator would have seen.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl Captured {
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
    }

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Captured {
        type Writer = Captured;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// The regression for #3064: an unusable log directory must cost the FILE sink only. Before the
    /// fix, `init` returned `Err` here and the process ran with no subscriber at all — the console
    /// capture would be empty, which is exactly what this asserts against.
    ///
    /// The subscriber is process-global and install-once, so this is the ONE test in the lib test
    /// binary that installs one; the file-sink success path is covered end-to-end in
    /// `tests/end_to_end.rs`, which runs as its own process.
    #[test]
    fn unwritable_log_dir_degrades_to_console_instead_of_silencing_logging() {
        let tmp = tempfile::tempdir().unwrap();
        // A regular FILE where the log directory should be: `create_dir_all` genuinely fails, the
        // same class of failure as a service-owned `%ProgramData%` dir an interactive run cannot open.
        let blocked = tmp.path().join("blocked");
        std::fs::write(&blocked, b"not a directory").unwrap();

        let console = Captured::default();
        let guard = init_with_console(
            Service {
                name: "dig-node",
                version: "9.9.9",
                run_context: crate::RunContext::Cli,
            },
            blocked.clone(),
            console.clone(),
        )
        .expect("an unwritable log dir must not fail init");

        let warning = console.text();
        assert!(
            warning.contains(&blocked.display().to_string()),
            "the warning names the path that failed; got: {warning:?}"
        );
        assert!(
            guard.file_error().is_some(),
            "the degrade is reportable to the caller"
        );

        tracing::info!(target: "dig_logging_test", "console still receives this record");

        let logged = console.text();
        assert!(
            logged.contains("console still receives this record"),
            "records must still reach the console sink; got: {logged:?}"
        );
    }
}
