//! [`init`] — the one entry point that installs the DIG logging stack (SPEC §1).
//!
//! It resolves the log directory, opens the rolling file appender, wires the JSONL file sink + the
//! human stderr sink behind one reloadable level filter, stamps the correlation ids, and spawns the
//! hourly maintenance task (byte-cap janitor + dropped-line reporter). It returns a [`LogGuard`] the
//! caller holds for the process lifetime; dropping it flushes the file writer.

use std::path::PathBuf;
use std::time::Duration;

use tracing_appender::rolling::{Builder as AppenderBuilder, Rotation};
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
/// it also exposes runtime level control (SPEC §5).
pub struct LogGuard {
    _writer: WriterGuard,
    dir: PathBuf,
    set_filter: FilterSetter,
}

impl LogGuard {
    /// The resolved log directory this run is writing to.
    pub fn log_dir(&self) -> &std::path::Path {
        &self.dir
    }

    /// Swap the live level filter (SPEC §5 runtime reload). The consumer's control plane calls this.
    pub fn set_filter(&self, directive: &str) -> Result<()> {
        (self.set_filter)(directive)
    }
}

/// Install the DIG logging stack for `service` (SPEC §1). Call ONCE at process start; a second call
/// returns [`Error::AlreadyInitialized`].
pub fn init(service: Service) -> Result<LogGuard> {
    let dir = dirs::log_dir(service.name);
    std::fs::create_dir_all(&dir).map_err(|source| Error::LogDir {
        path: dir.clone(),
        source,
    })?;

    let env = |key: &str| std::env::var(key).ok();
    let retention = janitor::retention_days(env);
    let max_bytes = janitor::max_bytes(env);
    janitor::enforce_byte_cap(&dir, service.name, max_bytes);

    let appender = AppenderBuilder::new()
        .rotation(Rotation::DAILY)
        .filename_prefix(format!("{}.jsonl", service.name))
        .max_log_files(retention)
        .build(&dir)
        .map_err(|source| Error::Appender {
            path: dir.clone(),
            source,
        })?;
    let (file_writer, writer_guard) = crate::writer::spawn(appender);

    let statics = OwnedStatics {
        service: service.name.to_string(),
        service_version: service.version.to_string(),
        run_context: service.run_context.as_str().to_string(),
        run_id: correlation::new_run_id(),
        parent_op_id: correlation::parent_op_id_from_env(),
    };

    let directive = filter::resolve_filter_from_env(filter::read_persisted_level(&dir).as_deref());
    let env_filter = EnvFilter::try_new(&directive).map_err(|e| Error::Filter {
        directive: directive.clone(),
        message: e.to_string(),
    })?;
    let (filter_layer, reload_handle) = reload::Layer::new(env_filter);

    let json_layer = DigJsonLayer::new(statics, file_writer.clone());
    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .compact();

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(json_layer)
        .with(stderr_layer.boxed())
        .try_init()
        .map_err(|_| Error::AlreadyInitialized)?;

    spawn_maintenance(dir.clone(), service.name, max_bytes, file_writer);

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
        set_filter,
    })
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
