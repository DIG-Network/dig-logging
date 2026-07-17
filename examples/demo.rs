//! A runnable demonstration of the dig-logging stack (SPEC acceptance).
//!
//! Run it with a temp log dir and a level override to see both sinks + the file rotation naming:
//!
//! ```text
//! DIG_LOG_DIR=/tmp/diglogs DIG_LOG=debug cargo run --example demo
//! # → human lines on stderr, and /tmp/diglogs/dig-node/dig-node.jsonl.<UTC-date> with JSON lines
//! ```

use dig_logging::{init, RunContext, Service};
use tracing::{info, info_span, warn};

fn main() -> Result<(), dig_logging::Error> {
    let guard = init(Service {
        name: "dig-node",
        version: env!("CARGO_PKG_VERSION"),
        run_context: RunContext::Service,
    })?;

    info!(peer = "203.0.113.7", "node serving");

    // A top-level operation carries op_id; every event inside inherits it (SPEC §6).
    let span = info_span!("download", op_id = "op-7f3a", store = "abc123");
    let _entered = span.enter();
    info!(bytes = 4096u64, "capsule fetched");
    warn!("peer slow, retrying");
    drop(_entered);

    println!("log directory: {}", guard.log_dir().display());
    // A demo of runtime level control (SPEC §5).
    guard.set_filter("trace").expect("valid filter");
    tracing::trace!("now visible after reload");
    Ok(())
}
