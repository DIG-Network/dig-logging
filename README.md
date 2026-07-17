# dig-logging

Shared structured logging + log-collection for the DIG service binaries (`dig-node`, `dig-dns`,
`dig-updater`; later `dig-relay`, `digstore`). One crate so sinks, log locations, rotation, the JSONL
schema, level control, correlation ids, redaction, and the `logs` CLI verbs are **byte-identical**
across every binary. A thin composition over [`tracing`](https://docs.rs/tracing),
[`tracing-subscriber`](https://docs.rs/tracing-subscriber), and
[`tracing-appender`](https://docs.rs/tracing-appender).

See [`SPEC.md`](SPEC.md) for the normative contract (schema, directories, retention, level
precedence, correlation, redaction, verbs).

## Use

```rust
let _guard = dig_logging::init(dig_logging::Service {
    name: "dig-node",
    version: env!("CARGO_PKG_VERSION"),
    run_context: dig_logging::RunContext::Service,
})?;
tracing::info!(peer = "203.0.113.7", "serving");
```

`init` installs a dual sink — a structured JSONL file (rolling daily, byte-capped, non-blocking +
lossy under backpressure) plus compact human text on `stderr` — behind one reloadable level filter,
and stamps a per-run `run_id`. Hold the returned `LogGuard` for the process lifetime.

### Log locations

| OS | Machine root (per-service subdir) |
|---|---|
| Windows | `C:\ProgramData\DigNetwork\logs\<service>` |
| macOS | `/Library/Logs/DigNetwork/<service>` |
| Linux | `/var/log/dig/<service>` |

`DIG_LOG_DIR` overrides the root; an unprivileged run falls back to a per-user dir.

### The `logs` verbs

Mount the shared subcommand and dispatch it:

```rust
let app = clap::Command::new("dig-node").subcommand(dig_logging::logs::command());
if let Some(("logs", m)) = app.get_matches().subcommand() {
    dig_logging::logs::run(&service, m)?;
}
```

`<bin> logs path | tail [-f] [-n N] [--level L] [--json] | level [<filter>] | bundle [-o out.zip] [--all]`.
`logs bundle` writes a **redacted** zip (secrets scrubbed per `SPEC.md` §8.2) safe to attach to a bug
report.

## Environment

| Var | Meaning | Default |
|---|---|---|
| `DIG_LOG_DIR` | Log ROOT override | per-OS machine root |
| `DIG_LOG` | Level filter (ecosystem name) | — |
| `RUST_LOG` | Level filter (Rust convention) | — |
| `DIG_LOG_RETENTION_DAYS` | Daily files kept | 7 |
| `DIG_LOG_MAX_BYTES` | Per-service byte cap | 50 MiB |
| `DIG_OP_ID` | Propagated parent operation id | — |

License: GPL-2.0-only.
