# dig-logging — normative specification

`dig-logging` is the shared logging + log-collection building block for the DIG service binaries
(`dig-node`, `dig-dns`, `dig-updater`; later `dig-relay`, `digstore`). It is the ONE place those
binaries get their logging from, so the sink layout, directory convention, JSONL schema, rotation
policy, level control, correlation ids, redaction rules, and `logs` CLI verbs are **byte-identical**
across every binary. It is a thin composition over [`tracing`](https://docs.rs/tracing),
[`tracing-subscriber`](https://docs.rs/tracing-subscriber), and
[`tracing-appender`](https://docs.rs/tracing-appender) — it builds ON `tracing`, it does not replace
it.

This document is the authoritative contract an independent reimplementation MUST match. It realizes
the decided architecture of `dig_ecosystem` epic #547 (decisions D1–D8). Where a value here differs
from an illustrative sketch elsewhere, this document wins.

## 1. Sinks (D2)

`init()` installs a subscriber with exactly two sinks, sharing one level filter (§5):

1. **File sink — structured JSONL.** One JSON object per line (§2), the durable machine-readable
   record. Written through a NON-BLOCKING, LOSSY writer (§4.4) to a rolling daily file (§4).
2. **Console sink — compact human text on `stderr`.** Preserves each binary's existing
   operator/journald experience; on Linux `journalctl -u <svc>` captures it for free.

No Windows Event Log / ETW, syslog, or OpenTelemetry sink exists in v1. The schema is additive-only,
so such sinks MAY be added later without breaking consumers.

## 2. JSONL schema (D2) — `schema: 1`

Every file-sink line is a single JSON object. Field order is not significant to consumers (JSON is
unordered), but the writer emits fields in the order below for human readability. The schema evolves
**additively only**: new optional fields MAY be added; an existing field's name, type, or meaning is
NEVER changed or removed. Consumers keying on `schema` MUST accept any `schema >= 1` and ignore
unknown fields.

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `schema` | integer | always | Schema version. `1` in this spec. |
| `ts` | string | always | Event time, RFC 3339 / ISO 8601 in **UTC** (e.g. `2026-07-16T01:44:25.123456Z`). |
| `level` | string | always | `ERROR` \| `WARN` \| `INFO` \| `DEBUG` \| `TRACE`. |
| `target` | string | always | The `tracing` target (module path by default). |
| `message` | string | always | The event's human message (`""` if the event carried none). |
| `service` | string | always | `dig-node` \| `dig-dns` \| `dig-updater` \| … (the caller's `Service.name`). |
| `service_version` | string | always | The caller's `Service.version` (its `CARGO_PKG_VERSION`). |
| `run_context` | string | always | `service` (OS-service run) \| `cli` (interactive/CLI run). |
| `run_id` | string | always | UUIDv4 minted once at `init()` (§6). Groups one process run across rotated files; distinguishes restarts. |
| `parent_op_id` | string | when set | The `DIG_OP_ID` env value at `init()`, if present + non-empty (§6). Ties this run to the operation in the parent process that spawned it. |
| `op_id` | string | when in an op span | Operation id, carried as a span field named `op_id` (§6); flattened onto every event inside the span. |
| *(span fields)* | any | when in a span | All other fields from every span in the event's scope, flattened root→leaf. A leaf span's field shadows an ancestor's of the same name. |
| *(event fields)* | any | as emitted | The event's own structured fields (excluding the reserved `message`). Event fields shadow span fields of the same name. |

Reserved field names a caller MUST NOT use for unrelated data: `schema`, `ts`, `level`, `target`,
`message`, `service`, `service_version`, `run_context`, `run_id`, `parent_op_id`. `op_id` is reserved
for the correlation contract (§6).

## 3. Log directory (D3)

One machine-wide log root, one subdirectory per service. The root is SYSTEM/root-writable and
**user-readable** (logs are operator diagnostics; secrets are barred at source §7 and redacted at
bundle §8). This differs deliberately from the owner-only #501 state dirs.

| OS | Machine log root | Service dir |
|---|---|---|
| Windows | `%PROGRAMDATA%\DigNetwork\logs` (default `C:\ProgramData\DigNetwork\logs`) | `…\logs\<service>` |
| macOS | `/Library/Logs/DigNetwork` | `/Library/Logs/DigNetwork/<service>` |
| Linux | `/var/log/dig` | `/var/log/dig/<service>` |

Resolution precedence (first that applies):

1. **`DIG_LOG_DIR`** — if set + non-empty, its value is the log ROOT; the service dir is
   `$DIG_LOG_DIR/<service>`. Overrides everything (tests, custom deploys).
2. **Machine root** `<service>` — used when that directory can be created + written (a privileged
   service run, or an installer-provisioned dir).
3. **Per-user dev fallback** `<service>` — used when the machine root is not creatable/writable (an
   unprivileged `cargo run` / dev run), mirroring dig-node's #501 dev-fallback pattern:

   | OS | Dev fallback root |
   |---|---|
   | Windows | `%LOCALAPPDATA%\DigNetwork\logs` |
   | macOS | `~/Library/Logs/DigNetwork` |
   | Linux | `${XDG_STATE_HOME:-~/.local/state}/dig/logs` |

The CLI and the service resolve identically, so `<bin> logs path` names the same directory the
service writes to. A binary MUST `create_dir_all` the resolved dir on init (installer provisioning is
an optimization, not a hard dependency).

**3.1 Windows operator-read ACE.** On Windows the machine root lives under `%ProgramData%\DigNetwork`,
which dig-installer locks to a protected, NON-inheriting DACL of `{SYSTEM:F, Administrators:F}`
(`icacls /inheritance:r` — the shared-root contract). The `logs\<service>` subtree therefore inherits
NO non-admin read from that root. To keep logs operator-readable (§3), when the **machine-root** branch
is taken, dig-logging sets its OWN explicit ACE on the service dir — an ADD-only (`icacls /grant:r`,
never DACL-replacing) read+execute grant to `BUILTIN\Users` by SID `S-1-5-32-545`, inheritable
(`(OI)(CI)RX`) so log files inherit read. This follows the shared-root adopter rule (a child needing
non-admin read sets its own ACE) and MUST NOT loosen the root DACL. The grant is best-effort — a
failure never blocks logging. It is applied ONLY to the machine-root branch; the `DIG_LOG_DIR`
override and the per-user dev fallback are caller-owned and left untouched. On macOS/Linux the
machine root's default directory mode already governs operator read (world-readable log dirs); no
extra step is needed.

## 4. Rotation & retention (D4)

- Files roll **daily**, named **`<service>.jsonl.YYYY-MM-DD`** (UTC date), via
  `tracing_appender::rolling` with `Rotation::DAILY`.
- **Count cap:** `max_log_files(N)`, `N` = `DIG_LOG_RETENTION_DAYS` (default **7**).
- **Byte-cap janitor:** in addition to the count cap, a total-bytes cap per service dir bounds a
  runaway-error day the count cap would not. Default `DIG_LOG_MAX_BYTES` = **50 MiB** (52 428 800).
  On init and hourly thereafter, files in the service dir are summed; while the total exceeds the
  cap, the **oldest** file (by modified time) is deleted. The current day's file is never deleted.
- **4.4 Non-blocking, lossy writer.** The file writer is a custom `LossyWriter`: each rendered line is
  handed to a bounded `sync_channel` (capacity 8192) drained by a dedicated writer thread that owns the
  rolling file appender. Under backpressure — a full channel — the line is DROPPED and an `AtomicU64`
  drop counter is bumped rather than blocking the caller, so a saturated logging pipeline MUST NEVER
  stall a service's serve path. The counter (`LossyWriter::dropped`) surfaces the loss; dig-logging
  emits a `WARN` event `target = "dig_logging"` reporting the dropped count so loss is itself visible
  in the log.

## 5. Levels (D5)

- **Default directive:** `info,hyper=warn,rustls=warn,h2=warn,tower=warn` (noise-trimmed `info`),
  baked into dig-logging.
- **Precedence (first VALID non-empty wins):** `persisted` (a level the operator saved via
  `logs level`) > **`DIG_LOG`** (the ecosystem-common env name) > **`RUST_LOG`** (the Rust
  convention, kept working) > the default directive.
- **Every candidate directive is VALIDATED against `EnvFilter` before it is chosen.** A directive
  that does not parse is SKIPPED and resolution falls through to the next source — ultimately the
  always-valid default. Logging is NEVER disabled because a bad directive was persisted (a persisted
  `level` file survives restarts, so an un-validated garbage directive would otherwise make `init`
  fail on every subsequent start). `logs level` additionally REJECTS an invalid directive at write
  time, so garbage is not persisted in the first place; the read-time validation is the backstop for
  anything persisted before that guard existed.
- One `EnvFilter` is shared by both sinks in v1.
- **Runtime reload.** `init()` returns a guard exposing `set_filter(&str)`; it swaps the live filter
  via a `tracing_subscriber::reload` handle. Consumers with a control plane (dig-node's
  `control.log.setLevel` / `dig-node logs level <filter>`) wire it; others read the persisted level
  once at startup.

## 6. Correlation ids (D6)

- **`run_id`** — a UUIDv4 minted at `init()`, stamped on EVERY record. Groups one process run across
  rotated files and distinguishes restarts.
- **`op_id`** — a short id a caller attaches as a span field named `op_id` on a top-level operation
  (an RPC dispatch, a download pass, an updater run). Because span fields flatten (§2), every event
  inside that span carries it.
- **`DIG_OP_ID` cross-process contract.** A parent process MAY set the env var `DIG_OP_ID` in a
  child's environment before spawning it. The child's `init()` reads it (if present + non-empty) into
  the per-process `parent_op_id` field, tying the child's whole run to the parent operation
  (installer → service; updater broker → worker). The value is an opaque short string; dig-logging
  neither parses nor validates it beyond non-emptiness.

## 7. Never-log list (defense at source) — normative

The following MUST NEVER be passed to a `tracing` event/span field or a log message by ANY consumer,
at any level. Redaction (§8) is the second line of defense, not the first; each consumer's integration
includes an audit + a regression test that these do not appear at source:

- BIP39 mnemonics / seed phrases and any wallet secret or derived private key material.
- Private keys of any kind (PEM/DER/hex), signing keys, KMS material.
- Control-plane / pairing tokens, session tokens, `Authorization` / bearer credentials, API keys.
- Passwords, passphrases, or the raw bytes of an encrypted key store.

Load-bearing PUBLIC identifiers MAY be logged: store ids, root hashes, coin ids, peer IPs, ports.

## 8. Collection layer — `logs` verbs, redaction, bundle (D7)

### 8.1 `logs` CLI verbs

dig-logging ships a reusable clap subcommand a binary mounts verbatim as `<bin> logs …`:

- `logs path [--json]` — print the resolved service log directory (§3). `--json`:
  `{"dir": "<path>"}`.
- `logs tail [-f] [-n N] [--level L] [--json]` — print the most recent lines of the current day's
  file. Default renders each JSONL line as compact human text; `--level L` filters to records at or
  above `L`; `--json` passes matching lines through raw (one JSON object per line). `-f` follows.
- `logs level [<filter>]` — with no argument, print the resolved effective filter; with a `<filter>`
  argument, persist it (live-apply is the consumer's wiring, §5). `--json` prints
  `{"filter": "<f>"}`.
- `logs bundle [-o out.zip] [--all] [--since <dur>]` — write a REDACTED zip (§8.3). `--all` bundles
  the ENTIRE DigNetwork log root (every service — trivial because of the single root §3); default
  bundles only this service. `--since <dur>` (e.g. `24h`, `7d`) limits by file date.

### 8.2 Redaction engine — `dig_logging::redact` (versioned rule set)

Redaction is applied to every line at BUNDLE time (and, later, report time) — the bundle writer
re-redacts the raw on-disk JSONL as it zips it. It is NEVER applied at write time: the on-disk log
files hold RAW lines, so `logs tail` and any manual copy of a log file see un-redacted text. Bundle
redaction is thus the guaranteed chokepoint for anything sent off-box; it is the SECOND line of
defense, never a substitute for §7 (the never-log-at-source rule remains the primary guarantee).
The rule set is versioned (`redaction_rules_version`, recorded in the bundle manifest). Rules
(applied to each line's raw text so both `message` and any structured field are covered):

- **REDACT** (replace the value with `[REDACTED:<kind>]`):
  - **BIP39 mnemonic runs** — a run of **≥ 12 consecutive** English-BIP39-wordlist words (case-
    insensitive), whether in `key=value`, a bare comment line, a NUMBERED `1. abandon 2. ability …`
    layout, or split across the text. This MUST catch comment-style, numbered, and multi-line
    placements, not only `key=value` (the `.test-credentials` leak: seeds live as `# Mnemonic:`
    comment lines). Non-English BIP39 wordlists are an ACCEPTED RESIDUAL — the detector uses the
    English wordlist only (bundling all wordlists is out of scope); source-discipline (§7) covers
    non-English seeds.
  - **Private-key / seed FIELDS (field-name-driven)** — a field whose NAME marks it secret has its
    value redacted, in `key=value`, `key: value`, or JSON `"key":"value"` form, covering raw
    base64/hex values (the DIG identity signing key, the beacon Ed25519 key): `private_key`,
    `secret_key`, `signing_key`, `beacon_key`, `sk`, `xprv`, `wif`, `seed`, `mnemonic`, and generally
    any name ending `_key`/`_secret` or containing `seed`/`mnemonic`. Private-key markers WITHOUT a
    `_key` suffix are matched precisely (`priv`, a `priv_` prefix, `privkey`/`privatekey`/`xpriv`), so
    incidental `priv` substrings (`privacy`, `private-beta`) are NOT over-scrubbed. Redaction is
    FIELD-NAME-driven, NOT a blanket entropy heuristic — see KEEP below.
  - **Generic `key`/`keystore` FIELDS (value-shape-gated)** — the bare names `key` and `keystore`
    are too generic to blanket-scrub (a `key=user_id` map-debug line is not a secret), so their value
    is redacted ONLY when it looks like raw secret material (a ≥ 20-char hex or base64/base64url blob).
    Short/obviously-non-secret values (`key=user_id`, `keystore=default`) are KEPT.
  - **Bare prose key phrases** — `<kind> key <hex-or-base64>` for `kind` ∈
    `signing|private|secret|beacon|identity|node|master|ed25519|bls|api` (e.g. `loaded identity key
    <hex>`, `node key <hex>`), which no kv rule would catch.
  - **Positional / Debug-struct shapes** — a secret TYPE name immediately wrapping a value with no
    `:`/`=` separator: `PrivKey(…)`, `SecretKey(…)`, `SigningKey(…)`, `SecretString(…)`, `Seed([…])`,
    `Mnemonic("…")`, `KeyPair(…)`, `Xprv(…)`, `MasterKey(…)`, and prefixed/aliased forms such as
    `ExtendedPrivKey(…)`, `MasterSecret(…)`, `BlsSk(…)`, `Ed25519Sk(…)`. Detection is SUFFIX-driven —
    a CamelCase type name that ENDS in a secret marker (`*PrivKey`/`*SecretKey`/`*Secret`/`*Seed`/
    `*Sk`/…), so a leading qualifier is absorbed. The `Sk` abbreviation is matched CASE-SENSITIVELY so
    benign words ending in lowercase `sk` (`Task(…)`, `Disk(…)`) and unrelated wrappers (`Coin(…)`,
    `Peer(…)`) are left alone. **This TYPE list is explicitly NON-EXHAUSTIVE**: a novel secret type
    name can still slip through, so source-discipline (§7 — never log a secret in the first place)
    remains the PRIMARY defense; this rule is defense-in-depth for the common Debug shapes.
  - **PEM blocks** — `-----BEGIN … -----` … `-----END … -----`, including blocks split across lines.
  - **`Authorization` / bearer values** — `Authorization: <v>`, `Bearer <v>`.
  - **Control / pairing / API / session token values** — `token`/`api_key`/`apikey`/`secret`/
    `password`/`passphrase`/`pairing_code` = / : `<v>` (JSON or `key=value`).
- **TRUNCATE**:
  - bech32 `xch1…` / `txch1…` addresses → keep the HRP + first 8 payload chars, then `…`.
  - home-dir usernames in paths: `C:\Users\<u>`, `/home/<u>`, `/Users/<u>` → `…\<user>` / `…/<user>`.
- **KEEP** (never redacted — public + load-bearing for debugging, even though they are ALSO 32-byte
  hex/base64): store ids, root hashes, coin ids, puzzle hashes, peer IPs, ports, and the safe field
  names `store_id`/`root`/`root_hash`/`coin_id`/`puzzle_hash`/`owner_puzzle_hash`/`peer`/`addr`/`ip`/
  `generation`/`capsule`/`resource_key`/`public_key`. Key redaction is therefore field-NAME-driven
  and MUST NOT blanket-scrub high-entropy hex/base64; the safe field names override the `_key`/
  `_secret` suffix rule (e.g. `resource_key` is kept). When in doubt a value is KEPT unless its field
  name is explicitly sensitive — a false-scrub of a storeId breaks debugging, so keys are named
  explicitly rather than guessed by entropy.

### 8.3 Bundle format

A `logs bundle` zip contains, at the archive root:

- `manifest.json` — `{schema:1, service, service_version, os, arch, created_at (RFC3339 UTC),
  redaction_rules_version, files:[{name, bytes}]}`.
- The REDACTED log files (`--all` → nested `<service>/<file>` per service). NEVER config files,
  NEVER key material, NEVER the raw un-redacted logs.

## 9. Public API surface (informative — §2/§3/§5/§6/§8 are the contract)

```rust
pub struct Service { pub name: &'static str, pub version: &'static str, pub run_context: RunContext }
pub enum RunContext { Service, Cli }
pub fn init(service: Service) -> Result<LogGuard, Error>;           // real env + filesystem
impl LogGuard { pub fn set_filter(&self, directive: &str) -> Result<(), Error>; }

pub fn resolve_log_dir(service, get_env, can_create) -> PathBuf;    // pure, table-testable
pub fn resolve_filter(persisted, dig_log, rust_log) -> String;      // pure precedence (§5)
pub fn resolve_valid_filter(persisted, dig_log, rust_log) -> String; // precedence + EnvFilter validity (§5)

pub mod redact { pub fn line(input: &str) -> String; pub const RULES_VERSION: u32; }
pub mod logs { pub fn command() -> clap::Command; pub fn run(service, matches) -> Result<()>; }
```
