# Development log — dig-logging

Durable realizations. Concise facts with context, not a change diary.

- **File naming = prefix carries the extension.** `tracing-appender` names a rolling file
  `<prefix>.<date>` when no suffix is set. To land on the SPEC §4 name `<service>.jsonl.YYYY-MM-DD`,
  the appender is built with `filename_prefix = "<service>.jsonl"` and NO `filename_suffix` — do not
  set a `.jsonl` suffix (that yields `<service>.<date>.jsonl`, the wrong order).

- **The non-blocking writer is our own, not `tracing_appender::non_blocking`.** The SPEC requires
  surfacing the dropped-line count as a WARN, and the upstream non-blocking worker's drop counter is
  not publicly readable. `writer.rs` is a bounded-channel lossy writer exposing `dropped()`, which
  the hourly maintenance task reads to emit the WARN. It still drains into the rolling appender.

- **One global `EnvFilter` behind a `reload::Layer` filters BOTH sinks.** Added at the registry level
  (`.with(filter_layer)`), not per-layer, so `LogGuard::set_filter` swaps the live level for the file
  and stderr sinks together (SPEC §5).

- **`serde_json` needs `preserve_order`** for the record to serialize in the SPEC §2 field order;
  without it `Map` is a `BTreeMap` and fields come out alphabetically. Order is not semantically
  significant, but golden tests + human readability rely on it.

- **Redaction runs mnemonic detection FIRST, on the raw words.** BIP39 runs (≥12 consecutive
  wordlist words) are found before the regex rules perturb the text. Gaps between words allow
  whitespace + `\n`-escape + quotes/punctuation, so a comment-style (`# Mnemonic: …`) or `\n`-joined
  seed is caught — the `.test-credentials` leak (2026-07-12) proved comment-style seeds are the real
  hazard, not just `key=value`.

- **Log dir is user-READABLE, unlike the #501 state dirs.** State dirs are owner-only (they hold the
  control token); the log root is SYSTEM-writable but Users-readable, because logs are operator
  diagnostics and secrets are barred at source (SPEC §7) + redacted at bundle (SPEC §8.2).
