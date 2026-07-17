# dig-logging — local runbook

## Prereqs
- Rust stable (edition 2021, MSRV 1.75).

## Build + test
```bash
cargo build --all-features
cargo test --all-features -- --test-threads=1   # integration test installs a global subscriber
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo llvm-cov --all-features --fail-under-lines 80   # coverage gate (>=80%)
```

## Try it
```bash
DIG_LOG_DIR=/tmp/diglogs DIG_LOG=debug cargo run --example demo
cat /tmp/diglogs/dig-node/dig-node.jsonl.$(date -u +%F)   # the JSONL file
```

## Release / publish (this crate is `modules/crates` → per-merge tag, SPEC-first crates.io dep)
- Merge to `main` → `.github/workflows/release.yml` regenerates `CHANGELOG.md`, commits it, and tags
  `vX.Y.Z` (pushed with `RELEASE_TOKEN`, a PAT — a `GITHUB_TOKEN` tag would not trigger downstream).
- The `v*` tag triggers `.github/workflows/publish.yml` → `cargo publish` to crates.io, gated on the
  `CARGO_REGISTRY_TOKEN` repo secret (a crates.io API token). Consumers depend on the published
  version (NOT a git dep — the #681 no-git-deps policy).

## Secrets to set on the repo
- `RELEASE_TOKEN` — the ecosystem PAT (set).
- `CARGO_REGISTRY_TOKEN` — a crates.io API token (REQUIRED before the first publish can succeed).
