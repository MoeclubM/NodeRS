# Changelog

## v0.0.19

This release keeps the validated `v0.0.18` datapath and adds an explicit release note for the delta since `v0.0.17`.

### Compared with `v0.0.17`

- Split the monolithic AnyTLS session implementation into focused modules:
  - `src/server/session/mod.rs`
  - `src/server/session/channel.rs`
  - `src/server/session/frame.rs`
  - `src/server/session/io.rs`
  - `src/server/session/writer.rs`
- Removed avoidable heap work from the upload batch write path.
- Kept the immediate-read download coalescing path that improved small-packet concurrent downloads without adding timer-based buffering.
- Preserved:
  - protocol correctness
  - per-user traffic accounting
  - user authentication and panel sync
  - online user reporting
- Re-ran:
  - `cargo test --offline`
  - `cargo clippy --offline --all-targets -- -D warnings`
  - benchmark comparison against `sing-box` AnyTLS

### Benchmarked and rejected after validation

These candidates were tested and intentionally not kept because they introduced measurable regressions:

- `Bytes`-based inbound payload pipeline
- buffered session writer (`BufWriter`)
- larger upload batch window (`256 KiB`)

The current branch therefore stays on the fastest validated implementation found in this round.
