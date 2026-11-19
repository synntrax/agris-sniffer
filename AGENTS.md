# Agent guide: agris-sniffer

Instructions for AI coding agents and humans working in this repo. `CLAUDE.md` imports this file.

## Keep the change log current (required)

Every change adds a line under `## [Unreleased]` in [`CHANGELOG.md`](CHANGELOG.md), in [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) style:

- Use the subsections **Added / Changed / Fixed / Removed / Security**.
- Say what changed, why, and the key file(s).
- On release: bump `agris-sniffer/Cargo.toml`, plus `sniffer-core/Cargo.toml` if it changed. Rename `[Unreleased]` to `[X.Y.Z] - date` and tag `vX.Y.Z`.
- Read the change log first when picking up work here.

## What this is

This is the privileged packet-capture sidecar for the Agris desktop app. It's open source because it runs with capture privileges, so keep it auditable:

- it makes no network connections;
- it writes no files (except `--probe` in dev builds);
- it holds no game data (the item list comes from `--items`).

The app pulls this repo in as the git submodule `apps/desktop/crates/sniffer` and downloads a **pinned** release binary (`sniffer.lock.json` in the app). A fix here reaches users only after: tag a release, bump the submodule, re-pin, then release the app.

## Layout

- `sniffer-core/`: platform-independent logic, with unit tests.
  - `parser.rs`: the loot prefix `85 fa 57 45`, plus per-payload parsing (UDP).
  - `tracker.rs`: `LootOffsetTracker`. It learns where the `(item_id u32 LE, qty u32 LE)` pair sits relative to the prefix and searches ±`WINDOW` bytes.
  - `stream.rs`: TCP reassembly, so records split across segments are found.
  - `protocol.rs`: the JSON-lines events to the app. Bump `PROTOCOL_VERSION` on breaking changes.
- `agris-sniffer/`: the pcap binary. A capture thread feeds a byte-capped queue to the processing thread.

## Invariants

- **Each `(item_id, qty)` pair is counted once.** Several prefixes can sit within `WINDOW` bytes of one pair. Callers pass `min_off` to `LootOffsetTracker::resolve_from`: past the last counted pair (`Flow::claimed_end` in `stream.rs`, a local in `parse_payload`). Without this, widening `WINDOW` doubled every drop.
- `WINDOW` lives only in `tracker.rs`. `stream.rs` derives `NEED_AFTER` and `KEEP_BEHIND` from it, so change it there.
- Retransmitted TCP bytes are trimmed, so they're never counted twice.
- Per-packet work in the binary has to be cheap. The sniffer runs next to the game, and `--payloads` hex-encodes every incoming packet (`to_hex`, no per-byte allocations).

## Build and test

```
cd sniffer-core && cargo test
cd agris-sniffer && cargo test && cargo build --release
cd agris-sniffer && cargo build --features probe   # dev research build
```
