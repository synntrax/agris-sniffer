# Changelog

Notable changes to agris-sniffer. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow the `vX.Y.Z` tags. **Every change adds an entry under [Unreleased]**; see `AGENTS.md`.

## [Unreleased]

## [0.2.1] - 2026-11-19

### Fixed
- Loot counted twice (exactly double the in-game quantity).
  - **Cause:** `LootOffsetTracker` resolves each prefix to the closest valid `(item_id, qty)` pair within ±window bytes, looking backwards too, and nothing recorded which pairs were already counted. When the game sends the marker twice near one record, or a stray marker follows soon after a record, both anchors claimed the same pair. Widening the window made this happen for normal drops.
  - **Fix:** each pair is counted once. `resolve_from(data, anchor, min_off)` (`sniffer-core/src/tracker.rs`) ignores pairs before `min_off`. The TCP reassembler tracks an absolute `claimed_end` per flow (`stream.rs`), and `parse_payload` does the same within each UDP datagram (`parser.rs`). A rejected duplicate anchor no longer relearns a wrong offset.
  - Regression tests at windows 30 and 60.

### Changed
- `WINDOW` is now a single constant in `tracker.rs`. `NEED_AFTER` and `KEEP_BEHIND` in `stream.rs` are derived from it, so widening the window keeps reassembly consistent.
- `--payloads` and `--probe` hex-encode with a lookup table into one allocation (`to_hex`), instead of one `format!` String per byte. This cuts CPU per forwarded packet while the game is running.

## [0.2.0] - 2026-11-17
### Added
- `--payloads`: forward the server's TCP data to the app, raw (used for class detection).

## [0.1.1] - 2026-11-14
### Changed
- libpcap is linked statically, so the Linux binary runs on every distro.

## [0.1.0] - 2026-11-14
### Added
- First release: pcap/Npcap capture, loot parsing with TCP reassembly, JSON-lines protocol.

### Security
- Hardened against floods (flow, pending-segment and queue caps) and pcap filter injection (`--ips` validation).
