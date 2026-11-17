# agris-sniffer

The open-source packet-capture helper used by the **Agris** loot tracker for Black Desert Online.

Agris needs raw packet capture to see loot pickups, so this part runs with elevated network privileges. It's open source so you can check exactly what it does, and every release binary is built from this repo by GitHub Actions with a [build provenance attestation](#verifying-a-release).

## What it does (and doesn't)

- Captures packets on one network interface with libpcap (Linux) or Npcap (Windows). It reads only, never sends.
- Looks for loot records whose item id is in the item list it's given (`--items`), and prints them as JSON lines on stdout.
- Prints capture stats (packets, matches, drops) so the app can show how healthy the capture is.
- With `--payloads`, also passes the TCP data the game server sends your PC to the app, unchanged, as JSON lines on stdout. The app uses it to recognise your own character's actions (class detection). The sniffer doesn't interpret it, and it goes nowhere but the app.
- It contains no game data, makes no network connections, writes no files, and exits when its stdin closes or receives `stop`.

## Usage

```
agris-sniffer --version
agris-sniffer --list-interfaces
agris-sniffer --iface <name> --items <items.csv> [--ips 1.2.3.4,10.0.0.0/8] [--payloads]
```

`items.csv` is an `item_name,item_id` CSV. Output events are defined in [`sniffer-core/src/protocol.rs`](sniffer-core/src/protocol.rs).

The Agris app downloads this binary from this repo's Releases, checks its SHA-256, and starts it for you. You don't need to run it by hand.

## Permissions

- **Linux:** needs `libpcap` and the `cap_net_raw,cap_net_admin` capabilities (the app asks to grant them with `pkexec setcap`). It never needs to run as root.
- **Windows:** needs [Npcap](https://npcap.com/#download).

## Building

```
cargo build --release --manifest-path agris-sniffer/Cargo.toml
```

Linux needs `libpcap-dev` (or `libpcap` on Arch). Windows needs the [Npcap SDK](https://npcap.com/#download), with its `Lib/x64` on `LIB`.

## Verifying a release

Each release has a `SHA256SUMS` file, and each binary has a GitHub attestation linking it to the commit and workflow run that built it:

```
gh attestation verify agris-sniffer-x86_64-unknown-linux-gnu --repo synntrax/agris-sniffer
```

## Layout

- `sniffer-core/`: the parsing logic (loot-record parser, offset tracker, TCP reassembly, JSON protocol), with unit tests.
- `agris-sniffer/`: the capture binary.

## License

[MIT](LICENSE)
