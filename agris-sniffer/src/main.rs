//! Privileged capture sidecar. Captures packets with libpcap/Npcap, extracts
//! loot records with `sniffer-core`, and writes `SnifferEvent`s as JSON lines
//! to stdout. Exits when stdin closes or receives a `stop` line.
//!
//! Pipeline (so no loot is skipped):
//!   capture thread --(unbounded queue)--> processing thread
//! The capture thread only copies packets off the (32 MB) kernel buffer, so slow
//! parsing never causes drops. The processing thread reassembles TCP streams so
//! records split across segments are found. On stop, everything already queued
//! is processed and flushed before exit.
//!
//! Usage:
//!   agris-sniffer --version
//!   agris-sniffer --list-interfaces
//!   agris-sniffer --iface <name> --items <items.csv> [--ips 1.2.3.4,10.0.0.0/8]
//!
//! `--items` is an `item_name,item_id` CSV of the loot to recognise (the app
//! supplies it, so this binary contains no game data).

use std::io::{BufRead, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap::{Capture, Device, Linktype};
use sniffer_core::items::{ItemDb, item_name, parse_items_csv};
use sniffer_core::parser::{LootHit, parse_payload};
use sniffer_core::protocol::{InterfaceInfo, PROTOCOL_VERSION, SnifferEvent, VersionInfo};
use sniffer_core::stream::{FlowKey, TcpReassembler};
use sniffer_core::tracker::LootOffsetTracker;

const KERNEL_BUFFER_BYTES: i32 = 32 * 1024 * 1024;

fn emit(ev: &SnifferEvent) {
    let mut out = std::io::stdout().lock();
    let _ = serde_json::to_writer(&mut out, ev);
    let _ = out.write_all(b"\n");
    let _ = out.flush();
}

fn fail(message: impl Into<String>) -> ! {
    emit(&SnifferEvent::Error { message: message.into() });
    std::process::exit(1);
}

struct Args {
    version: bool,
    list_interfaces: bool,
    iface: Option<String>,
    items: Option<String>,
    ips: Vec<String>,
}

fn parse_args() -> Args {
    let mut args = Args { version: false, list_interfaces: false, iface: None, items: None, ips: vec![] };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--version" | "-V" => args.version = true,
            "--list-interfaces" => args.list_interfaces = true,
            "--iface" => args.iface = it.next(),
            "--items" => args.items = it.next(),
            "--ips" => {
                args.ips = it
                    .next()
                    .unwrap_or_default()
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            }
            other => fail(format!("unknown argument: {other}")),
        }
    }
    args
}

/// Same filter as `build_bpf()` in live_monitor.py.
fn build_bpf(ips: &[String]) -> String {
    let base = "(tcp or udp)";
    if ips.is_empty() {
        return base.to_string();
    }
    let hosts = ips
        .iter()
        .map(|ip| if ip.contains('/') { format!("net {ip}") } else { format!("host {ip}") })
        .collect::<Vec<_>>()
        .join(" or ");
    format!("{base} and ({hosts})")
}

fn list_interfaces() {
    let devices = Device::list().unwrap_or_else(|e| fail(format!("failed to list interfaces: {e}")));
    let infos: Vec<InterfaceInfo> = devices
        .into_iter()
        .map(|d| InterfaceInfo {
            loopback: d.flags.is_loopback(),
            up: d.flags.is_up(),
            addresses: d.addresses.iter().map(|a| a.addr.to_string()).collect(),
            description: d.desc,
            name: d.name,
        })
        .collect();
    println!("{}", serde_json::to_string(&infos).unwrap());
}

fn sliced(linktype: Linktype, data: &[u8]) -> Option<SlicedPacket<'_>> {
    match linktype {
        Linktype::ETHERNET => SlicedPacket::from_ethernet(data).ok(),
        Linktype::LINUX_SLL => SlicedPacket::from_linux_sll(data).ok(),
        Linktype::RAW | Linktype::IPV4 | Linktype::IPV6 => SlicedPacket::from_ip(data).ok(),
        // BSD loopback / Npcap loopback adapter: 4-byte address family header.
        Linktype::NULL | Linktype::LOOP => SlicedPacket::from_ip(data.get(4..)?).ok(),
        _ => None,
    }
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Parses queued packets: TCP via stream reassembly, UDP per datagram.
struct Processor {
    items: ItemDb,
    tracker: LootOffsetTracker,
    tcp: TcpReassembler,
    linktype: Linktype,
    started: Instant,
    packets: u64,
    matches: u64,
}

impl Processor {
    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    fn handle(&mut self, data: &[u8]) {
        self.packets += 1;
        let Some(pkt) = sliced(self.linktype, data) else { return };
        let (src, dst) = match &pkt.net {
            Some(NetSlice::Ipv4(ip)) => (
                ip.header().source_addr().into(),
                ip.header().destination_addr().into(),
            ),
            Some(NetSlice::Ipv6(ip)) => (
                ip.header().source_addr().into(),
                ip.header().destination_addr().into(),
            ),
            _ => return,
        };
        let hits = match &pkt.transport {
            Some(TransportSlice::Tcp(t)) => {
                let key = FlowKey { src, src_port: t.source_port(), dst, dst_port: t.destination_port() };
                let now = self.now_ms();
                self.tcp.push(&mut self.tracker, key, t.sequence_number(), t.payload(), t.fin() || t.rst(), now)
            }
            Some(TransportSlice::Udp(u)) => parse_payload(&mut self.tracker, u.payload()),
            _ => return,
        };
        self.report(hits);
    }

    fn tick(&mut self) {
        let now = self.now_ms();
        let hits = self.tcp.tick(&mut self.tracker, now);
        self.report(hits);
    }

    fn flush(&mut self) {
        let hits = self.tcp.flush_all(&mut self.tracker);
        self.report(hits);
    }

    fn report(&mut self, hits: Vec<LootHit>) {
        for hit in hits {
            self.matches += 1;
            emit(&SnifferEvent::Loot {
                item_id: hit.item_id,
                name: item_name(&self.items, hit.item_id),
                qty: hit.qty,
                ts: now_unix(),
            });
        }
    }
}

fn load_items(path: &str) -> ItemDb {
    let csv = std::fs::read_to_string(path).unwrap_or_else(|e| fail(format!("failed to read item list '{path}': {e}")));
    let items = parse_items_csv(&csv);
    if items.is_empty() {
        fail(format!("item list '{path}' has no items (expected an item_name,item_id CSV)"));
    }
    items
}

fn run_capture(iface: &str, items: ItemDb, ips: &[String]) {
    let tracker = LootOffsetTracker::new(items.keys().copied().collect());

    let mut cap = Capture::from_device(iface)
        .and_then(|c| {
            c.promisc(false)
                .snaplen(65535)
                .buffer_size(KERNEL_BUFFER_BYTES)
                .timeout(200)
                .immediate_mode(true)
                .open()
        })
        // Non-blocking reads so the capture loop always notices a stop request,
        // even on a quiet network (immediate mode can ignore the read timeout).
        .and_then(|c| c.setnonblock())
        .unwrap_or_else(|e| fail(format!("failed to open interface '{iface}': {e}")));
    let filter = build_bpf(ips);
    if let Err(e) = cap.filter(&filter, true) {
        fail(format!("failed to set filter '{filter}': {e}"));
    }
    let linktype = cap.get_datalink();

    // Stop when stdin closes (parent exited / closed pipe) or sends "stop".
    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        std::thread::spawn(move || {
            for line in std::io::stdin().lock().lines() {
                match line {
                    Ok(l) if l.trim() == "stop" => break,
                    Ok(_) => continue,
                    Err(_) => break,
                }
            }
            stop.store(true, Ordering::SeqCst);
        });
    }

    // Capture thread: copy packets into an unbounded queue as fast as possible.
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let queued = Arc::new(AtomicU64::new(0));
    let dropped = Arc::new(AtomicU64::new(0));
    {
        let (stop, queued, dropped) = (stop.clone(), queued.clone(), dropped.clone());
        std::thread::spawn(move || {
            let mut last_stats = Instant::now();
            while !stop.load(Ordering::SeqCst) {
                match cap.next_packet() {
                    Ok(pkt) => {
                        queued.fetch_add(1, Ordering::Relaxed);
                        if tx.send(pkt.data.to_vec()).is_err() {
                            return;
                        }
                    }
                    // Kernel buffer empty: back off briefly (it keeps buffering meanwhile).
                    Err(pcap::Error::TimeoutExpired | pcap::Error::NoMorePackets) => {
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(e) => {
                        emit(&SnifferEvent::Error { message: format!("capture error: {e}") });
                        break;
                    }
                }
                if last_stats.elapsed() >= Duration::from_millis(500) {
                    if let Ok(s) = cap.stats() {
                        dropped.store((s.dropped + s.if_dropped) as u64, Ordering::Relaxed);
                    }
                    last_stats = Instant::now();
                }
            }
            // Dropping `tx` lets the processor drain the queue and finish.
        });
    }

    emit(&SnifferEvent::Ready { iface: iface.to_string(), filter });

    let mut proc = Processor {
        items,
        tracker,
        tcp: TcpReassembler::new(),
        linktype,
        started: Instant::now(),
        packets: 0,
        matches: 0,
    };
    let stats = |p: &Processor| SnifferEvent::Stats {
        packets: p.packets,
        matches: p.matches,
        dropped: dropped.load(Ordering::Relaxed),
        queued: queued.load(Ordering::Relaxed).saturating_sub(p.packets),
        gaps: p.tcp.gaps_skipped,
    };

    let mut last_tick = Instant::now();
    let mut last_stats = Instant::now();
    loop {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(data) => proc.handle(&data),
            Err(RecvTimeoutError::Timeout) => {}
            // Capture thread finished (stop requested) and the queue is drained.
            Err(RecvTimeoutError::Disconnected) => break,
        }
        if last_tick.elapsed() >= Duration::from_millis(100) {
            proc.tick();
            last_tick = Instant::now();
        }
        if last_stats.elapsed() >= Duration::from_secs(1) {
            emit(&stats(&proc));
            last_stats = Instant::now();
        }
    }
    proc.flush();
    emit(&stats(&proc));
}

fn main() {
    let args = parse_args();
    if args.version {
        let info = VersionInfo { version: env!("CARGO_PKG_VERSION").to_string(), protocol: PROTOCOL_VERSION };
        println!("{}", serde_json::to_string(&info).unwrap());
        return;
    }
    if args.list_interfaces {
        list_interfaces();
        return;
    }
    let Some(iface) = args.iface else { fail("missing --iface <name>") };
    let Some(items) = args.items else { fail("missing --items <items.csv>") };
    run_capture(&iface, load_items(&items), &args.ips);
}
