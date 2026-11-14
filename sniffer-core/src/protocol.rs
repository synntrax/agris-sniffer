//! JSON-lines protocol between the privileged sidecar and the app.
use serde::{Deserialize, Serialize};

/// Bumped on any breaking change to the arguments or events below. The app
/// refuses a sniffer whose protocol differs (see `agris-sniffer --version`).
pub const PROTOCOL_VERSION: u32 = 1;

/// Printed by `agris-sniffer --version`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    pub version: String,
    pub protocol: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SnifferEvent {
    Ready { iface: String, filter: String },
    Loot { item_id: u32, name: String, qty: u32, ts: u64 },
    Stats {
        packets: u64,
        matches: u64,
        /// Packets the kernel/driver dropped before we could read them.
        #[serde(default)]
        dropped: u64,
        /// Packets captured but not yet parsed.
        #[serde(default)]
        queued: u64,
        /// TCP gaps (lost segments) the reassembler had to skip.
        #[serde(default)]
        gaps: u64,
    },
    Error { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceInfo {
    pub name: String,
    pub description: Option<String>,
    pub loopback: bool,
    pub up: bool,
    pub addresses: Vec<String>,
}
