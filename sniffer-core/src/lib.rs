//! Platform-independent loot-capture logic used by the `agris-sniffer` binary
//! (and by the Agris app for the shared protocol types).
//!
//! It holds no game data: the item list is supplied at runtime (`--items`).

pub mod items;
pub mod parser;
pub mod protocol;
pub mod stream;
pub mod tracker;
