//! TCP stream reassembly so loot records that straddle segment boundaries are
//! not missed (the Python version scanned each packet in isolation).
//!
//! Each direction of each TCP connection keeps a small byte buffer. Segments
//! are appended in sequence order (retransmitted bytes are trimmed, out-of-order
//! segments wait in `pending`), and every loot prefix is resolved exactly once,
//! as soon as enough bytes after it have arrived (or the flow goes idle).

use std::collections::HashMap;
use std::net::IpAddr;

use crate::parser::{LootHit, PREFIX};
use crate::tracker::LootOffsetTracker;

/// Bytes needed after a prefix start before it can be resolved:
/// prefix (4) + tracker window (30) after the anchor.
const NEED_AFTER: usize = PREFIX.len() + 30;
/// Bytes kept before the scan position (tracker looks up to 30 bytes back).
const KEEP_BEHIND: usize = 64;
/// Give up waiting for a missing segment after this long / this much buffered.
const GAP_TIMEOUT_MS: u64 = 1_000;
const MAX_PENDING_BYTES: usize = 1 << 20;
/// Resolve trailing prefixes of a flow that has been quiet this long.
const IDLE_FLUSH_MS: u64 = 150;
/// Forget flows idle this long.
const FLOW_EXPIRY_MS: u64 = 120_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src: IpAddr,
    pub src_port: u16,
    pub dst: IpAddr,
    pub dst_port: u16,
}

#[derive(Default)]
struct Flow {
    next_seq: Option<u32>,
    buf: Vec<u8>,
    /// Prefix positions before this index have been resolved.
    scan_from: usize,
    /// Out-of-order segments: (seq, payload, arrival ms).
    pending: Vec<(u32, Vec<u8>, u64)>,
    pending_bytes: usize,
    last_seen_ms: u64,
    flushed: bool,
}

/// Signed distance from `b` to `a` in sequence space (handles wraparound).
fn seq_diff(a: u32, b: u32) -> i64 {
    a.wrapping_sub(b) as i32 as i64
}

impl Flow {
    fn append(&mut self, seq: u32, payload: &[u8]) -> bool {
        let next = *self.next_seq.get_or_insert(seq);
        let diff = seq_diff(seq, next);
        if diff > 0 {
            return false; // future segment
        }
        let skip = (-diff) as usize;
        if skip >= payload.len() {
            return true; // pure retransmission
        }
        let fresh = &payload[skip..];
        self.buf.extend_from_slice(fresh);
        self.next_seq = Some(next.wrapping_add(fresh.len() as u32));
        self.flushed = false;
        true
    }

    /// Append any pending segments that are now contiguous.
    fn drain_pending(&mut self) {
        loop {
            let Some(next) = self.next_seq else { return };
            let Some(i) = self.pending.iter().position(|(s, _, _)| seq_diff(*s, next) <= 0) else {
                return;
            };
            let (seq, data, _) = self.pending.swap_remove(i);
            self.pending_bytes -= data.len();
            self.append(seq, &data);
        }
    }

    /// Resolve prefixes that have enough trailing bytes (or all, if `flush`).
    fn scan(&mut self, tracker: &mut LootOffsetTracker, flush: bool, out: &mut Vec<LootHit>) {
        let len = self.buf.len();
        let mut pos = self.scan_from;
        while pos + PREFIX.len() <= len {
            let Some(rel) = self.buf[pos..].windows(PREFIX.len()).position(|w| w == PREFIX) else {
                pos = len + 1 - PREFIX.len(); // no prefix starts before here
                break;
            };
            let p = pos + rel;
            if !flush && p + NEED_AFTER > len {
                pos = p; // wait for more bytes
                break;
            }
            if let Some((item_id, qty, _)) = tracker.resolve(&self.buf, p + PREFIX.len()) {
                out.push(LootHit { item_id, qty });
            }
            pos = p + 1;
        }
        // Never jump past the last 3 bytes: they may be the start of a prefix
        // whose remainder arrives in the next segment.
        self.scan_from = pos.min(len).max(self.scan_from);
        if flush {
            self.flushed = true;
        }
        // Trim history we no longer need.
        let drop = self.scan_from.saturating_sub(KEEP_BEHIND);
        if drop > 0 {
            self.buf.drain(..drop);
            self.scan_from -= drop;
        }
    }

    /// A segment never arrived: resolve what we have, then jump past the gap.
    fn skip_gap(&mut self, tracker: &mut LootOffsetTracker, out: &mut Vec<LootHit>) {
        self.scan(tracker, true, out);
        self.buf.clear();
        self.scan_from = 0;
        let Some(next) = self.next_seq else { return };
        if let Some((seq, _, _)) = self.pending.iter().min_by_key(|(s, _, _)| seq_diff(*s, next)) {
            self.next_seq = Some(*seq);
        }
        self.drain_pending();
    }
}

pub struct TcpReassembler {
    flows: HashMap<FlowKey, Flow>,
    /// Segments whose missing predecessor never arrived (diagnostics).
    pub gaps_skipped: u64,
}

impl Default for TcpReassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpReassembler {
    pub fn new() -> Self {
        Self { flows: HashMap::new(), gaps_skipped: 0 }
    }

    /// Feed one TCP segment. `fin_or_rst` ends the flow (after resolving it).
    pub fn push(
        &mut self,
        tracker: &mut LootOffsetTracker,
        key: FlowKey,
        seq: u32,
        payload: &[u8],
        fin_or_rst: bool,
        now_ms: u64,
    ) -> Vec<LootHit> {
        let mut out = Vec::new();
        let flow = self.flows.entry(key).or_default();
        flow.last_seen_ms = now_ms;

        if !payload.is_empty() {
            if flow.append(seq, payload) {
                flow.drain_pending();
            } else {
                flow.pending_bytes += payload.len();
                flow.pending.push((seq, payload.to_vec(), now_ms));
            }
        }

        let oldest_pending = flow.pending.iter().map(|(_, _, t)| *t).min();
        if flow.pending_bytes > MAX_PENDING_BYTES
            || oldest_pending.is_some_and(|t| now_ms.saturating_sub(t) > GAP_TIMEOUT_MS)
        {
            self.gaps_skipped += 1;
            flow.skip_gap(tracker, &mut out);
        }

        flow.scan(tracker, false, &mut out);
        if fin_or_rst {
            flow.skip_gap(tracker, &mut out);
            flow.scan(tracker, true, &mut out);
            self.flows.remove(&key);
        }
        out
    }

    /// Periodic maintenance: resolve trailing prefixes of quiet flows, give up on
    /// stale gaps, and forget dead flows.
    pub fn tick(&mut self, tracker: &mut LootOffsetTracker, now_ms: u64) -> Vec<LootHit> {
        let mut out = Vec::new();
        for flow in self.flows.values_mut() {
            let idle = now_ms.saturating_sub(flow.last_seen_ms);
            if flow.pending.iter().any(|(_, _, t)| now_ms.saturating_sub(*t) > GAP_TIMEOUT_MS) {
                self.gaps_skipped += 1;
                flow.skip_gap(tracker, &mut out);
            }
            if idle >= IDLE_FLUSH_MS && !flow.flushed {
                flow.scan(tracker, true, &mut out);
            }
        }
        self.flows.retain(|_, f| now_ms.saturating_sub(f.last_seen_ms) < FLOW_EXPIRY_MS);
        out
    }

    /// Resolve everything still buffered (call before exiting).
    pub fn flush_all(&mut self, tracker: &mut LootOffsetTracker) -> Vec<LootHit> {
        let mut out = Vec::new();
        for flow in self.flows.values_mut() {
            flow.skip_gap(tracker, &mut out);
            while !flow.pending.is_empty() {
                flow.skip_gap(tracker, &mut out);
            }
            flow.scan(tracker, true, &mut out);
        }
        self.flows.clear();
        out
    }

    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const ITEM: u32 = 44322;

    fn key() -> FlowKey {
        FlowKey {
            src: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            src_port: 8888,
            dst: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_port: 50000,
        }
    }

    fn tracker() -> LootOffsetTracker {
        LootOffsetTracker::new([ITEM].into_iter().collect())
    }

    /// Stream with `n` loot records of qty 1..=n, padded between records.
    fn stream(n: u32) -> Vec<u8> {
        let mut v = vec![0xAAu8; 40];
        for q in 1..=n {
            v.extend_from_slice(&PREFIX);
            v.extend_from_slice(&[0u8; 6]);
            v.extend_from_slice(&ITEM.to_le_bytes());
            v.extend_from_slice(&q.to_le_bytes());
            v.extend_from_slice(&[0xBBu8; 50]);
        }
        v
    }

    fn total(hits: &[LootHit]) -> u32 {
        hits.iter().map(|h| h.qty).sum()
    }

    fn feed(segments: &[(u32, &[u8])]) -> Vec<LootHit> {
        let (mut r, mut t) = (TcpReassembler::new(), tracker());
        let mut hits = Vec::new();
        for (i, (seq, data)) in segments.iter().enumerate() {
            hits.extend(r.push(&mut t, key(), *seq, data, false, i as u64));
        }
        hits.extend(r.flush_all(&mut t));
        hits
    }

    #[test]
    fn record_split_across_segments_is_found() {
        let s = stream(3);
        // Split every 7 bytes: every record straddles several segments.
        let segs: Vec<(u32, &[u8])> =
            s.chunks(7).enumerate().map(|(i, c)| (1000 + (i * 7) as u32, c)).collect();
        let hits = feed(&segs);
        assert_eq!(hits.len(), 3);
        assert_eq!(total(&hits), 1 + 2 + 3);
    }

    #[test]
    fn retransmissions_are_not_double_counted() {
        let s = stream(2);
        let (a, b) = s.split_at(60);
        // a, a again (retransmit), overlapping a[50..]+b, b again.
        let mut overlap = a[50..].to_vec();
        overlap.extend_from_slice(b);
        let hits = feed(&[(0, a), (0, a), (50, &overlap), (60, b)]);
        assert_eq!(total(&hits), 1 + 2);
    }

    #[test]
    fn out_of_order_segments_are_reordered() {
        let s = stream(4);
        let segs: Vec<(u32, &[u8])> = s.chunks(33).enumerate().map(|(i, c)| ((i * 33) as u32, c)).collect();
        let mut shuffled = segs.clone();
        shuffled.swap(1, 2);
        shuffled.swap(3, 5);
        assert_eq!(total(&feed(&shuffled)), 1 + 2 + 3 + 4);
    }

    #[test]
    fn sequence_wraparound() {
        let s = stream(2);
        let base = u32::MAX - 20;
        let segs: Vec<(u32, &[u8])> =
            s.chunks(25).enumerate().map(|(i, c)| (base.wrapping_add((i * 25) as u32), c)).collect();
        assert_eq!(total(&feed(&segs)), 3);
    }

    #[test]
    fn idle_tick_resolves_trailing_record() {
        let (mut r, mut t) = (TcpReassembler::new(), tracker());
        let mut s = stream(1);
        s.truncate(40 + 4 + 6 + 8); // record ends exactly at end of data
        let hits = r.push(&mut t, key(), 0, &s, false, 0);
        assert!(hits.is_empty(), "not enough lookahead yet");
        let hits = r.tick(&mut t, 1_000);
        assert_eq!(total(&hits), 1);
        assert!(r.tick(&mut t, 2_000).is_empty(), "resolved only once");
    }

    #[test]
    fn prefix_split_across_idle_flush_is_found() {
        let (mut r, mut t) = (TcpReassembler::new(), tracker());
        let s = stream(1);
        let cut = 40 + 2; // first 2 bytes of the prefix
        let mut hits = r.push(&mut t, key(), 0, &s[..cut], false, 0);
        hits.extend(r.tick(&mut t, 1_000)); // idle flush between the halves
        hits.extend(r.push(&mut t, key(), cut as u32, &s[cut..], false, 1_001));
        hits.extend(r.flush_all(&mut t));
        assert_eq!(total(&hits), 1);
    }

    #[test]
    fn missing_segment_is_skipped_after_timeout() {
        let s = stream(3);
        let (mut r, mut t) = (TcpReassembler::new(), tracker());
        let segs: Vec<(u32, &[u8])> = s.chunks(64).enumerate().map(|(i, c)| ((i * 64) as u32, c)).collect();
        let mut hits = Vec::new();
        for (i, (seq, d)) in segs.iter().enumerate() {
            if i == 1 {
                continue; // lost
            }
            hits.extend(r.push(&mut t, key(), *seq, d, false, 0));
        }
        hits.extend(r.tick(&mut t, 5_000));
        hits.extend(r.flush_all(&mut t));
        assert!(r.gaps_skipped >= 1);
        assert!(total(&hits) >= 2, "records outside the lost segment still count");
    }
}
