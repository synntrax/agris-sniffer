use std::collections::HashSet;

/// Learns the byte offset between the loot prefix anchor and the
/// `(item_id: u32 LE, qty: u32 LE)` pair, then uses it as a fast path.
/// Port of the `LootOffsetTracker` from the original Python prototype.
pub struct LootOffsetTracker {
    known_item_ids: HashSet<u32>,
    window: usize,
    max_qty: u32,
    offset: Option<isize>,
    pub offset_confidence: u32,
}

fn read_u32_le(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

impl LootOffsetTracker {
    pub fn new(known_item_ids: HashSet<u32>) -> Self {
        Self {
            known_item_ids,
            window: 30,
            max_qty: 100_000,
            offset: None,
            offset_confidence: 0,
        }
    }

    fn valid(&self, item_id: u32, qty: u32) -> bool {
        self.known_item_ids.contains(&item_id) && qty > 0 && qty <= self.max_qty
    }

    fn read_pair(data: &[u8], off: usize) -> Option<(u32, u32)> {
        Some((read_u32_le(data, off)?, read_u32_le(data, off + 4)?))
    }

    /// Returns `(item_id, qty, offset_in_data)`.
    pub fn try_fast_path(&self, data: &[u8], anchor: usize) -> Option<(u32, u32, usize)> {
        let off = anchor as isize + self.offset?;
        if off < 0 {
            return None;
        }
        let off = off as usize;
        let (item_id, qty) = Self::read_pair(data, off)?;
        self.valid(item_id, qty).then_some((item_id, qty, off))
    }

    pub fn scan_and_relearn(&mut self, data: &[u8], anchor: usize) -> Option<(u32, u32, usize)> {
        let lo = anchor.saturating_sub(self.window);
        let hi = (anchor + self.window).min(data.len());
        let mut best: Option<(usize, usize, u32, u32)> = None;
        for off in lo..hi.saturating_sub(7) {
            let Some((item_id, qty)) = Self::read_pair(data, off) else {
                continue;
            };
            if !self.valid(item_id, qty) {
                continue;
            }
            let dist = off.abs_diff(anchor);
            if best.is_none_or(|b| dist < b.0) {
                best = Some((dist, off, item_id, qty));
            }
        }
        let (_, off, item_id, qty) = best?;
        self.offset = Some(off as isize - anchor as isize);
        self.offset_confidence = 1;
        Some((item_id, qty, off))
    }

    pub fn resolve(&mut self, data: &[u8], anchor: usize) -> Option<(u32, u32, usize)> {
        if let Some(hit) = self.try_fast_path(data, anchor) {
            self.offset_confidence += 1;
            return Some(hit);
        }
        self.offset_confidence = 0;
        self.scan_and_relearn(data, anchor)
    }

    pub fn offset(&self) -> Option<isize> {
        self.offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tracker() -> LootOffsetTracker {
        LootOffsetTracker::new([44322u32].into_iter().collect())
    }

    fn buf_with_pair_at(len: usize, off: usize, id: u32, qty: u32) -> Vec<u8> {
        let mut v = vec![0u8; len];
        v[off..off + 4].copy_from_slice(&id.to_le_bytes());
        v[off + 4..off + 8].copy_from_slice(&qty.to_le_bytes());
        v
    }

    #[test]
    fn learns_then_uses_fast_path() {
        let mut t = tracker();
        let data = buf_with_pair_at(64, 20, 44322, 25);
        assert_eq!(t.resolve(&data, 10), Some((44322, 25, 20)));
        assert_eq!(t.offset(), Some(10));
        assert_eq!(t.offset_confidence, 1);
        assert_eq!(t.resolve(&data, 10), Some((44322, 25, 20)));
        assert_eq!(t.offset_confidence, 2);
    }

    #[test]
    fn rejects_unknown_and_bad_qty() {
        let mut t = tracker();
        assert_eq!(t.resolve(&buf_with_pair_at(64, 20, 1, 25), 10), None);
        assert_eq!(t.resolve(&buf_with_pair_at(64, 20, 44322, 0), 10), None);
        assert_eq!(t.resolve(&buf_with_pair_at(64, 20, 44322, 100_001), 10), None);
    }

    #[test]
    fn relearns_when_offset_changes() {
        let mut t = tracker();
        t.resolve(&buf_with_pair_at(64, 20, 44322, 1), 10);
        let data = buf_with_pair_at(64, 14, 44322, 3);
        assert_eq!(t.resolve(&data, 10), Some((44322, 3, 14)));
        assert_eq!(t.offset(), Some(4));
    }
}
