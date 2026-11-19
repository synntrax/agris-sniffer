use crate::tracker::LootOffsetTracker;

/// Marker that precedes a loot record in a packet payload.
pub const PREFIX: [u8; 4] = [0x85, 0xfa, 0x57, 0x45];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LootHit {
    pub item_id: u32,
    pub qty: u32,
}

/// Every (possibly overlapping) start index of `prefix` in `buf`.
pub fn find_all_prefix<'a>(buf: &'a [u8], prefix: &'a [u8]) -> impl Iterator<Item = usize> + 'a {
    buf.windows(prefix.len())
        .enumerate()
        .filter(move |(_, w)| *w == prefix)
        .map(|(i, _)| i)
}

/// Scan one transport-layer payload for loot records. Each `(item_id, qty)` pair
/// counts once, even if several prefixes are close enough to reach it.
pub fn parse_payload(tracker: &mut LootOffsetTracker, data: &[u8]) -> Vec<LootHit> {
    let anchors: Vec<usize> = find_all_prefix(data, &PREFIX).collect();
    let mut min_off = 0;
    let mut hits = Vec::new();
    for start in anchors {
        if let Some((item_id, qty, off)) = tracker.resolve_from(data, start + PREFIX.len(), min_off) {
            min_off = off + 8;
            hits.push(LootHit { item_id, qty });
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_prefixed_record() {
        let mut t = LootOffsetTracker::new([44322u32].into_iter().collect());
        let mut data = vec![0xAA; 8];
        data.extend_from_slice(&PREFIX);
        data.extend_from_slice(&[0; 6]);
        data.extend_from_slice(&44322u32.to_le_bytes());
        data.extend_from_slice(&7u32.to_le_bytes());
        data.extend_from_slice(&[0; 8]);
        assert_eq!(parse_payload(&mut t, &data), vec![LootHit { item_id: 44322, qty: 7 }]);
    }

    #[test]
    fn repeated_prefix_counts_once() {
        let mut t = LootOffsetTracker::with_window([44322u32].into_iter().collect(), 60);
        let mut data = vec![0xAA; 8];
        data.extend_from_slice(&PREFIX);
        data.extend_from_slice(&[0; 2]);
        data.extend_from_slice(&PREFIX);
        data.extend_from_slice(&[0; 6]);
        data.extend_from_slice(&44322u32.to_le_bytes());
        data.extend_from_slice(&7u32.to_le_bytes());
        data.extend_from_slice(&PREFIX);
        data.extend_from_slice(&[0xCC; 40]);
        assert_eq!(parse_payload(&mut t, &data), vec![LootHit { item_id: 44322, qty: 7 }]);
    }

    #[test]
    fn no_prefix_no_hits() {
        let mut t = LootOffsetTracker::new([1u32].into_iter().collect());
        assert!(parse_payload(&mut t, &[1, 0, 0, 0, 1, 0, 0, 0]).is_empty());
    }
}
