use std::collections::HashMap;

/// Item id -> item name.
pub type ItemDb = HashMap<u32, String>;

/// Parse `item_name,item_id` CSV. The id is always the last column, so names
/// containing commas still work.
pub fn parse_items_csv(csv: &str) -> ItemDb {
    csv.lines()
        .skip(1)
        .filter_map(|line| {
            let (name, id) = line.trim_end_matches('\r').rsplit_once(',')?;
            let name = name.trim().trim_matches('"');
            let id: u32 = id.trim().parse().ok()?;
            (!name.is_empty()).then(|| (id, name.to_string()))
        })
        .collect()
}

pub fn item_name(db: &ItemDb, id: u32) -> String {
    db.get(&id).cloned().unwrap_or_else(|| format!("Unknown ({id})"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_csv() {
        let db = parse_items_csv("item_name,item_id\nMushroom Hypha,44322\nbad,row,x\n");
        assert_eq!(db.get(&44322).map(String::as_str), Some("Mushroom Hypha"));
        assert_eq!(db.len(), 1);
    }
}
