//! Canonical JSON serialization (RFC 8785 / JCS subset).
//!
//! For WLP compatibility we need deterministic serialization:
//! sorted keys, no trailing commas, no whitespace, no BOM.
//! serde_json with sorted keys gets us there for the types we use.

use serde::Serialize;
use serde_json::Value;

/// Serialize a value to canonical JSON bytes.
///
/// Keys are sorted lexicographically at every nesting level.
/// Output is compact (no whitespace).
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    let v = serde_json::to_value(value)?;
    let sorted = sort_keys(&v);
    serde_json::to_vec(&sorted)
}

fn sort_keys(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let sorted: serde_json::Map<String, Value> = map
                .iter()
                .map(|(k, v)| (k.clone(), sort_keys(v)))
                .collect();
            Value::Object(sorted)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(sort_keys).collect()),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn keys_are_sorted() {
        let mut map = BTreeMap::new();
        map.insert("zebra", 1);
        map.insert("alpha", 2);
        let bytes = canonical_json(&map).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert_eq!(s, r#"{"alpha":2,"zebra":1}"#);
    }

    #[test]
    fn nested_keys_sorted() {
        let mut inner = BTreeMap::new();
        inner.insert("z", 1);
        inner.insert("a", 2);
        let mut outer = BTreeMap::new();
        outer.insert("nested", inner);
        let bytes = canonical_json(&outer).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert_eq!(s, r#"{"nested":{"a":2,"z":1}}"#);
    }
}
