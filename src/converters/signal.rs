use std::path::Path;

// Signal Desktop -> $signal$ (john).
//
//   $signal$1*<salt>*<encrypted key>
//
// Signal Desktop keeps the wrapped database key in `config.json` as hex
// strings, which is the only layout john's extractor recognises.
//
// The previous implementation additionally guessed at a "binary protobuf" and a
// "raw" layout, hex-dumping fixed byte ranges for both. Neither corresponds to
// anything Signal writes, and because they accepted almost any input they made
// this converter unusable in auto-detect. They are gone: if the key material is
// not in config.json, this reports nothing rather than inventing a hash.

pub fn convert(path: &Path) -> Option<Vec<String>> {
    let data = std::fs::read(path).ok()?;
    let json: serde_json::Value = serde_json::from_slice(&data).ok()?;
    let obj = json.as_object()?;

    let key = obj.get("encryptedKey").and_then(|v| v.as_str())?;
    let salt = obj.get("salt").and_then(|v| v.as_str())?;

    if !is_hex(key) || !is_hex(salt) {
        return None;
    }
    Some(vec![format!("$signal$1*{}*{}", salt, key)])
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.len().is_multiple_of(2) && s.chars().all(|c| c.is_ascii_hexdigit())
}
