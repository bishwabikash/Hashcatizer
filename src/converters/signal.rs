use crate::common::to_hex;
use std::path::Path;

pub fn convert(path: &Path) -> Option<Vec<String>> {
    let data = std::fs::read(path).ok()?;
    // JSON config.json
    if let Ok(j) = serde_json::from_slice::<serde_json::Value>(&data) {
        if let (Some(key), Some(salt)) = (
            j.get("encryptedKey").and_then(|v| v.as_str()),
            j.get("salt").and_then(|v| v.as_str()),
        ) {
            return Some(vec![format!("$signal$1*{}*{}", salt, key)]);
        }
    }
    // Binary protobuf
    if data.first() == Some(&0x0a) {
        return parse_protobuf(&data);
    }
    // Raw: salt at [4:36] if first 4 bytes = LE 32
    if data.len() >= 40 && u32::from_le_bytes(data[0..4].try_into().ok()?) == 32 {
        let salt    = to_hex(&data[4..36]);
        let enc_key = to_hex(&data[40..data.len().min(296)]);
        return Some(vec![format!("$signal$1*{}*{}", salt, enc_key)]);
    }
    None
}

fn parse_protobuf(data: &[u8]) -> Option<Vec<String>> {
    let salt    = to_hex(&data[..data.len().min(32)]);
    let iv      = to_hex(&data[32..data.len().min(44)]);
    let enc_end = (44 + 48).min(data.len());
    let enc     = to_hex(&data[44..enc_end]);
    Some(vec![format!("$signal$2*{}*{}*{}", salt, iv, enc)])
}
