use crate::common::{to_hex, b64_decode};

pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    // Try JSON first
    if let Ok(j) = serde_json::from_slice::<serde_json::Value>(data) {
        return parse_json(&j);
    }
    // Raw hex (v1 — 64-char hex)
    let text = std::str::from_utf8(data).ok()?.trim();
    if text.len() == 64 && text.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(vec![format!("$electrum$1*{}", text)]);
    }
    // Base64 (v5)
    if let Ok(raw) = b64_decode(text) {
        if raw.len() >= 32 {
            return Some(vec![format!("$electrum$5*{}", to_hex(&raw))]);
        }
    }
    None
}

fn parse_json(j: &serde_json::Value) -> Option<Vec<String>> {
    // xprv (v3)
    if let Some(xprv) = j.get("xprv").or_else(|| j.pointer("/keystore/xprv")).and_then(|v| v.as_str()) {
        let raw = b64_decode(xprv).ok()?;
        return Some(vec![format!("$electrum$3*{}", to_hex(&raw))]);
    }
    // Encrypted seed (v4)
    if j.get("seed_version").is_some() {
        if j.get("use_encryption").and_then(|v| v.as_bool()).unwrap_or(false) {
            for key in &["seed", "master_private_keys", "keypairs"] {
                if let Some(ct) = j.get(key).and_then(|v| v.as_str()) {
                    if let Ok(raw) = b64_decode(ct) {
                        return Some(vec![format!("$electrum$4*{}", to_hex(&raw))]);
                    }
                }
            }
        }
    }
    None
}
