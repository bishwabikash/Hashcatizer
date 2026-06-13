use crate::common::to_hex;

pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;
    let mut hashes = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        // Format: email:iterations:hash64hex
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() == 3 {
            let email = parts[0];
            let iters = parts[1];
            let hash64 = parts[2];
            // Require ASCII so the [..64] byte-slice can't split a multibyte char.
            if hash64.len() >= 64 && hash64.is_ascii() {
                let raw = hex::decode(&hash64[..64]).ok()?;
                let email_hex = to_hex(email.as_bytes());
                hashes.push(format!("$lastpass${}${}${}", iters, email_hex, to_hex(&raw[..32])));
                continue;
            }
        }
        // JSON format
        if let Ok(j) = serde_json::from_str::<serde_json::Value>(line) {
            if let (Some(iters), Some(email), Some(pw)) = (
                j.get("iterations").and_then(|v| v.as_u64()),
                j.get("username").and_then(|v| v.as_str()),
                j.get("password_hash").and_then(|v| v.as_str()),
            ) {
                hashes.push(format!("$lastpass${}${}${}", iters, to_hex(email.as_bytes()), pw));
            }
        }
    }
    if hashes.is_empty() { None } else { Some(hashes) }
}
