use crate::common::b64_decode;
pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;
    let mut hashes = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("|1|") {
            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() >= 4 {
                let salt_hex = hex::encode(b64_decode(parts[2]).ok()?);
                let hash_hex = hex::encode(b64_decode(parts[3].split_whitespace().next().unwrap_or("")).ok()?);
                hashes.push(format!("$sshng${}${}", salt_hex, hash_hex));
            }
        }
    }
    if hashes.is_empty() { None } else { Some(hashes) }
}
