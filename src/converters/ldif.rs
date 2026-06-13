use crate::common::b64_decode;

pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;
    let mut hashes = Vec::new();
    let mut cur_user = String::new();
    let mut pending = String::new();

    for line in text.lines() {
        // Multi-line continuation
        if line.starts_with(' ') && !pending.is_empty() {
            pending.push_str(line.trim_start());
            continue;
        }
        // Check previous pending
        if !pending.is_empty() {
            if let Some(h) = parse_password_line(&pending, &cur_user) {
                hashes.push(h);
            }
            pending.clear();
        }
        if line.to_lowercase().starts_with("dn:") {
            if let Some(uid) = extract_uid(line) {
                cur_user = uid;
            }
        } else if line.to_lowercase().starts_with("userpassword:: ") {
            pending = line.to_string();
        } else if line.to_lowercase().starts_with("userpassword: ") {
            if let Some(h) = parse_literal_password(&line["userpassword: ".len()..], &cur_user) {
                hashes.push(h);
            }
        }
    }
    if !pending.is_empty() {
        if let Some(h) = parse_password_line(&pending, &cur_user) {
            hashes.push(h);
        }
    }
    if hashes.is_empty() { None } else { Some(hashes) }
}

fn parse_password_line(line: &str, user: &str) -> Option<String> {
    // Double colon = base64
    let lower = line.to_lowercase();
    if lower.starts_with("userpassword:: ") {
        let b64 = &line["userpassword:: ".len()..];
        let raw = b64_decode(b64).ok()?;
        let val = String::from_utf8_lossy(&raw);
        return Some(format!("{}:{}", user, val));
    }
    None
}

fn parse_literal_password(val: &str, user: &str) -> Option<String> {
    Some(format!("{}:{}", user, val.trim()))
}

fn extract_uid(dn_line: &str) -> Option<String> {
    // dn: uid=jsmith, ou=...
    let rest = dn_line.splitn(2, ':').nth(1)?.trim();
    for part in rest.split(',') {
        let kv: Vec<&str> = part.trim().splitn(2, '=').collect();
        if kv.len() == 2 && (kv[0].eq_ignore_ascii_case("uid") || kv[0].eq_ignore_ascii_case("cn")) {
            return Some(kv[1].trim().to_string());
        }
    }
    Some(rest.to_string())
}
