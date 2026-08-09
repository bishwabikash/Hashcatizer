// NetNTLMv1 / NetNTLMv2 -> hashcat -m 5500 / 5600.
//
//   v1: user::domain:lmresp(48):ntresp(48):challenge(16)
//   v2: user::domain:challenge(16):ntresp(32):blob
//
// Both are validated field by field. The old implementation accepted any line
// containing "::", which matches C++ source, IPv6 addresses and YAML alike.

pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;
    let mut hashes = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if classify(line).is_some() {
            hashes.push(line.to_string());
        }
    }
    if hashes.is_empty() { None } else { Some(hashes) }
}

/// hashcat mode for a validated line, or None if it is not NetNTLM at all.
pub fn classify(line: &str) -> Option<&'static str> {
    let f: Vec<&str> = line.split(':').collect();
    // user :: domain : a : b : c  -> the empty field is the "::" marker
    if f.len() != 6 || !f[1].is_empty() {
        return None;
    }
    let hex = |s: &str, n: usize| s.len() == n && s.chars().all(|c| c.is_ascii_hexdigit());
    let hexish = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit());

    if hex(f[3], 48) && hex(f[4], 48) && hex(f[5], 16) {
        Some("5500") // NetNTLMv1
    } else if hex(f[3], 16) && hex(f[4], 32) && hexish(f[5]) {
        Some("5600") // NetNTLMv2
    } else {
        None
    }
}
