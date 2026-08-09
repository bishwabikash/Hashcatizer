// Cisco IOS config — extracts type 5/8/9 hashes and decodes type 7
const TYPE7_XLAT: &[u8] = b"\x64\x73\x66\x64\x3b\x6b\x66\x6f\x41\x2c\x2e\x69\x79\x65\x77\x72\
\x6b\x6c\x64\x4a\x4b\x44\x48\x53\x55\x42\x73\x67\x76\x63\x61\x36\
\x39\x38\x33\x34\x6e\x63\x78\x76\x39\x38\x37\x33\x32\x35\x34\x6b\
\x3b\x66\x67\x38\x37";

pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;
    let mut hashes = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(h) = extract_cisco_hash(line) {
            hashes.push(h);
        }
    }
    if hashes.is_empty() { None } else { Some(hashes) }
}

fn extract_cisco_hash(line: &str) -> Option<String> {
    // Type 5: "password 5 $1$..."
    if let Some(pos) = line.find("password 5 ").or_else(|| line.find("secret 5 ")) {
        let hash = line[pos + 11..].trim();
        if hash.starts_with("$1$") { return Some(hash.to_string()); }
    }
    // Type 8
    if let Some(pos) = line.find("password 8 ").or_else(|| line.find("secret 8 ")) {
        let hash = line[pos + 11..].trim();
        if hash.starts_with("$8$") { return Some(hash.to_string()); }
    }
    // Type 9
    if let Some(pos) = line.find("password 9 ").or_else(|| line.find("secret 9 ")) {
        let hash = line[pos + 11..].trim();
        if hash.starts_with("$9$") { return Some(hash.to_string()); }
    }
    // Type 4 (43-char base64)
    if let Some(pos) = line.find("password 4 ").or_else(|| line.find("secret 4 ")) {
        let val = line[pos + 11..].trim();
        if val.len() == 43 { return Some(val.to_string()); }
    }
    // Type 7 — decode
    if let Some(pos) = line.find("password 7 ") {
        let enc = line[pos + 11..].trim();
        if let Some(plain) = decode_type7(enc) {
            return Some(format!("[Type7 decoded] {}", plain));
        }
    }
    // enable / username secrets (passthrough)
    for prefix in &["enable secret ", "enable password "] {
        if let Some(rest) = line.strip_prefix(prefix) {
            let rest = rest.trim();
            if rest.starts_with('$') {
                return Some(rest.to_string());
            }
        }
    }
    None
}

fn decode_type7(enc: &str) -> Option<String> {
    // Type-7 is hex ASCII; reject anything else so byte-offset slicing below
    // can never land inside a multibyte UTF-8 character.
    if enc.len() < 4 || !enc.is_ascii() { return None; }
    let seed: usize = enc[..2].parse().ok()?;
    let mut result = String::new();
    let mut i = 2;
    let mut pos = seed;
    while i + 1 < enc.len() {
        let byte = u8::from_str_radix(&enc[i..i + 2], 16).ok()?;
        result.push((byte ^ TYPE7_XLAT[pos % 53]) as char);
        i += 2;
        pos += 1;
    }
    Some(result)
}
