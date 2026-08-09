
pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    if !data.starts_with(b"$ANSIBLE_VAULT") {
        return None;
    }
    let text = std::str::from_utf8(data).ok()?;
    let mut lines = text.lines();
    let header = lines.next()?;
    let parts: Vec<&str> = header.split(';').collect();
    if parts.len() < 3 || parts[2].trim() != "AES256" {
        return None;
    }
    let body: String = lines.collect::<String>();
    let raw = hex::decode(body.trim()).ok()?;
    let parts2: Vec<&[u8]> = raw.split(|&b| b == b'\n').collect();
    if parts2.len() < 3 {
        return None;
    }
    // The vault body is hex-encoded ASCII whose three lines are *themselves*
    // hex strings, so they go out verbatim — hex-encoding them again would
    // double-encode the salt and ciphertext.
    let salt = std::str::from_utf8(parts2[0]).ok()?.trim();
    let checksum = std::str::from_utf8(parts2[1]).ok()?.trim();
    let ciphertext = std::str::from_utf8(parts2[2]).ok()?.trim();
    if !(salt.chars().all(|c| c.is_ascii_hexdigit()) && !salt.is_empty()) {
        return None;
    }
    Some(vec![format!("$ansible$0*0*{}*{}*{}", salt, ciphertext, checksum)])
}
