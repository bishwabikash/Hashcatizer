/// Generic passthrough for already-formatted network hashes.
pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;
    let mut hashes = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        if line.starts_with('$') || line.contains("::") || line.contains(':') {
            hashes.push(line.to_string());
        }
    }
    if hashes.is_empty() { None } else { Some(hashes) }
}
