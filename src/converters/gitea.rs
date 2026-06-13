pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;
    let mut out = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with("$2a$") || l.starts_with("$2b$") || l.starts_with("$2y$") {
            out.push(l.to_string());
        } else if l.starts_with("pbkdf2:") || l.contains("$pbkdf2") {
            out.push(l.to_string());
        }
    }
    if out.is_empty() { None } else { Some(out) }
}
