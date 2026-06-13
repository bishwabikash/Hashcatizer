pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;
    let mut out = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        if l.contains(':') { out.push(l.to_string()); }
    }
    if out.is_empty() { None } else { Some(out) }
}
