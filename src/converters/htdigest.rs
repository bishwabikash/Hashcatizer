pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;
    let mut hashes = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() == 3 {
            hashes.push(format!("{}:$htdigest${}${}${}", parts[0], parts[0], parts[1], parts[2]));
        }
    }
    if hashes.is_empty() { None } else { Some(hashes) }
}
