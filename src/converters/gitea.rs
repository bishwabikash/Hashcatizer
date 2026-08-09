pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;
    let mut out = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        // Gitea stores either bcrypt or PBKDF2 password hashes.
        let is_bcrypt = l.starts_with("$2a$") || l.starts_with("$2b$") || l.starts_with("$2y$");
        let is_pbkdf2 = l.starts_with("pbkdf2:") || l.contains("$pbkdf2");
        if is_bcrypt || is_pbkdf2 {
            out.push(l.to_string());
        }
    }
    if out.is_empty() { None } else { Some(out) }
}
