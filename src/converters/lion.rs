pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;
    let mut hashes = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        // Format: user:hashdata (136 hex chars = 4-byte salt + 64-byte digest)
        let (user, hashpart) = if let Some(p) = line.find(':') {
            (&line[..p], &line[p + 1..])
        } else {
            ("", line)
        };
        let hash = hashpart.trim();
        if hash.len() >= 136 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
            let salt   = &hash[..8];
            let digest = &hash[8..136];
            hashes.push(format!("{}:$ml$0${}${}", user, salt, digest));
        }
    }
    if hashes.is_empty() { None } else { Some(hashes) }
}
