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
            // -m 1722 takes the 8 hex salt and 128 hex digest concatenated, with
            // no separator -- which is exactly the input layout. Emit it
            // unchanged.
            //
            // This used to be rewritten as "$ml$0$<salt>$<digest>". That is the
            // shape of -m 7100, but 7100 is the 10.8+ PBKDF2 format and needs a
            // real iteration count, so a zero there matches no mode at all and
            // the hash became uncrackable.
            let out = &hash[..136];
            if user.is_empty() {
                hashes.push(out.to_string());
            } else {
                hashes.push(format!("{}:{}", user, out));
            }
        }
    }
    if hashes.is_empty() { None } else { Some(hashes) }
}
