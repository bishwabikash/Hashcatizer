pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;
    let mut hashes = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        // Tab-separated: USER\tBCODE\tPASCODE
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() >= 2 {
            let user  = parts[0].trim().to_uppercase();
            let bcode = parts[1].trim().to_uppercase();
            if bcode.len() == 16 && bcode.chars().all(|c| c.is_ascii_hexdigit()) {
                hashes.push(format!("{}:{}", user, bcode));
            }
            if parts.len() >= 3 {
                let pass = parts[2].trim();
                if pass.len() == 40 {
                    hashes.push(format!("{}:{}", user, pass));
                }
            }
            continue;
        }
        // {x-issha, N} passthrough
        if line.starts_with('{') {
            hashes.push(line.to_string());
        }
    }
    if hashes.is_empty() { None } else { Some(hashes) }
}
