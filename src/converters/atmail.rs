pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;
    let mut hashes = Vec::new();
    for line in text.lines() {
        // SQL INSERT format
        if let Some(v) = parse_values_line(line) {
            hashes.push(v);
            continue;
        }
        // Simple user:hash
        if let Some(pos) = line.find(':') {
            let hash = line[pos + 1..].trim();
            if !hash.is_empty() {
                hashes.push(line.to_string());
            }
        }
    }
    if hashes.is_empty() { None } else { Some(hashes) }
}

fn parse_values_line(line: &str) -> Option<String> {
    let upper = line.trim().to_uppercase();
    if !upper.starts_with("INSERT") {
        return None;
    }
    let re = regex::Regex::new(r"VALUES\s*\(\s*'([^']+)'\s*,\s*'([^']+)'").ok()?;
    let caps = re.captures(line)?;
    Some(format!("{}:{}", &caps[1], &caps[2]))
}
