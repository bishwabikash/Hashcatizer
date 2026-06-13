pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;
    let mut out = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        // prosody SCRAM entries: user:N:salt:stored_key:server_key
        if l.contains("scram") || l.contains("SCRAM") {
            let parts: Vec<&str> = l.splitn(5, ':').collect();
            if parts.len() == 5 {
                out.push(format!("$scram${}${}${}${}", parts[1], parts[2], parts[3], parts[4]));
            }
        } else if l.contains(':') {
            out.push(l.to_string());
        }
    }
    if out.is_empty() { None } else { Some(out) }
}
