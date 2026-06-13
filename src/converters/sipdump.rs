pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;
    let mut out = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        // SIP dump format: user*realm*nonce*uri*cnonce*nc*qop*response
        let parts: Vec<&str> = l.splitn(8, '*').collect();
        if parts.len() == 8 {
            out.push(format!("$sip$*{}*{}*{}*{}*{}*{}*{}*{}",
                parts[0], parts[1], parts[2], parts[3],
                parts[4], parts[5], parts[6], parts[7]));
        } else if l.contains(':') {
            out.push(l.to_string());
        }
    }
    if out.is_empty() { None } else { Some(out) }
}
