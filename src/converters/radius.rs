// RADIUS shared-secret material extracted by radius2john.
//
// Only already-formatted "$radius$" lines are recognised. Deriving these from a
// raw capture needs the request/response pair plus the authenticator, which is
// pcap work rather than line parsing — the pcap converter is the right home for
// that, and pretending otherwise here produced a hash for any file containing a
// colon.

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;
    let mut out = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("$radius$") && line.len() > "$radius$".len() {
            out.push(line.to_string());
        }
    }
    if out.is_empty() { None } else { Some(out) }
}
