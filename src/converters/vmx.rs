pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;
    for line in text.lines() {
        if line.trim_start().starts_with("encryption.keySafe") {
            let parts: Vec<&str> = line.splitn(2, '=').collect();
            if parts.len() == 2 {
                let val = parts[1].trim().trim_matches('"');
                return Some(vec![format!("$vmx${}", val)]);
            }
        }
    }
    None
}
