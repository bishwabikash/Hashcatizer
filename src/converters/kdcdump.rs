// KDC key dumps -> hashcat -m 1000 (NTLM).
//
//   $NT$<32 hex>
//
// A dump line is "principal:hash"; only entries whose second field is a real
// NT hash are emitted. The previous implementation hex-dumped the first 512
// bytes of whatever it was given.

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;
    let mut out = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((_principal, rest)) = line.split_once(':') else {
            continue;
        };
        let hash = rest.trim().trim_start_matches("$NT$");
        if hash.len() == 32 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
            out.push(format!("$NT${}", hash.to_ascii_lowercase()));
        }
    }
    if out.is_empty() { None } else { Some(out) }
}
