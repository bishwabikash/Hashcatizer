// ike-scan PSK parameter files -> hashcat -m 5300 (MD5) / 5400 (SHA1).
//
// The hash *is* the ike-scan line: nine colon-separated hex fields
//   g_xr : g_xi : cky_r : cky_i : sai_b : idir_b : ni_b : nr_b : hash_r
//
// Requiring all nine fields to be non-empty hex is what keeps this converter
// from claiming every text file that happens to contain a colon, which is what
// the previous "line contains ':'" test did.

const FIELDS: usize = 9;

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;
    let mut out = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if is_psk_parameters(line) {
            out.push(line.to_string());
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

fn is_psk_parameters(line: &str) -> bool {
    let fields: Vec<&str> = line.split(':').collect();
    fields.len() == FIELDS
        && fields
            .iter()
            .all(|f| !f.is_empty() && f.len() % 2 == 0 && f.chars().all(|c| c.is_ascii_hexdigit()))
}
