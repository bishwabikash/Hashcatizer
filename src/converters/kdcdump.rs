use crate::common::to_hex;

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;
    let mut out = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        // Format: principal:enctype:kvno:key_hex
        let parts: Vec<&str> = l.splitn(4, ':').collect();
        if parts.len() == 4 {
            let _ = parts[1].parse::<u32>().ok()?;
            out.push(format!("$krb5kdc${}*{}*{}*{}", parts[1], parts[2], parts[0], parts[3]));
        }
    }
    if out.is_empty() {
        // binary dump fallback
        let limit = data.len().min(256);
        Some(vec![format!("$krb5kdc$0*0*unknown*{}", to_hex(&data[..limit]))])
    } else { Some(out) }
}
