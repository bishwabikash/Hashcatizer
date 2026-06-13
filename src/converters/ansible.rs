use crate::common::to_hex;

pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    if !data.starts_with(b"$ANSIBLE_VAULT") {
        return None;
    }
    let text = std::str::from_utf8(data).ok()?;
    let mut lines = text.lines();
    let header = lines.next()?;
    let parts: Vec<&str> = header.split(';').collect();
    if parts.len() < 3 || parts[2].trim() != "AES256" {
        return None;
    }
    let body: String = lines.collect::<String>();
    let raw = hex::decode(body.trim()).ok()?;
    let parts2: Vec<&[u8]> = raw.split(|&b| b == b'\n').collect();
    if parts2.len() < 3 {
        return None;
    }
    let salt = to_hex(parts2[0]);
    let checksum = to_hex(parts2[1]);
    let ciphertext = to_hex(parts2[2]);
    Some(vec![format!("$ansible$0*0*{}*{}*{}", salt, ciphertext, checksum)])
}
