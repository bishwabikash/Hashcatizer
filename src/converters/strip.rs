use crate::common::to_hex;

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    // Strip password manager (SQLCipher): first 96 bytes
    // $strip$*<salt>*<iv>*<enc>
    if data.len() < 96 { return None; }
    let salt = to_hex(&data[..16]);
    let iv   = to_hex(&data[16..32]);
    let enc  = to_hex(&data[32..96]);
    Some(vec![format!("$strip$*{}*{}*{}", salt, iv, enc)])
}
