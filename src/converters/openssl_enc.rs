use crate::common::to_hex;

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    // OpenSSL encrypted file: magic "Salted__" at offset 0
    if data.len() < 16 { return None; }
    if &data[..8] != b"Salted__" { return None; }
    let salt = to_hex(&data[8..16]);
    let ct   = to_hex(&data[16..]);
    Some(vec![format!("$openssl$0*{}*{}", salt, ct)])
}
