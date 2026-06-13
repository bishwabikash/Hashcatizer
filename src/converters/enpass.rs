use crate::common::to_hex;
pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    // SQLCipher: first 16 bytes = salt (must not be SQLite header), next 48 = enc page
    if data.starts_with(b"SQLite format 3\x00") { return None; }
    if data.len() < 64 { return None; }
    let salt     = to_hex(&data[0..16]);
    let enc_page = to_hex(&data[16..64]);
    Some(vec![format!("$enpass$0*24000*{}*{}", salt, enc_page)])
}
