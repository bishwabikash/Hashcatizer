use crate::common::to_hex;

pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    // VeraCrypt — same as TrueCrypt, first 512 bytes are encrypted header
    if data.len() < 512 { return None; }
    Some(vec![to_hex(&data[0..512])])
}
