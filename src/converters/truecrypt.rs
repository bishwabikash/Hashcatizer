use crate::common::to_hex;

pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    // TrueCrypt volumes have no magic — first 512 bytes are the encrypted header
    if data.len() < 512 { return None; }
    Some(vec![to_hex(&data[0..512])])
}
