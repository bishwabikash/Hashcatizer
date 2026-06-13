use crate::common::to_hex;

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    // Lotus Notes ID file: first 256 bytes contain salt material
    if data.len() < 256 { return None; }
    Some(vec![format!("$lotus$0*{}", to_hex(&data[..256]))])
}
