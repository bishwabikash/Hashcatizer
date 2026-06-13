use crate::common::to_hex;

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    // OpenBSD softraid volume header: first 512 bytes
    if data.len() < 512 { return None; }
    Some(vec![format!("$softraid$0*{}", to_hex(&data[..512]))])
}
