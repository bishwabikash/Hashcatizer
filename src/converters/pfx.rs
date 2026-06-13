use crate::common::to_hex;

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    // PKCS#12 / PFX: magic 0x3082 or 0x3080
    if data.len() < 4 { return None; }
    let limit = data.len().min(4096);
    Some(vec![format!("$pfx$*{}*{}", limit, to_hex(&data[..limit]))])
}
