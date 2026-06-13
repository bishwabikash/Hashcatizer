use crate::common::to_hex;

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    // StarOffice / OOo older encrypted docs
    if data.len() < 512 { return None; }
    let limit = data.len().min(512);
    Some(vec![format!("$staroffice$*{}", to_hex(&data[..limit]))])
}
