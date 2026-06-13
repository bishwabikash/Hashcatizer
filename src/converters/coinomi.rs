use crate::common::to_hex;
pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    if data.len() < 48 { return None; }
    Some(vec![format!("$coinomi${}", to_hex(&data[..data.len().min(256)]))])
}
