use crate::common::to_hex;
pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    if data.len() < 512 { return None; }
    Some(vec![format!("$DPAPImk${}", to_hex(&data[..data.len().min(512)]))])
}
