use crate::common::to_hex;
pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    if data.len() < 4096 { return None; }
    Some(vec![format!("$fvde$1*{}", to_hex(&data[..4096]))])
}
