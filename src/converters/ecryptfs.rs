use crate::common::to_hex;
pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    if data.len() < 56 { return None; }
    let salt    = to_hex(&data[0..8]);
    let wrapped = to_hex(&data[8..56]);
    Some(vec![format!("$ecryptfs$0$1${}${}", salt, wrapped)])
}
