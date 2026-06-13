use crate::common::{to_hex, u32_le};

pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    if data.len() < 72 || &data[0..4] != b"PWS3" { return None; }
    let salt      = to_hex(&data[4..36]);
    let iterations = u32_le(data, 36);
    let hp        = to_hex(&data[40..72]);
    Some(vec![format!("$pwsafe$*3*{}*{}*{}", salt, iterations, hp)])
}
