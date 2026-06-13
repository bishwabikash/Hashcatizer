use crate::common::to_hex;

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    // andOTP backup: first 12 bytes = IV, next 244 = encrypted data
    if data.len() < 256 { return None; }
    let iv  = to_hex(&data[..12]);
    let enc = to_hex(&data[12..256]);
    Some(vec![format!("$andotp${}*{}", iv, enc)])
}
