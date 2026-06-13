use crate::common::{to_hex, u32_be};

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    // Java KeyStore: magic 0xFEEDFEED
    if data.len() < 36 { return None; }
    if u32_be(data, 0) != 0xFEEDFEED { return None; }
    // SHA1 pre-image starts at data[4..], end: last 20 bytes
    let sha1_off = data.len() - 20;
    let sha1     = to_hex(&data[sha1_off..]);
    let hex32    = to_hex(&data[4..data.len().min(36)]);
    Some(vec![format!("$keystore$0*{}*{}", sha1, hex32)])
}
