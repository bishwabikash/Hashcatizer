use crate::common::to_hex;

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    // KWallet: magic "KWALLET\n" at offset 0
    if data.len() < 8 { return None; }
    if &data[..7] != b"KWALLET" { return None; }
    let limit = data.len().min(512);
    Some(vec![format!("$kwallet$0*{}", to_hex(&data[..limit]))])
}
