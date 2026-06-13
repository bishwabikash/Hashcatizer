use crate::common::to_hex;

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    // Monero wallet file: skip first 64 bytes of the spend key block
    // hashcat mode 26610: $monero$0*<hex48>
    if data.len() < 48 { return None; }
    Some(vec![format!("$monero$0*{}", to_hex(&data[..48]))])
}
