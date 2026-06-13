use crate::common::to_hex;

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    // Kerberos credential cache: magic 0x0504/0x0503/0x0502/0x0501
    if data.len() < 4 { return None; }
    let version = u16::from_be_bytes([data[0], data[1]]);
    if !(0x0501..=0x0504).contains(&version) { return None; }
    let limit = data.len().min(512);
    Some(vec![format!("$krb5cc$0*{}", to_hex(&data[..limit]))])
}
