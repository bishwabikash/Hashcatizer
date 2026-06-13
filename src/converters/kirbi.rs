use crate::common::to_hex;

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    // Kerberos ticket: starts with 0x76 (KRB_AS_REP) or 0x30 (DER seq)
    if data.is_empty() { return None; }
    if data[0] != 0x76 && data[0] != 0x30 { return None; }
    let limit = data.len().min(512);
    Some(vec![format!("$krb5tgs$0*unknown*{}", to_hex(&data[..limit]))])
}
