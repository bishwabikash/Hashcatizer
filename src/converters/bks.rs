use crate::common::{to_hex, u16_be, u32_be};

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    // BKS keystore: magic 0x00000002 or 0x00000001
    if data.len() < 24 { return None; }
    let magic = u32_be(data, 0);
    if magic != 1 && magic != 2 { return None; }
    let ver       = magic;
    let salt_len  = u16_be(data, 4) as usize;
    if data.len() < 6 + salt_len + 4 + 20 { return None; }
    let salt      = to_hex(&data[6..6 + salt_len]);
    let iters     = u32_be(data, 6 + salt_len);
    let hmac_off  = 6 + salt_len + 4;
    let hmac      = to_hex(&data[hmac_off..hmac_off + 20]);
    let hex48_end = (hmac_off + 48).min(data.len());
    let hex48     = to_hex(&data[hmac_off..hex48_end]);
    Some(vec![format!("$bks${}*{}*{}*{}*{}*{}", ver, salt_len, salt, iters, hmac, hex48)])
}
