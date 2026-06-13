use crate::common::{to_hex, u32_le};

pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    // Scan for RESU + MMYS
    let mut pos = 0;
    while pos + 8 <= data.len() {
        if &data[pos..pos + 4] == b"RESU" && &data[pos + 4..pos + 8] == b"MMYS" {
            if let Some(h) = parse_user_entry(data, pos) {
                return Some(vec![h]);
            }
        }
        pos += 4;
    }
    None
}

fn parse_user_entry(data: &[u8], resu_pos: usize) -> Option<String> {
    // After 32-byte OnDiskUserInfo header
    let base = resu_pos + 32;
    if base + 164 > data.len() { return None; }
    let symm_alg      = data[base + 2];
    let username_bytes = &data[base + 8..base + 136];
    let username       = null_term(username_bytes);
    let s2k_type       = data[base + 136];
    let hash_iters     = u32_le(data, base + 137);
    let salt           = to_hex(&data[base + 144..base + 160]);
    let esk_end        = (base + 160 + 128).min(data.len());
    let esk            = to_hex(&data[base + 160..esk_end]);
    Some(format!(
        "{}:$pgpwde${}*{}*{}*{}*{}",
        username, symm_alg, s2k_type, hash_iters, salt, esk
    ))
}

fn null_term(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).to_string()
}
