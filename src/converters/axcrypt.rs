use crate::common::{to_hex, u32_le};

const MAGIC: &[u8] = b"\xc0\xb9\x07\x2e";

pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    if !data.starts_with(MAGIC) { return None; }
    let mut iterations = 0u32;
    let mut salt       = Vec::new();
    let mut wrapped    = Vec::new();
    let mut off = 4;
    while off + 6 < data.len() {
        let section_type  = u32_le(data, off); off += 4;
        let section_len   = u32_le(data, off) as usize; off += 4;
        if off + section_len > data.len() { break; }
        match section_type {
            4  => iterations = u32_le(data, off),
            5  => salt       = data[off..off + section_len].to_vec(),
            24 => wrapped    = data[off..off + section_len].to_vec(),
            _ => {}
        }
        off += section_len;
    }
    if salt.is_empty() { return None; }
    Some(vec![format!(
        "$axcrypt$*1*{}*{}*{}",
        iterations, to_hex(&salt), to_hex(&wrapped)
    )])
}
