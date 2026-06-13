use crate::common::{to_hex, u32_le, u64_le};

pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    if data.len() < 32 || &data[0..6] != b"7z\xbc\xaf\x27\x1c" { return None; }
    // Start header
    let next_hdr_offset = u64_le(data, 12) as usize;
    let next_hdr_size   = u64_le(data, 20) as usize;
    let next_hdr_crc    = u32_le(data, 28);

    let hdr_start = 32 + next_hdr_offset;
    if hdr_start + next_hdr_size > data.len() { return None; }
    let hdr_data = &data[hdr_start..hdr_start + next_hdr_size];

    // Scan for AES codec ID
    let aes_id1 = b"\x06\xf1\x07\x01";
    let aes_id2 = b"\x06\xF1\x07";
    let pos = hdr_data.windows(4).position(|w| w == aes_id1)
        .or_else(|| hdr_data.windows(3).position(|w| w == aes_id2))?;
    let prop_start = pos + if hdr_data[pos..].starts_with(aes_id1) { 4 } else { 3 };
    if prop_start >= hdr_data.len() { return None; }

    let first_byte = hdr_data[prop_start];
    let num_cycles_power = first_byte & 0x3F;
    let has_salt = (first_byte & 0x80) != 0;
    let has_iv   = (first_byte & 0x40) != 0;

    let (salt_hex, iv_hex, salt_size, iv_size) = if has_salt || has_iv {
        if prop_start + 1 >= hdr_data.len() { return None; }
        let second = hdr_data[prop_start + 1];
        let ss = ((second >> 4) + 1) as usize;
        let is = ((second & 0x0F) + 1) as usize;
        let mut off = prop_start + 2;
        let salt_raw = if has_salt {
            let s = crate::common::safe_take(hdr_data, off, ss)?; off += ss; s
        } else { &[] };
        let iv_raw   = if has_iv {
            crate::common::safe_take(hdr_data, off, is)?
        } else { &[] };
        (to_hex(salt_raw), to_hex(iv_raw), ss, is)
    } else {
        ("0".to_string(), "0".to_string(), 0, 0)
    };

    Some(vec![format!(
        "$7z$0${}${}${}${}${}${}${}${}",
        num_cycles_power,
        salt_size, if salt_size > 0 { &salt_hex } else { "0" },
        iv_size,   if iv_size > 0   { &iv_hex   } else { "0" },
        next_hdr_crc,
        next_hdr_size,
        to_hex(hdr_data)
    )])
}
