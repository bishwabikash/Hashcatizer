use crate::common::{to_hex, u32_be};

pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    if data.len() < 592 || &data[0..6] != b"LUKS\xba\xbe" {
        return None;
    }
    // Find first active key slot (offset 208, 8 slots × 48 bytes each)
    const ACTIVE: u32 = 0x00AC71F3;
    let mk_digest   = to_hex(&data[168..188]);
    let mk_salt     = to_hex(&data[112..144]);
    let _mk_iters   = u32_be(data, 144);

    let mut hashes = Vec::new();
    for i in 0..8usize {
        let slot_off = 208 + i * 48;
        if slot_off + 48 > data.len() { break; }
        let state = u32_be(data, slot_off);
        if state != ACTIVE { continue; }
        let iters   = u32_be(data, slot_off + 4);
        let salt    = to_hex(&data[slot_off + 8..slot_off + 40]);
        let stripes = u32_be(data, slot_off + 44);
        hashes.push(format!(
            "$luks$1*{}*{}*{}*{}*{}",
            iters, salt, stripes, mk_digest, mk_salt
        ));
    }
    if hashes.is_empty() { None } else { Some(hashes) }
}
