use crate::common::to_hex;

// Lotus Notes / Domino ID files -> john's lotus5 format (no hashcat mode; the
// 8600/8700/9100 modes take Domino *account* hashes, not ID files).
//
// The user blob is length-prefixed at offset 0xD6, and john emits it as
// uppercase hex with no marker prefix.

const BLOB_LEN_OFFSET: usize = 0xD6;

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let len_bytes = data.get(BLOB_LEN_OFFSET..BLOB_LEN_OFFSET + 2)?;
    let blob_size = u16::from_le_bytes(len_bytes.try_into().ok()?) as usize;

    // A plausible user blob is a few hundred bytes; anything else means the
    // offset landed on unrelated data.
    if !(16..=4096).contains(&blob_size) {
        return None;
    }
    let start = BLOB_LEN_OFFSET + 2;
    let blob = data.get(start..start.checked_add(blob_size)?)?;

    Some(vec![to_hex(blob).to_uppercase()])
}
