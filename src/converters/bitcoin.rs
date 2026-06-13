use crate::common::{to_hex, u32_le, read_compact_size};

pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    // Scan for "mkey" key in BDB wallet.dat
    let mkey = b"mkey";
    let pos = data.windows(mkey.len()).position(|w| w == mkey)?;
    // value starts after the key record; skip to value bytes
    let val_start = pos + mkey.len();
    if val_start + 4 > data.len() {
        return None;
    }
    // Skip nID (4 bytes LE)
    let mut off = val_start;
    off += 4; // nID
    let (enc_key_len, off2) = read_compact_size(data, off)?;
    off = off2;
    let enc_key_end = off + enc_key_len as usize;
    if enc_key_end > data.len() { return None; }
    let enc_key = &data[off..enc_key_end];
    off = enc_key_end;

    let (salt_len, off3) = read_compact_size(data, off)?;
    off = off3;
    let salt_end = off + salt_len as usize;
    if salt_end + 8 > data.len() { return None; }
    let salt = &data[off..salt_end];
    off = salt_end;

    let _deriv_method = u32_le(data, off);
    off += 4;
    let rounds = u32_le(data, off);

    // hashcat uses last 32 bytes of enc_key
    let cry_master = if enc_key.len() > 32 { &enc_key[enc_key.len() - 32..] } else { enc_key };
    let cm_hex = to_hex(cry_master);
    let salt_hex = to_hex(salt);
    Some(vec![format!(
        "$bitcoin${}${}${}${}${}$2$00$2$00",
        cm_hex.len() / 2,
        cm_hex,
        salt_hex.len() / 2,
        salt_hex,
        rounds
    )])
}
