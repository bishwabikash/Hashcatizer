use crate::common::to_hex;

const DELIM: &[u8] = b"\x07\x65\x92\x1A\x2A\x07\x74\x53\x47\x52\x07\x33\x61\x71\x93\x00";
const PBA_SALT:  &[u8] = b"\x80\x7a\x05\x00";
const PBA_ITER:  &[u8] = b"\x80\x7b\x02\x00";
const HASH_FUNC: &[u8] = b"\x80\x78\x02\x00";
const PBA_CHK:   &[u8] = b"\x80\x79\x05\x00";

pub fn convert(data: &[u8], filename: &str) -> Option<Vec<String>> {
    let pos = data.windows(DELIM.len()).position(|w| w == DELIM)?;
    let off = pos + DELIM.len();
    // Need version(2) + global_iv(16) = 18 bytes after the delimiter.
    if off + 18 > data.len() { return None; }

    let ver = u16::from_le_bytes(data[off..off + 2].try_into().ok()?);
    let global_iv = to_hex(&data[off + 2..off + 18]);
    let ct_end = find_next_delim(data, off + 18).unwrap_or(data.len());
    let ciphertext = &data[off + 18..ct_end];

    // Without AES decrypt (no pycryptodome equivalent for no-key case), output raw
    let ct_hex = to_hex(&ciphertext[..ciphertext.len().min(256)]);
    let basename = std::path::Path::new(filename)
        .file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();

    // Search plaintext for TLV tags in ciphertext region (best-effort without decryption)
    let pba_salt  = find_tlv(ciphertext, PBA_SALT);
    let iter_raw  = find_tlv(ciphertext, PBA_ITER);
    let hash_raw  = find_tlv(ciphertext, HASH_FUNC);
    let pba_chk   = find_tlv(ciphertext, PBA_CHK);

    if let (Some(salt), Some(chk)) = (pba_salt, pba_chk) {
        let hash_func = hash_raw.map(|v| u16_from_be(v) as u32).unwrap_or(0);
        let iters     = iter_raw.map(|v| u16_from_be(v) as u64).unwrap_or(0);
        Some(vec![format!(
            "unnamed:$zed${}${}${}${}${}:::{}",
            ver, hash_func, iters,
            to_hex(salt), to_hex(chk), basename
        )])
    } else {
        // Fallback: raw ciphertext
        Some(vec![format!(
            "unnamed:$zed${}$raw${}${}:::{}",
            ver, global_iv, ct_hex, basename
        )])
    }
}

fn find_next_delim(data: &[u8], start: usize) -> Option<usize> {
    data[start..].windows(DELIM.len()).position(|w| w == DELIM).map(|p| p + start)
}

fn find_tlv<'a>(data: &'a [u8], tag: &[u8]) -> Option<&'a [u8]> {
    let pos = data.windows(tag.len()).position(|w| w == tag)? + tag.len();
    if pos + 2 > data.len() { return None; }
    let len = u16::from_le_bytes(data[pos..pos + 2].try_into().ok()?) as usize;
    if pos + 2 + len > data.len() { return None; }
    Some(&data[pos + 2..pos + 2 + len])
}

fn u16_from_be(v: &[u8]) -> u16 {
    if v.len() >= 2 { u16::from_be_bytes([v[0], v[1]]) } else { 0 }
}
