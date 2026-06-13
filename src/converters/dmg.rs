use crate::common::{to_hex, u32_be};

pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    // Locate "encrcdsa" or "cdsaencr" magic
    let magic1 = b"encrcdsa";
    let magic2 = b"cdsaencr";
    let pos = data.windows(8).position(|w| w == magic1 || w == magic2)?;
    let hdr = &data[pos..];
    parse_header(hdr).map(|h| vec![h])
}

fn parse_header(hdr: &[u8]) -> Option<String> {
    if hdr.len() < 16 { return None; }
    let version = u32_be(hdr, 8);
    match version {
        1 => parse_v1(hdr),
        2 => parse_v2(hdr),
        _ => None,
    }
}

fn parse_v1(hdr: &[u8]) -> Option<String> {
    let mut off = 12;
    let iv_size = u32_be(hdr, off) as usize; off += 4;
    if off + iv_size + 4 > hdr.len() { return None; }
    let iv = to_hex(&hdr[off..off + iv_size]); off += iv_size;
    let enc_key_size = u32_be(hdr, off) as usize; off += 4;
    if off + enc_key_size + 4 > hdr.len() { return None; }
    let enc_key = to_hex(&hdr[off..off + enc_key_size]); off += enc_key_size;
    let salt_size = u32_be(hdr, off) as usize; off += 4;
    if off + salt_size + 4 > hdr.len() { return None; }
    let kdf_salt = to_hex(&hdr[off..off + salt_size]); off += salt_size;
    let iterations = u32_be(hdr, off);
    Some(format!(
        "$dmg$1*{}*{}*{}*{}*{}*{}*{}",
        iv_size, iv, enc_key_size, enc_key, salt_size, kdf_salt, iterations
    ))
}

fn parse_v2(hdr: &[u8]) -> Option<String> {
    let mut off = 12;
    let enc_iv_size = u32_be(hdr, off) as usize; off += 4;
    if off + enc_iv_size + 4 > hdr.len() { return None; }
    let enc_iv = to_hex(&hdr[off..off + enc_iv_size]); off += enc_iv_size;
    let enc_bits = u32_be(hdr, off); off += 4;
    let blob_size = u32_be(hdr, off) as usize; off += 4;
    if off + blob_size + 4 > hdr.len() { return None; }
    let blob = to_hex(&hdr[off..off + blob_size]); off += blob_size;
    off += 4; // kdf_algo
    let salt_size = u32_be(hdr, off) as usize; off += 4;
    if off + salt_size + 4 > hdr.len() { return None; }
    let kdf_salt = to_hex(&hdr[off..off + salt_size]); off += salt_size;
    let iterations = u32_be(hdr, off);
    Some(format!(
        "$dmg$2*{}*{}*{}*{}*{}*{}*{}*{}",
        enc_iv_size, enc_iv, enc_bits, blob_size, blob, salt_size, kdf_salt, iterations
    ))
}
