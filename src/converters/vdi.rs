use crate::common::{to_hex, u32_le};

pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    // VDI magic: "<<< " text pre-header or 0x7f10dabe signature
    let crypt_marker = b"CRYPT";
    if let Some(pos) = data.windows(5).position(|w| w == crypt_marker) {
        let off = pos + 5;
        if off + 44 > data.len() { return None; }
        let cipher_id  = u32_le(data, off);
        let key_len    = u32_le(data, off + 4);
        let iterations = u32_le(data, off + 8);
        let salt       = to_hex(&data[off + 12..off + 44]);
        let enc_end    = (off + 44 + 32).min(data.len());
        let enc_data   = to_hex(&data[off + 44..enc_end]);
        return Some(vec![format!(
            "$vbox${}${}${}${}${}",
            cipher_id, key_len, iterations, salt, enc_data
        )]);
    }
    // Fallback
    if data.len() >= 64 {
        return Some(vec![format!(
            "$vbox$0$0$0${}${}",
            to_hex(&data[0..32]),
            to_hex(&data[32..64])
        )]);
    }
    None
}
