use crate::common::to_hex;

pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    // Format 1: LE uint32 == 32 at offset 0
    if data.len() >= 40 && u32::from_le_bytes(data[0..4].try_into().ok()?) == 32 {
        let salt    = to_hex(&data[4..36]);
        let key_sz  = u32::from_le_bytes(data[36..40].try_into().ok()?);
        let enc_end = (40 + key_sz as usize).min(data.len());
        let enc_key = to_hex(&data[40..enc_end]);
        return Some(vec![format!("$telegram$1*100000*{}*{}", salt, enc_key)]);
    }
    // Format 2: raw salt at [0:32]
    if data.len() >= 32 {
        let salt    = to_hex(&data[0..32]);
        let enc_end = data.len().min(32 + 256);
        let enc_key = to_hex(&data[32..enc_end]);
        return Some(vec![format!("$telegram$1*100000*{}*{}", salt, enc_key)]);
    }
    None
}
