use crate::common::{to_hex, u32_le, u16_le};

const MAIN_MAGIC: u32 = 0x50475064; // "PGPd"
const MAIN_TYPE:  u32 = 0x4E49414D; // "NAIM"
const USER_TYPE:  u32 = 0x52455355; // "RESU"

pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    let mut algorithm: u32 = 0;
    let mut salt = Vec::new();
    let mut hashes = Vec::new();

    // Scan for PGPDISK_MAGIC
    let mut pos = 0;
    while pos + 4 <= data.len() {
        let magic = u32_le(data, pos);
        if magic != MAIN_MAGIC { pos += 4; continue; }
        // Read record type
        if pos + 60 > data.len() { break; }
        let rtype = u32_le(data, pos + 4);
        match rtype {
            _ if rtype == MAIN_TYPE => {
                algorithm = u32_le(data, pos + 56);
                match crate::common::safe_take(data, pos + 60, 16) {
                    Some(s) => salt = s.to_vec(),
                    None => break,
                }
            }
            _ if rtype == USER_TYPE => {
                if salt.is_empty() { pos += 4; continue; }
                // Username: [60..188] null-terminated
                let name_bytes = match crate::common::safe_take(data, pos + 60, 128) {
                    Some(b) => b,
                    None => { pos += 4; continue; }
                };
                let name = null_term_str(name_bytes);
                let pki = pos + 188;
                if pki + 146 > data.len() { pos += 4; continue; }
                let enc_key     = to_hex(&data[pki..pki + 128]);
                let check_bytes = to_hex(&data[pki + 128..pki + 144]);
                let hash_reps   = u16_le(data, pki + 144);
                hashes.push(format!(
                    "{}:$pgpdisk$0*{}*{}*{}*{}*{}",
                    name, algorithm, hash_reps,
                    to_hex(&salt), enc_key, check_bytes
                ));
            }
            _ => {}
        }
        pos += 4;
    }
    if hashes.is_empty() { None } else { Some(hashes) }
}

fn null_term_str(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).to_string()
}
