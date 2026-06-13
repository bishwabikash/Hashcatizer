use crate::common::to_hex;
use crate::common::u32_le;
pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    if data.len() < 393 { return None; }
    let magic = u32_le(data, 0);
    if magic != 0x58504348 {
        eprintln!("[warn] Non-standard hccapx header");
    }
    Some(vec![to_hex(&data[..393])])
}
