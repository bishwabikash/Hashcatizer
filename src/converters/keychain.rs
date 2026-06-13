use crate::common::to_hex;
const KYCH: &[u8] = b"kych";
pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let pos = data.windows(4).position(|w| w == KYCH).unwrap_or(0);
    let base = pos;
    if base + 96 > data.len() { return None; }
    let salt    = to_hex(&data[base + 44..base + 64]);
    let iv      = to_hex(&data[base + 64..base + 72]);
    let wrapped = to_hex(&data[base + 72..base + 96]);
    Some(vec![format!("$keychain$*{}*{}*{}", salt, iv, wrapped)])
}
