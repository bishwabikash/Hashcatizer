use crate::common::{to_hex, u32_be};
const GNOME_MAGIC: &[u8] = b"GnomeKeyring\n\r\x00\n";
pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let pos = data.windows(GNOME_MAGIC.len()).position(|w| w == GNOME_MAGIC)?;
    let off = pos + GNOME_MAGIC.len();
    if off + 52 > data.len() { return None; }
    let crypto   = data[off + 2];
    let iter_off = off + 20;
    let iters    = u32_be(data, iter_off);
    let salt     = to_hex(&data[iter_off + 4..iter_off + 12]);
    let enc_end  = (iter_off + 12 + 48).min(data.len());
    let enc_data = to_hex(&data[iter_off + 12..enc_end]);
    Some(vec![format!("$keyring${}*{}*{}*{}", iters, salt, crypto, enc_data)])
}
