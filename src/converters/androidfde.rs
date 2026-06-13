use crate::common::{to_hex, u32_le};

const MAGIC: &[u8] = b"\xd0\xb5\xb1\xc4";

pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    let pos = data.windows(4).position(|w| w == MAGIC)
        .or_else(|| {
            // try last 16 KB
            let tail_start = data.len().saturating_sub(16384);
            data[tail_start..].windows(4).position(|w| w == MAGIC).map(|p| p + tail_start)
        })?;
    let ftr = &data[pos..];
    if ftr.len() < 132 { return None; }
    let keysize  = u32_le(ftr, 16) as usize;
    let mk_end   = (56 + keysize).min(ftr.len());
    let master_key = to_hex(&ftr[56..mk_end]);
    let salt       = to_hex(&ftr[104..104 + 16]);
    let n_factor   = u32_le(ftr, 120);
    let r_factor   = u32_le(ftr, 124);
    let p_factor   = u32_le(ftr, 128);
    Some(vec![format!(
        "$fde${}${}${}${}${}${}${}",
        keysize, master_key, 16, salt, n_factor, r_factor, p_factor
    )])
}
