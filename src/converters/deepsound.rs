use crate::common::to_hex;
const DSCF: &[u8] = b"DSCF";
pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let pos = data.windows(4).position(|w| w == DSCF)?;
    let end = (pos + 256).min(data.len());
    Some(vec![format!("$deepsound${}", to_hex(&data[pos..end]))])
}
