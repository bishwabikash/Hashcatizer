use crate::common::to_hex;
pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    // ZIP file containing EncryptedDocument
    if !data.starts_with(b"PK\x03\x04") { return None; }
    let marker = b"EncryptedDocument";
    let pos = data.windows(marker.len()).position(|w| w == marker)?;
    let end = (pos + 256).min(data.len());
    Some(vec![format!("$iwork${}", to_hex(&data[pos..end]))])
}
