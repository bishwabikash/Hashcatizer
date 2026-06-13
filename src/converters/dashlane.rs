use crate::common::to_hex;
pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    if data.len() >= 64 {
        let salt = to_hex(&data[..32]);
        let enc  = to_hex(&data[32..64]);
        return Some(vec![format!("$dashlane$1*{}*{}", salt, enc)]);
    }
    let j: serde_json::Value = serde_json::from_slice(data).ok()?;
    let salt = j.get("salt")?.as_str()?;
    let content = j.get("content")?.as_str()?;
    // Truncate on a char boundary so multibyte UTF-8 content can't split-panic.
    let mut end = content.len().min(64);
    while end > 0 && !content.is_char_boundary(end) { end -= 1; }
    Some(vec![format!("$dashlane$1*{}*{}", salt, &content[..end])])
}
