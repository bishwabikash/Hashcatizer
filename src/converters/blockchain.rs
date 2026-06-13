use crate::common::b64_decode;

pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;
    let j: serde_json::Value = serde_json::from_str(text).ok()?;
    if let (Some(payload), Some(iters)) = (
        j.get("payload").and_then(|v| v.as_str()),
        j.get("pbkdf2_iterations").and_then(|v| v.as_u64()),
    ) {
        let raw = b64_decode(payload).ok()?;
        return Some(vec![format!(
            "$blockchain$v2${}${}${}",
            iters,
            raw.len(),
            payload.trim()
        )]);
    }
    // V1 — raw base64 payload only
    if let Some(payload) = j.get("payload").and_then(|v| v.as_str()) {
        let raw = b64_decode(payload).ok()?;
        let first32 = &raw[..raw.len().min(32)];
        let enc = crate::common::b64_encode(first32);
        return Some(vec![format!("$blockchain${}${}", raw.len(), enc)]);
    }
    None
}
