use crate::common::to_hex;

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    // PEM encrypted private key: parse DEK-Info header
    let text = std::str::from_utf8(data).ok()?;
    if !text.contains("ENCRYPTED") { return None; }

    let cipher = if text.contains("AES-256") { "AES-256-CBC" }
                 else if text.contains("AES-128") { "AES-128-CBC" }
                 else if text.contains("DES-EDE3") { "DES-EDE3-CBC" }
                 else { "AES-256-CBC" };

    // Extract IV from DEK-Info
    let mut iv = String::new();
    for line in text.lines() {
        if line.starts_with("DEK-Info:") {
            let parts: Vec<&str> = line.splitn(2, ',').collect();
            if parts.len() == 2 { iv = parts[1].trim().to_string(); }
            break;
        }
    }

    // Extract base64 body
    let mut b64 = String::new();
    let mut in_body = false;
    for line in text.lines() {
        if line.starts_with("-----BEGIN") { in_body = true; continue; }
        if line.starts_with("-----END")   { break; }
        if in_body && !line.starts_with("Proc-Type") && !line.starts_with("DEK-Info") {
            b64.push_str(line.trim());
        }
    }
    if b64.is_empty() { return None; }
    let body_bytes = base64::engine::general_purpose::STANDARD.decode(&b64).ok()?;

    Some(vec![format!(
        "$PEM$1*{}*{}*{}*{}",
        cipher, iv, body_bytes.len(), to_hex(&body_bytes)
    )])
}

use base64::Engine as _;
