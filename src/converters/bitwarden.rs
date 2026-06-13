use crate::common::{b64_decode, to_hex};

pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;
    // Android XML format
    if let Some(h) = parse_xml(text) {
        return Some(vec![h]);
    }
    // JSON storage.js
    if let Ok(j) = serde_json::from_str::<serde_json::Value>(text) {
        return parse_json(&j);
    }
    None
}

fn parse_json(j: &serde_json::Value) -> Option<Vec<String>> {
    let email = j.get("userEmail")?.as_str()?.to_lowercase();
    let enc_key = j.get("encKey")?.as_str()?;
    decode_enc_key(&email, enc_key).map(|h| vec![h])
}

fn parse_xml(text: &str) -> Option<String> {
    // Quick regex scan for Android SharedPreferences XML
    let email_re = regex::Regex::new(r#"name="email"[^>]*>([^<]+)<"#).ok()?;
    let key_re   = regex::Regex::new(r#"name="encKey"[^>]*>([^<]+)<"#).ok()?;
    let email = email_re.captures(text)?.get(1)?.as_str().trim().to_lowercase();
    let enc_key = key_re.captures(text)?.get(1)?.as_str().trim();
    decode_enc_key(&email, enc_key)
}

fn decode_enc_key(email: &str, enc_key: &str) -> Option<String> {
    // Format: "0.<b64_iv>|<b64_blob>"
    let stripped = enc_key.strip_prefix("0.").unwrap_or(enc_key);
    let parts: Vec<&str> = stripped.splitn(2, '|').collect();
    if parts.len() < 2 { return None; }
    let iv = b64_decode(parts[0]).ok()?;
    let blob = b64_decode(parts[1]).ok()?;
    Some(format!(
        "$bitwarden$0*5000*{}*{}*{}",
        email,
        to_hex(&iv),
        to_hex(&blob)
    ))
}
