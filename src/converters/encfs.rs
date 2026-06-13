use crate::common::{to_hex, b64_decode};

pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;
    // Parse XML tags manually (quick-xml or by regex for simplicity)
    macro_rules! tag {
        ($name:expr) => {
            extract_tag(text, $name)
        };
    }
    let key_size: usize    = tag!("keySize")?.parse().ok()?;
    let iterations: usize  = tag!("kdfIterations")?.parse().ok()?;
    let salt_len: usize    = tag!("saltLen")?.parse().ok()?;
    let salt_b64           = tag!("saltData")?;
    let enc_key_b64        = tag!("encodedKeyData")?;
    let enc_key_len: usize = tag!("encodedKeySize")?.parse().ok()?;

    let salt    = b64_decode(&salt_b64).ok()?;
    let enc_key = b64_decode(&enc_key_b64).ok()?;

    Some(vec![format!(
        "$encfs${}*{}*{}*{}*{}*{}",
        key_size, iterations, salt_len, to_hex(&salt),
        enc_key_len, to_hex(&enc_key)
    )])
}

fn extract_tag(text: &str, tag: &str) -> Option<String> {
    let open  = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = text.find(&open)? + open.len();
    let end   = text[start..].find(&close)? + start;
    Some(text[start..end].trim().to_string())
}
