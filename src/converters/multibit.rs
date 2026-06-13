use crate::common::to_hex;

pub fn convert(data: &[u8], path: &str) -> Option<Vec<String>> {
    let ext = std::path::Path::new(path)
        .extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();

    if ext == "key" {
        // multibit classic key: $multibit$1*<salt>*<enc>
        if data.len() < 48 { return None; }
        let salt = to_hex(&data[8..16]);
        let enc  = to_hex(&data[16..48]);
        Some(vec![format!("$multibit$1*{}*{}", salt, enc)])
    } else if ext == "wallet" || ext == "protobuf" {
        // multibit HD wallet: $multibit$2*<hex>
        if data.is_empty() { return None; }
        let limit = data.len().min(256);
        Some(vec![format!("$multibit$2*{}", to_hex(&data[..limit]))])
    } else {
        None
    }
}
