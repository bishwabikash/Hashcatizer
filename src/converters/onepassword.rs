use crate::common::{to_hex, b64_decode};
use std::path::Path;

pub fn convert(path: &Path) -> Option<Vec<String>> {
    // cloudkeychain / OPVault
    for candidate in &["default/profile.js", "profile.js"] {
        let p = if path.is_dir() { path.join(candidate) } else { path.to_path_buf() };
        if p.exists() {
            let data = std::fs::read(&p).ok()?;
            if let Some(h) = parse_cloudkeychain(&data) {
                return Some(vec![h]);
            }
        }
    }
    // agilekeychain
    for candidate in &["data/default/encryptionKeys.js", "encryptionKeys.js"] {
        let p = if path.is_dir() { path.join(candidate) } else { path.to_path_buf() };
        if p.exists() {
            let data = std::fs::read(&p).ok()?;
            if let Some(h) = parse_agilekeychain(&data) {
                return Some(vec![h]);
            }
        }
    }
    // Single file fallback
    let data = std::fs::read(path).ok()?;
    parse_cloudkeychain(&data)
        .or_else(|| parse_agilekeychain(&data))
        .map(|h| vec![h])
}

fn parse_cloudkeychain(data: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(data).ok()?;
    // Strip JS wrapper "var profile=..."
    let json_start = text.find('{')? ;
    let json_end   = text.rfind('}')? + 1;
    let j: serde_json::Value = serde_json::from_str(&text[json_start..json_end]).ok()?;
    let iters      = j.get("iterations")?.as_u64()?;
    let salt_b64   = j.get("salt")?.as_str()?;
    let mk_b64     = j.get("masterKey")?.as_str()?;
    let ok_b64     = j.get("overviewKey")?.as_str()?;
    let salt       = b64_decode(salt_b64).ok()?;
    let mk         = b64_decode(mk_b64).ok()?;
    let ok         = b64_decode(ok_b64).ok()?;
    Some(format!(
        "$cloudkeychain${}${}${}${}${}${}",
        salt.len(), to_hex(&salt), iters, mk.len(), to_hex(&mk), to_hex(&ok)
    ))
}

fn parse_agilekeychain(data: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(data).ok()?;
    let json_start = text.find('[').or_else(|| text.find('{'))?;
    let j: serde_json::Value = serde_json::from_str(&text[json_start..]).ok()?;
    let list = j.as_array().or_else(|| j.get("list")?.as_array())?;
    for entry in list {
        if entry.get("level").and_then(|v| v.as_str()) != Some("SL5") { continue; }
        let iters     = entry.get("iterations")?.as_u64()?;
        let data_b64  = entry.get("data")?.as_str()?;
        let valid_b64 = entry.get("validation")?.as_str()?;
        let ct_raw    = b64_decode(data_b64).ok()?;
        let valid_raw = b64_decode(valid_b64).ok()?;
        // "Salted__" only guarantees 8 bytes; the OpenSSL salt header is 16.
        let (ct, salt) = if ct_raw.starts_with(b"Salted__") && ct_raw.len() >= 16 {
            (&ct_raw[16..], &ct_raw[8..16])
        } else {
            (ct_raw.as_slice(), &ct_raw[..0])
        };
        return Some(format!(
            "$agilekeychain${}*{}*{}*{}*{}*{}*{}",
            salt.len(), to_hex(salt), iters,
            ct.len(), to_hex(ct),
            valid_raw.len(), to_hex(&valid_raw)
        ));
    }
    None
}
