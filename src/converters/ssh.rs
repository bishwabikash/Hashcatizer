use crate::common::to_hex;

const AUTH_MAGIC: &[u8] = b"openssh-key-v1\x00";

pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;

    // OpenSSH new format
    if text.contains("BEGIN OPENSSH PRIVATE KEY") {
        return parse_openssh(text);
    }
    // PEM legacy format
    parse_pem_legacy(text)
}

fn parse_pem_legacy(text: &str) -> Option<Vec<String>> {
    // Detect cipher from DEK-Info header
    let dek_re  = regex::Regex::new(r"DEK-Info:\s*([A-Z0-9-]+),([0-9a-fA-F]+)").ok()?;
    let caps    = dek_re.captures(text)?;
    let cipher  = &caps[1];
    let iv_hex  = caps[2].to_lowercase();

    // Collect base64 body
    let body_re = regex::Regex::new(r"-----BEGIN[^-]+-----\r?\n([\s\S]+?)-----END").ok()?;
    let body_caps = body_re.captures(text)?;
    let b64_raw: String = body_caps[1].lines()
        .filter(|l| !l.starts_with("Proc-Type") && !l.starts_with("DEK-Info"))
        .collect::<Vec<_>>().join("");
    let der = crate::common::b64_decode(&b64_raw).ok()?;

    let cipher_id = match cipher {
        "DES-EDE3-CBC"  => 0,
        "AES-128-CBC"   => 1,
        "AES-192-CBC"   => 4,
        "AES-256-CBC"   => 5,
        "AES-256-CTR"   => 5,
        _ => return None,
    };
    let iv_bytes    = hex::decode(&iv_hex).ok()?;
    let data_hex    = to_hex(&der[..der.len().min(256)]);
    Some(vec![format!(
        "$sshng${}${}${}${}${}",
        cipher_id, iv_bytes.len(), iv_hex, data_hex.len() / 2, data_hex
    )])
}

fn parse_openssh(text: &str) -> Option<Vec<String>> {
    let body_re = regex::Regex::new(r"-----BEGIN OPENSSH PRIVATE KEY-----\r?\n([\s\S]+?)-----END").ok()?;
    let caps    = body_re.captures(text)?;
    let b64_body: String = caps[1].split_whitespace().collect();
    let raw = crate::common::b64_decode(&b64_body).ok()?;

    if !raw.starts_with(AUTH_MAGIC) { return None; }
    let mut off = AUTH_MAGIC.len();
    // cipher name
    let (cipher_name, off2) = read_len_str(&raw, off)?;
    off = off2;
    // kdf name
    let (kdf_name, off3) = read_len_str(&raw, off)?;
    off = off3;
    // kdf options
    let (kdf_len, off4) = read_u32_be(&raw, off)?;
    off = off4;

    let (cipher_id, salt, rounds) = if kdf_name == "bcrypt" && kdf_len >= 20 {
        let (salt_raw, _off5) = read_len_bytes(&raw, off)?;
        let (rnd, _off6)     = read_u32_be(&raw, off + 4 + salt_raw.len())?;
        let cid = match cipher_name.as_str() {
            "aes256-cbc" => 2,
            "aes256-ctr" => 6,
            _ => 2,
        };
        (cid, salt_raw.to_vec(), rnd)
    } else if kdf_name == "none" {
        return None; // not encrypted
    } else {
        return None;
    };
    off += kdf_len as usize;

    // Skip num_keys + public key blob
    let (num_keys, off5) = read_u32_be(&raw, off)?;
    off = off5;
    for _ in 0..num_keys {
        let (pk_len, o) = read_u32_be(&raw, off)?;
        off = o + pk_len as usize;
    }
    // Encrypted blob
    let enc_data = &raw[off..];
    let data_hex = to_hex(&enc_data[..enc_data.len().min(256)]);
    let salt_hex = to_hex(&salt);
    Some(vec![format!(
        "$sshng${}${}${}${}${}${}${}",
        cipher_id, salt.len(), salt_hex,
        data_hex.len() / 2, data_hex,
        rounds, off
    )])
}

fn read_u32_be(data: &[u8], off: usize) -> Option<(u32, usize)> {
    if off + 4 > data.len() { return None; }
    Some((u32::from_be_bytes(data[off..off+4].try_into().ok()?), off + 4))
}
fn read_len_str(data: &[u8], off: usize) -> Option<(String, usize)> {
    let (len, start) = read_u32_be(data, off)?;
    let end = start + len as usize;
    if end > data.len() { return None; }
    Some((String::from_utf8_lossy(&data[start..end]).to_string(), end))
}
fn read_len_bytes(data: &[u8], off: usize) -> Option<(&[u8], usize)> {
    let (len, start) = read_u32_be(data, off)?;
    let end = start + len as usize;
    if end > data.len() { return None; }
    Some((&data[start..end], end))
}
