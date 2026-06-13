use crate::common::{to_hex, u16_le, u32_le};

const OLE2_SIG: &[u8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1";

pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    if !data.starts_with(OLE2_SIG) { return None; }
    // Locate EncryptionInfo stream in OLE2 structure — simplified scan
    let enc_info_key = b"E\x00n\x00c\x00r\x00y\x00p\x00t\x00i\x00o\x00n\x00I\x00n\x00f\x00o\x00";
    let pos = data.windows(enc_info_key.len()).position(|w| w == enc_info_key);
    if let Some(p) = pos {
        // stream data follows the directory entry; locate via FAT
        // Simplified: scan for vMajor/vMinor after position
        return parse_enc_info_from_scan(data, p);
    }
    // Try Excel 97-2003 FilePass record
    parse_excel_filepass(data)
}

fn parse_enc_info_from_scan(data: &[u8], dir_pos: usize) -> Option<Vec<String>> {
    // Search for actual EncryptionInfo stream data bytes after FAT resolution
    // For simplicity: scan for ECMA-376 Agile marker (XML) or standard header
    let agile_marker = b"http://schemas.microsoft.com/office/2006/keyEncryptor/password";
    if let Some(pos) = data.windows(agile_marker.len()).position(|w| w == agile_marker) {
        return parse_agile(data, pos);
    }
    // Standard encryption: look for vMajor=3 or 4 near EncryptionInfo
    // Scan forward from dir_pos
    let scan = &data[dir_pos..];
    for i in 0..scan.len().saturating_sub(100) {
        let vmajor = u16_le(scan, i);
        let vminor = u16_le(scan, i + 2);
        if (vmajor == 3 || vmajor == 4) && (vminor == 2 || vminor == 3 || vminor == 4) {
            if let Some(h) = parse_standard(scan, i, vmajor) {
                return Some(vec![h]);
            }
        }
    }
    None
}

fn parse_standard(data: &[u8], base: usize, vmajor: u16) -> Option<String> {
    // EncryptionHeader at base+8; EncryptionVerifier after header
    let header_size = u32_le(data, base + 8) as usize;
    let hdr_off     = base + 12;
    if hdr_off + header_size + 52 > data.len() { return None; }
    // flags at hdr_off+0, alg_id at hdr_off+4, key_size at hdr_off+12
    let key_size = u32_le(data, hdr_off + 12) as usize;
    let ver_off  = hdr_off + header_size;
    let salt_size   = u32_le(data, ver_off) as usize;
    if ver_off + 4 + 16 + 16 + 4 + 32 > data.len() { return None; }
    let salt            = to_hex(&data[ver_off + 4..ver_off + 4 + 16]);
    let enc_verifier    = to_hex(&data[ver_off + 20..ver_off + 36]);
    let vh_size = u32_le(data, ver_off + 36) as usize;
    let enc_verifier_hash = to_hex(&data[ver_off + 40..ver_off + 40 + 32]);
    let year = if vmajor >= 4 { 2013 } else { 2010 };
    Some(format!(
        "$office$*{}*{}*{}*{}*{}*{}*{}",
        year, vh_size, key_size, salt_size, salt, enc_verifier, enc_verifier_hash
    ))
}

fn parse_agile(data: &[u8], pos: usize) -> Option<Vec<String>> {
    let xml_region = std::str::from_utf8(&data[pos.saturating_sub(4096)..pos + 4096.min(data.len() - pos)]).ok()?;
    macro_rules! attr {
        ($name:expr) => {
            extract_xml_attr(xml_region, $name)
        };
    }
    let spin_count  = attr!("spinCount")?.parse::<u32>().ok()?;
    let key_bits    = attr!("keyBits")?.parse::<u32>().ok()?;
    let salt_size   = attr!("saltSize")?.parse::<u32>().ok()?;
    let salt_b64    = attr!("saltValue")?;
    let enc_vi_b64  = attr!("encryptedVerifierHashInput")?;
    let enc_vh_b64  = attr!("encryptedVerifierHashValue")?;
    let enc_key_b64 = attr!("encryptedKeyValue")?;

    let salt        = hex_from_b64(&salt_b64)?;
    let enc_vi      = hex_from_b64(&enc_vi_b64)?;
    let enc_vh      = hex_from_b64(&enc_vh_b64)?;
    let enc_key_val = hex_from_b64(&enc_key_b64)?;
    let hash_size = 32u32; // SHA-256 default

    Some(vec![format!(
        "$office$*2013*{}*{}*{}*{}*{}*{}*{}*{}",
        hash_size, key_bits, salt_size, salt, enc_vi, enc_vh, enc_key_val, spin_count
    )])
}

fn parse_excel_filepass(data: &[u8]) -> Option<Vec<String>> {
    // Scan for FilePass opcode 0x002F
    let opcode = b"\x2f\x00";
    let pos = data.windows(2).position(|w| w == opcode)?;
    let rec = data.get(pos + 4..)?; // skip opcode + size
    let major = u16_le(rec, 0);
    // RC4 (major=1) — needs salt(16) + verifier(16) + verifier-hash(20) at offset 6.
    if major == 1 {
        if rec.len() < 58 { return None; }
        let salt            = to_hex(&rec[6..22]);
        let enc_verifier    = to_hex(&rec[22..38]);
        let verifier_hash   = to_hex(&rec[38..58]);
        return Some(vec![format!(
            "$oldoffice$1*{}*{}*{}",
            salt, enc_verifier, &verifier_hash[..32]
        )]);
    }
    None
}

fn extract_xml_attr(xml: &str, name: &str) -> Option<String> {
    let pattern = format!("{}=\"", name);
    let start = xml.find(&pattern)? + pattern.len();
    let end = xml[start..].find('"')? + start;
    Some(xml[start..end].to_string())
}

fn hex_from_b64(b64: &str) -> Option<String> {
    let raw = crate::common::b64_decode(b64.trim()).ok()?;
    Some(to_hex(&raw))
}
