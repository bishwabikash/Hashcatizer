use crate::common::{to_hex, u16_le, u32_le, utf16le_decode};

pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    // Detect PCAP magic
    let is_pcap = data.starts_with(b"\xa1\xb2\xc3\xd4")
        || data.starts_with(b"\xd4\xc3\xb2\xa1")
        || data.starts_with(b"\x0a\x0d\x0d\x0a");
    if !is_pcap { return None; }

    let mut hashes = Vec::new();
    // Scan for NTLMSSP\0 authenticate messages
    let ntlm_marker = b"NTLMSSP\x00\x03\x00\x00\x00";
    let mut pos = 0;
    while let Some(offset) = data[pos..].windows(ntlm_marker.len()).position(|w| w == ntlm_marker) {
        let abs = pos + offset;
        if let Some(hash) = parse_ntlm(data, abs) {
            hashes.push(hash);
        }
        pos = abs + ntlm_marker.len();
    }
    if hashes.is_empty() { None } else { Some(hashes) }
}

fn parse_ntlm(data: &[u8], off: usize) -> Option<String> {
    if off + 72 > data.len() { return None; }
    let msg  = &data[off..];
    let lm_len  = u16_le(msg, 12) as usize;
    let lm_off  = u32_le(msg, 16) as usize;
    let nt_len  = u16_le(msg, 20) as usize;
    let nt_off  = u32_le(msg, 24) as usize;
    let dom_len = u16_le(msg, 28) as usize;
    let dom_off = u32_le(msg, 32) as usize;
    let usr_len = u16_le(msg, 36) as usize;
    let usr_off = u32_le(msg, 40) as usize;

    let domain = utf16le_decode(safe_slice(msg, dom_off, dom_off + dom_len));
    let user   = utf16le_decode(safe_slice(msg, usr_off, usr_off + usr_len));
    let lm_resp = safe_slice(msg, lm_off, lm_off + lm_len);
    let nt_resp = safe_slice(msg, nt_off, nt_off + nt_len);

    if nt_len > 24 {
        // NTLMv2 — first 16 bytes are the NTProofStr, the rest is the blob.
        if nt_resp.len() < 16 { return None; }
        let challenge = "0" .repeat(16); // placeholder — exact challenge in NTLMSSP neg
        Some(format!(
            "{}::{}:{}:{}:{}",
            user, domain, challenge,
            to_hex(&nt_resp[..16]),
            to_hex(&nt_resp[16..])
        ))
    } else {
        let challenge = "0".repeat(16);
        Some(format!(
            "{}::{}:{}:{}:{}",
            user, domain,
            to_hex(lm_resp),
            to_hex(nt_resp),
            challenge
        ))
    }
}

fn safe_slice(data: &[u8], s: usize, e: usize) -> &[u8] {
    let e = e.min(data.len());
    if s >= e { &[] } else { &data[s..e] }
}
