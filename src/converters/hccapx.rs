use crate::common::to_hex;

// hccapx capture files -> hashcat -m 22000 (WPA-PBKDF2-PMKID+EAPOL).
//
//   WPA*02*<mic>*<mac_ap>*<mac_sta>*<essid>*<nonce_ap>*<eapol>*<message_pair>
//
// hccapx is hashcat's own legacy binary container (mode 2500, deprecated). The
// modern replacement is the 22000 text line, so records are transcoded rather
// than hex-dumped: a .hccapx file holds one 393-byte record per handshake and
// every field the 22000 line needs is already in it.

const SIGNATURE: &[u8] = b"HCPX";
const RECORD_LEN: usize = 393;

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    if !data.starts_with(SIGNATURE) || data.len() < RECORD_LEN {
        return None;
    }
    let mut out = Vec::new();

    for record in data.chunks_exact(RECORD_LEN) {
        if !record.starts_with(SIGNATURE) {
            continue; // resynchronising is hopeless; a stray record ends it
        }
        if let Some(line) = parse_record(record) {
            out.push(line);
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

fn parse_record(r: &[u8]) -> Option<String> {
    // signature[4] version[4] message_pair essid_len essid[32] keyver
    // keymic[16] mac_ap[6] nonce_ap[32] mac_sta[6] nonce_sta[32]
    // eapol_len[2] eapol[256]
    let message_pair = *r.get(8)?;
    let essid_len = *r.get(9)? as usize;
    if essid_len > 32 {
        return None;
    }
    let essid = r.get(10..10 + essid_len)?;
    let keymic = r.get(43..59)?;
    let mac_ap = r.get(59..65)?;
    let nonce_ap = r.get(65..97)?;
    let mac_sta = r.get(97..103)?;

    let eapol_len = u16::from_le_bytes(r.get(135..137)?.try_into().ok()?) as usize;
    if eapol_len > 256 {
        return None;
    }
    let eapol = r.get(137..137 + eapol_len)?;

    Some(format!(
        "WPA*02*{}*{}*{}*{}*{}*{}*{:02x}",
        to_hex(keymic),
        to_hex(mac_ap),
        to_hex(mac_sta),
        to_hex(essid),
        to_hex(nonce_ap),
        to_hex(eapol),
        message_pair
    ))
}
