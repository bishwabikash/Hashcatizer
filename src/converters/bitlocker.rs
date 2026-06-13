use crate::common::{to_hex, u16_le, u32_le, u64_le};

const FVE_SIG: &[u8] = b"-FVE-FS-";

pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    // Confirm BitLocker signature at offset 3
    if data.len() < 200 || &data[3..11] != FVE_SIG {
        return None;
    }
    // FVE metadata offsets at volume header bytes 176, 184, 192 (LE uint64 each)
    let fve_offset = u64_le(data, 176) as usize;
    if fve_offset == 0 || fve_offset + 512 > data.len() {
        // Try second/third offsets
        let fve2 = u64_le(data, 184) as usize;
        if fve2 == 0 || fve2 + 512 > data.len() {
            return None;
        }
    }

    let fve_offset = u64_le(data, 176) as usize;
    let fve = &data[fve_offset..];
    if fve.len() < 48 || &fve[0..8] != FVE_SIG {
        return None;
    }

    let block_size = u32_le(fve, 8) as usize;
    // Walk entries starting at offset 48
    let mut off = 48;
    while off + 6 < fve.len().min(block_size) {
        let entry_size = u16_le(fve, off) as usize;
        if entry_size < 8 || off + entry_size > fve.len() { break; }
        let entry_type = u16_le(fve, off + 2);
        // 0x0002 = VMK
        if entry_type == 0x0002 {
            if off + 28 > fve.len() { break; }
            let protection = u16_le(fve, off + 26);
            if protection == 0x2000 {
                // password-protected VMK — parse sub-entries
                if let Some(hash) = parse_vmk_subentries(&fve[off..off + entry_size]) {
                    return Some(vec![hash]);
                }
            }
        }
        off += entry_size;
    }
    None
}

fn parse_vmk_subentries(vmk: &[u8]) -> Option<String> {
    let mut salt = None::<Vec<u8>>;
    let mut nonce = None::<Vec<u8>>;
    let mut mac_and_enc = None::<Vec<u8>>;

    let mut off = 36;
    while off + 6 < vmk.len() {
        let sub_size = u16_le(vmk, off) as usize;
        if sub_size < 8 || off + sub_size > vmk.len() { break; }
        let val_type = u16_le(vmk, off + 4);
        match val_type {
            0x0003 => {
                // STRETCH key data: [8..24] = salt (16 bytes)
                if off + 24 <= vmk.len() {
                    salt = Some(vmk[off + 8..off + 24].to_vec());
                }
            }
            0x0005 => {
                // AES-CCM: nonce [8..20], mac [20..36], enc_data [36..sub_size]
                if off + sub_size <= vmk.len() {
                    nonce = Some(vmk[off + 8..off + 20].to_vec());
                    mac_and_enc = Some(vmk[off + 20..off + sub_size].to_vec());
                }
            }
            _ => {}
        }
        off += sub_size;
    }

    let salt = salt?;
    let nonce = nonce?;
    let mac_enc = mac_and_enc?;
    Some(format!(
        "$bitlocker$1*16*{}*{}*{}*{}*{}",
        to_hex(&salt),
        nonce.len(),
        to_hex(&nonce),
        mac_enc.len(),
        to_hex(&[nonce.as_slice(), mac_enc.as_slice()].concat())
    ))
}
