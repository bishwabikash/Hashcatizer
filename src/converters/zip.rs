use crate::common::{to_hex, u16_le, u32_le, safe_take};

// WinZip AES-encrypted ZIP entries -> hashcat -m 13600 ($zip2$).
//
// Only the WinZip AES case is supported: every field is read literally from the
// local file header + encrypted blob with no decompression. Legacy ZipCrypto
// (-m 172xx) is intentionally not produced here — it needs the full compressed
// stream plus CRC-derived checksum words, which is error-prone from a pure parser.

const LFH_SIG: &[u8] = b"PK\x03\x04";
const CD_SIG:  &[u8] = b"PK\x01\x02";
const AES_EXTRA_ID: u16 = 0x9901;
const AES_COMPRESSION: u16 = 99;

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let mut hashes = Vec::new();
    let mut scan = 0usize;
    while let Some(rel) = data[scan..].windows(4).position(|w| w == LFH_SIG) {
        let lfh = scan + rel;
        if let Some(h) = parse_local_header(data, lfh) {
            hashes.push(h);
        }
        scan = lfh + 4;
    }
    if hashes.is_empty() { None } else { Some(hashes) }
}

fn parse_local_header(data: &[u8], lfh: usize) -> Option<String> {
    // Need the 30-byte fixed local file header.
    if lfh + 30 > data.len() { return None; }
    let method   = u16_le(data, lfh + 8);
    if method != AES_COMPRESSION { return None; } // not a WinZip AES entry
    let mut comp_size = u32_le(data, lfh + 18) as usize;
    let name_len  = u16_le(data, lfh + 26) as usize;
    let extra_len = u16_le(data, lfh + 28) as usize;

    let extra_start = lfh + 30 + name_len;
    let extra = safe_take(data, extra_start, extra_len)?;
    let strength = aes_strength(extra)?; // 1/2/3 from the 0x9901 record

    // Streamed entries (general-purpose flag bit 3) store size 0 in the LFH and
    // put the real size in the central directory / data descriptor. Recover it.
    if comp_size == 0 {
        comp_size = central_dir_comp_size(data, lfh)?;
    }

    let salt_len = 4 + 4 * strength as usize; // 8/12/16 bytes for strength 1/2/3
    // blob = salt | 2-byte pwd verify | ciphertext | 10-byte auth code
    if comp_size < salt_len + 2 + 10 { return None; }
    let ct_len = comp_size - salt_len - 2 - 10;

    let blob_start = extra_start + extra_len;
    let salt   = safe_take(data, blob_start, salt_len)?;
    let verify = safe_take(data, blob_start + salt_len, 2)?;
    let ct     = safe_take(data, blob_start + salt_len + 2, ct_len)?;
    let auth   = safe_take(data, blob_start + salt_len + 2 + ct_len, 10)?;

    Some(format!(
        "$zip2$*0*{}*0*{}*{}*{:x}*{}*{}*$/zip2$",
        strength, to_hex(salt), to_hex(verify), ct_len, to_hex(ct), to_hex(auth)
    ))
}

/// Find the WinZip AES extra record (id 0x9901, size 7) and return its strength
/// byte (1=128-bit/8B salt, 2=192/12B, 3=256/16B).
fn aes_strength(extra: &[u8]) -> Option<u8> {
    let mut off = 0;
    while off + 4 <= extra.len() {
        let id   = u16_le(extra, off);
        let size = u16_le(extra, off + 2) as usize;
        let body_start = off + 4;
        if body_start + size > extra.len() { break; }
        if id == AES_EXTRA_ID && size == 7 {
            // body: [0,1] version, [2,3] vendor "AE", [4] strength, [5,6] real method
            return extra.get(body_start + 4).copied().filter(|&s| (1..=3).contains(&s));
        }
        off = body_start + size;
    }
    None
}

/// For streamed entries, read the compressed size from the central-directory
/// record whose relative-local-header-offset matches `lfh`.
fn central_dir_comp_size(data: &[u8], lfh: usize) -> Option<usize> {
    let mut scan = 0usize;
    while let Some(rel) = data[scan..].windows(4).position(|w| w == CD_SIG) {
        let cd = scan + rel;
        if cd + 46 <= data.len() {
            let lh_off = u32_le(data, cd + 42) as usize;
            if lh_off == lfh {
                let cs = u32_le(data, cd + 20) as usize;
                if cs > 0 { return Some(cs); }
            }
        }
        scan = cd + 4;
    }
    None
}
