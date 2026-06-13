use crate::common::{to_hex, u16_le};

// RAR archives -> hashcat.
//   RAR3/4 with encrypted headers ("rar a -hp")  -> -m 12500  ($RAR3$*0*...)
//   RAR5 (-hp encrypted headers or -p file data)  -> -m 13000  ($rar5$...)
//
// RAR3 "-p" (encrypted file data, modes 23700/23800) is intentionally not
// produced: it must embed the raw encrypted file-data block and has fiddly
// header-flag constraints that are unreliable from a pure parser.

const RAR3_MAGIC: &[u8] = b"Rar!\x1a\x07\x00";
const RAR5_MAGIC: &[u8] = b"Rar!\x1a\x07\x01\x00";

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    // RAR5 magic is a prefix superset of RAR3's, so test RAR5 first.
    if let Some(pos) = find(data, RAR5_MAGIC) {
        return parse_rar5(data, pos + RAR5_MAGIC.len()).map(|h| vec![h]);
    }
    if let Some(pos) = find(data, RAR3_MAGIC) {
        return parse_rar3_hp(data, pos).map(|h| vec![h]);
    }
    None
}

// ---------------------------------------------------------------------------
// RAR3/4 encrypted-headers (-hp) -> $RAR3$*0*<salt8>*<encblock16>
// ---------------------------------------------------------------------------
fn parse_rar3_hp(data: &[u8], magic_pos: usize) -> Option<String> {
    // Main archive header begins right after the 7-byte marker.
    let hdr = magic_pos + RAR3_MAGIC.len();
    if hdr + 7 > data.len() { return None; }
    if data[hdr + 2] != 0x73 { return None; } // HEAD_TYPE must be MAIN_HEAD ('s')
    let head_flags = u16_le(data, hdr + 3);
    if head_flags & 0x0080 == 0 { return None; } // MHD_PASSWORD => encrypted headers

    // For -hp, the 8-byte salt + 16-byte verifier live in the encrypted
    // end-of-archive terminator: the last 24 bytes of the file.
    if data.len() < 24 { return None; }
    let tail = &data[data.len() - 24..];
    let salt     = &tail[0..8];
    let encblock = &tail[8..24];
    Some(format!("$RAR3$*0*{}*{}", to_hex(salt), to_hex(encblock)))
}

// ---------------------------------------------------------------------------
// RAR5 -> $rar5$16$<salt16>$<lg2count>$<iv16>$8$<pswcheck8>
// ---------------------------------------------------------------------------
fn parse_rar5(data: &[u8], start: usize) -> Option<String> {
    let mut off = start;
    // Walk blocks looking for either an archive-level CRYPT header (0x04, -hp)
    // or a FILE/SERVICE block carrying an FHEXTRA_CRYPT record (-p).
    while off < data.len() {
        // Block: HeadCRC32(4) | HeaderSize(vint) | HeaderType(vint) | HeaderFlags(vint)
        let block_start = off;
        if block_start + 4 > data.len() { break; }
        let mut p = block_start + 4; // skip HeadCRC32

        let (head_size, np) = read_vint(data, p)?;
        p = np;
        let header_body_start = p; // HeaderType begins here; HeaderSize counts from here
        let (htype, np) = read_vint(data, p)?;
        p = np;
        let (hflags, np) = read_vint(data, p)?;
        p = np;

        if hflags & 0x01 != 0 { let (_e, np) = read_vint(data, p)?; p = np; } // HFL_EXTRA
        let mut data_size = 0u64;
        if hflags & 0x02 != 0 { let (d, np) = read_vint(data, p)?; data_size = d; p = np; } // HFL_DATA

        let block_end = header_body_start
            .checked_add(head_size as usize)?
            .checked_add(data_size as usize)?;

        match htype {
            0x04 => {
                // HEAD_CRYPT (archive-level encrypted headers).
                if let Some(h) = parse_rar5_crypt_record(data, p, true) {
                    // pswcheck path: salt/lg2/pswcheck present, IV taken from the
                    // record; emit directly.
                    return Some(h);
                }
            }
            0x02 | 0x03 if hflags & 0x01 != 0 => {
                // FILE / SERVICE block with an extra area: scan it for FHEXTRA_CRYPT.
                let extra_end = header_body_start + head_size as usize;
                if let Some(h) = scan_fhextra_crypt(data, p, extra_end) {
                    return Some(h);
                }
            }
            _ => {}
        }

        if block_end <= block_start { break; } // no forward progress -> bail
        off = block_end;
    }
    None
}

/// Parse a RAR5 CRYPT record body (archive HEAD_CRYPT). Layout:
/// version(vint=0) | flags(vint) | Lg2Count(1) | salt(16) | [pswcheck(8) csum(4)] | IV(16)
fn parse_rar5_crypt_record(data: &[u8], mut p: usize, _archive: bool) -> Option<String> {
    let (version, np) = read_vint(data, p)?; p = np;
    if version != 0 { return None; }
    let (flags, np) = read_vint(data, p)?; p = np;
    let use_pswcheck = flags & 0x01 != 0;
    let lg2 = *data.get(p)?; p += 1;
    let salt = safe_take16(data, p)?; p += 16;
    if !use_pswcheck { return None; } // hashcat needs the pswcheck verifier
    let pswcheck = data.get(p..p + 8)?; p += 8;
    let _csum = data.get(p..p + 4)?; p += 4;
    let iv = safe_take16(data, p)?;
    Some(rar5_line(salt, lg2, iv, pswcheck))
}

/// Scan a FILE/SERVICE extra area for the FHEXTRA_CRYPT (FieldType 0x01) record.
/// Each extra record: size(vint) | type(vint) | data...; the size covers type+data.
fn scan_fhextra_crypt(data: &[u8], mut p: usize, extra_end: usize) -> Option<String> {
    while p < extra_end {
        let (rec_size, np) = read_vint(data, p)?;
        let after_size = np;
        let (field_type, np2) = read_vint(data, after_size)?;
        let rec_end = after_size.checked_add(rec_size as usize)?;
        if rec_end > extra_end { break; }
        if field_type == 0x01 {
            // FHEXTRA_CRYPT: EncVersion(vint) | Flags(vint) | Lg2Count(1) | salt(16) | IV(16) | pswcheck(8)
            let mut q = np2;
            let (_encver, nq) = read_vint(data, q)?; q = nq;
            let (flags, nq) = read_vint(data, q)?; q = nq;
            if flags & 0x01 == 0 { return None; } // FHEXTRA_CRYPT_PSWCHECK required
            let lg2 = *data.get(q)?; q += 1;
            let salt = safe_take16(data, q)?; q += 16;
            let iv = safe_take16(data, q)?; q += 16;
            let pswcheck = data.get(q..q + 8)?;
            return Some(rar5_line(salt, lg2, iv, pswcheck));
        }
        p = rec_end;
    }
    None
}

fn rar5_line(salt: &[u8], lg2: u8, iv: &[u8], pswcheck: &[u8]) -> String {
    format!(
        "$rar5$16${}${}${}$8${}",
        to_hex(salt), lg2, to_hex(iv), to_hex(pswcheck)
    )
}

// ---- helpers ----

/// Read a RAR5 vint (LE base-128, 7 bits/byte, high bit = continuation).
/// Returns (value, offset-past-vint). Caps at 10 bytes to avoid runaway input.
fn read_vint(data: &[u8], start: usize) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    let mut i = start;
    for _ in 0..10 {
        let b = *data.get(i)?;
        value |= ((b & 0x7f) as u64) << shift;
        i += 1;
        if b & 0x80 == 0 { return Some((value, i)); }
        shift += 7;
    }
    None
}

fn safe_take16(data: &[u8], start: usize) -> Option<&[u8]> {
    data.get(start..start + 16)
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() { return None; }
    hay.windows(needle.len()).position(|w| w == needle)
}
