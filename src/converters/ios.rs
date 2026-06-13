use crate::common::to_hex;
use std::path::Path;

pub fn convert(path: &Path) -> Option<Vec<String>> {
    // iOS backup directory
    let manifest = if path.is_dir() {
        path.join("Manifest.plist")
    } else {
        path.to_path_buf()
    };
    let data = std::fs::read(&manifest).ok()?;
    parse_manifest(&data)
}

fn parse_manifest(data: &[u8]) -> Option<Vec<String>> {
    // Binary plist: look for "BackupKeyBag" key and get its data
    // For binary plist we just scan for TLV keybag bytes
    let bkb_marker = b"BackupKeyBag";
    let pos = data.windows(bkb_marker.len()).position(|w| w == bkb_marker)?;
    // Binary plist data object following the key — scan forward for keybag data header
    let keybag = extract_data_after(data, pos + bkb_marker.len())?;
    let (mode, hash) = parse_keybag(keybag)?;
    Some(vec![format!("$itunes_backup$*{}*{}", mode, hash)])
}

fn extract_data_after(data: &[u8], start: usize) -> Option<&[u8]> {
    // In binary plist, data objects are prefixed with type+length nybble
    // Skip to the first 0x4x byte (data marker) after `start`
    let slice = data.get(start..)?;
    let pos = slice.iter().position(|&b| b & 0xF0 == 0x40)?;
    let marker = slice[pos];
    let mut len = (marker & 0x0F) as usize;
    let mut off = pos + 1;
    if len == 15 {
        // extended length int follows
        let int_marker = *slice.get(off)?;
        let int_len_bytes = 1usize << (int_marker & 0x0F);
        off += 1;
        len = 0;
        for i in 0..int_len_bytes {
            len = (len << 8) | (*slice.get(off + i)? as usize);
        }
        off += int_len_bytes;
    }
    crate::common::safe_take(slice, off, len)
}

fn parse_keybag(kb: &[u8]) -> Option<(u32, String)> {
    let mut salt = None::<&[u8]>;
    let mut iter: u32 = 10000;
    let mut dpsl = None::<&[u8]>;
    let mut dpic: u32 = 0;

    let mut off = 0;
    while off + 8 <= kb.len() {
        let tag = &kb[off..off + 4];
        let len = u32::from_be_bytes(kb[off + 4..off + 8].try_into().ok()?) as usize;
        off += 8;
        if off + len > kb.len() { break; }
        let val = &kb[off..off + len];
        match tag {
            b"SALT" => salt = Some(val),
            b"ITER" if len == 4 => iter = u32::from_be_bytes(val.try_into().ok()?),
            b"DPSL" => dpsl = Some(val),
            b"DPIC" if len == 4 => dpic = u32::from_be_bytes(val.try_into().ok()?),
            _ => {}
        }
        off += len;
    }

    let kb_hex = to_hex(&kb[..kb.len().min(256)]);
    if dpic > 0 && dpsl.is_some() {
        // iOS >= 10.2 (mode 14800)
        let dpsl_hex = to_hex(dpsl.unwrap());
        let first40 = to_hex(&kb[..kb.len().min(20)]);
        Some((10, format!("{}*{}*{}*{}*{}", first40, dpic, dpsl_hex, kb.len(), kb_hex)))
    } else {
        // Older (mode 14700)
        let salt_hex = salt.map(to_hex).unwrap_or_else(|| to_hex(&kb[..kb.len().min(10)]));
        Some((9, format!("{}*{}*0*{}*{}", salt_hex, iter, kb.len(), kb_hex)))
    }
}
