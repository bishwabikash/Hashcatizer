use crate::common::to_hex;
use rusqlite::{Connection, OpenFlags};
use std::path::Path;

pub fn convert(path: &Path) -> Option<Vec<String>> {
    let data = std::fs::read(path).ok()?;
    // key4.db (SQLite)
    if data.starts_with(b"SQLite format 3\x00") {
        return convert_key4(path);
    }
    // key3.db (BDB / binary)
    convert_key3(&data)
}

fn convert_key4(path: &Path) -> Option<Vec<String>> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
    let mut stmt = conn
        .prepare("SELECT item1, item2 FROM metadata WHERE id='password'")
        .ok()?;
    let mut rows = stmt.query([]).ok()?;
    let row = rows.next().ok()??;
    let global_salt: Vec<u8> = row.get(0).ok()?;
    let item2: Vec<u8>       = row.get(1).ok()?;
    // Walk the DER in item2: extract salt + iterations + enc_data
    let (salt, iters, enc_data) = parse_der_pbes2(&item2)?;
    Some(vec![format!(
        "$mozilla$*{}*{}*{}*{}",
        to_hex(&global_salt),
        to_hex(&salt),
        iters,
        to_hex(&enc_data)
    )])
}

fn parse_der_pbes2(der: &[u8]) -> Option<(Vec<u8>, u32, Vec<u8>)> {
    // Walk DER, collect first OCTET STRING (salt), first INTEGER (iterations),
    // last OCTET STRING (enc_data)
    let mut off = 0;
    let mut salt = Vec::new();
    let mut iters: u32 = 1;
    let mut enc_data = Vec::new();

    while off + 2 < der.len() {
        let tag = der[off]; off += 1;
        let (len, advance) = der_length(der, off)?;
        off += advance;
        if off + len > der.len() { break; }
        let val = &der[off..off + len];
        match tag {
            0x04 => {
                // OCTET STRING
                if salt.is_empty() && len >= 8 {
                    salt = val.to_vec();
                } else if !salt.is_empty() {
                    enc_data = val.to_vec();
                }
            }
            0x02 => {
                // INTEGER — iterations
                if len <= 4 {
                    let mut n: u32 = 0;
                    for &b in val { n = (n << 8) | b as u32; }
                    iters = n;
                }
            }
            _ => {}
        }
        if tag != 0x30 && tag != 0xA0 && tag != 0xA1 && tag != 0x06 && tag != 0x04 && tag != 0x02 {
            off += len;
        }
    }
    if salt.is_empty() || enc_data.is_empty() { return None; }
    Some((salt, iters, enc_data))
}

fn convert_key3(data: &[u8]) -> Option<Vec<String>> {
    // BDB: scan for "password-check" key
    let marker = b"password-check";
    let pos = data.windows(marker.len()).position(|w| w == marker)?;
    let global_salt = data.get(3..19)?.to_vec();
    let pc_end = pos + marker.len();
    // password_check bytes after key
    let pc_data = data.get(pc_end..pc_end + 24)?;
    Some(vec![format!(
        "$mozilla$*{}*{}",
        to_hex(&global_salt),
        to_hex(pc_data)
    )])
}

fn der_length(data: &[u8], off: usize) -> Option<(usize, usize)> {
    if off >= data.len() { return None; }
    let b = data[off];
    if b & 0x80 == 0 {
        Some((b as usize, 1))
    } else {
        let n = (b & 0x7F) as usize;
        if off + 1 + n > data.len() { return None; }
        let mut len: usize = 0;
        for i in 0..n { len = (len << 8) | data[off + 1 + i] as usize; }
        Some((len, 1 + n))
    }
}
