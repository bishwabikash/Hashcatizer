use crate::common::{to_hex, u16_le, u32_le, u64_le};

const SIG1: u32 = 0x9AA2D903;
const SIG2_KDB:  u32 = 0xB54BFB65; // KeePass 1
const SIG2_KDBX: u32 = 0xB54BFB67; // KeePass 2

pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    if data.len() < 12 { return None; }
    let sig1 = u32_le(data, 0);
    let sig2 = u32_le(data, 4);
    if sig1 != SIG1 { return None; }
    match sig2 {
        SIG2_KDB  => parse_kdb(data).map(|h| vec![h]),
        SIG2_KDBX => parse_kdbx(data).map(|h| vec![h]),
        _ => None,
    }
}

fn parse_kdb(data: &[u8]) -> Option<String> {
    if data.len() < 124 { return None; }
    let rounds        = u32_le(data, 120);
    let master_seed   = to_hex(&data[16..32]);
    let enc_iv        = to_hex(&data[32..48]);
    let contents_hash = to_hex(&data[56..88]);
    let transform_seed= to_hex(&data[88..120]);
    Some(format!(
        "$keepass$*1*{}*0*{}*{}*{}*{}",
        rounds, master_seed, transform_seed, enc_iv, contents_hash
    ))
}

fn parse_kdbx(data: &[u8]) -> Option<String> {
    let file_ver_minor = u16_le(data, 8);
    let file_ver_major = u16_le(data, 10);
    let major = file_ver_major;
    let file_version = (file_ver_major as u32) * 1000 + file_ver_minor as u32;
    let mut off = 12;

    let mut master_seed = None::<Vec<u8>>;
    let mut transform_seed = None::<Vec<u8>>;
    let mut enc_iv = None::<Vec<u8>>;
    let mut transform_rounds: u64 = 600000;
    let mut stream_start = None::<Vec<u8>>;
    let mut enc_data_begin = 0usize;

    loop {
        if off >= data.len() { break; }
        let field_id = data[off]; off += 1;
        if field_id == 0 {
            // END header
            if major >= 4 {
                let field_size = u32_le(data, off) as usize; off += 4;
                off += field_size;
            } else {
                let field_size = u16_le(data, off) as usize; off += 2;
                off += field_size;
            }
            enc_data_begin = off;
            break;
        }
        let field_size: usize = if major >= 4 {
            let s = u32_le(data, off) as usize; off += 4; s
        } else {
            let s = u16_le(data, off) as usize; off += 2; s
        };
        if off + field_size > data.len() { break; }
        let fdata = &data[off..off + field_size];
        match field_id {
            4  => master_seed = Some(fdata.to_vec()),
            5  => transform_seed = Some(fdata.to_vec()),
            6  => { if fdata.len() >= 8 { transform_rounds = u64_le(fdata, 0); } }
            7  => enc_iv = Some(fdata.to_vec()),
            9  => stream_start = Some(fdata.to_vec()),
            11 => {
                // KDF Parameters variant dict (KDBX 4)
                if let Some(kdf) = parse_kdf_dict(fdata) {
                    if let Some(s) = kdf.0 { transform_seed = Some(s); }
                    if kdf.1 > 0 { transform_rounds = kdf.1; }
                }
            }
            _ => {}
        }
        off += field_size;
    }

    let master_seed   = master_seed?;
    let transform_seed= transform_seed?;
    let enc_iv        = enc_iv?;
    let stream_start_hex = stream_start.as_deref().map(to_hex).unwrap_or_default();
    let enc_first32 = to_hex(crate::common::safe_slice(data, enc_data_begin, enc_data_begin + 32));

    Some(format!(
        "$keepass$*2*{}*{}*{}*{}*{}*{}*{}",
        transform_rounds, file_version,
        to_hex(&master_seed), to_hex(&transform_seed),
        to_hex(&enc_iv), stream_start_hex, enc_first32
    ))
}

/// Parse KDBX 4 KDF variant dictionary — returns (transform_seed, rounds)
fn parse_kdf_dict(data: &[u8]) -> Option<(Option<Vec<u8>>, u64)> {
    if data.len() < 2 { return None; }
    let mut off = 2; // skip version
    let mut seed = None;
    let mut rounds: u64 = 0;
    while off < data.len() {
        let item_type = data[off]; off += 1;
        if item_type == 0 { break; }
        if off + 4 > data.len() { break; }
        let name_len = u32_le(data, off) as usize; off += 4;
        if off + name_len > data.len() { break; }
        let name = std::str::from_utf8(&data[off..off + name_len]).unwrap_or("").to_string();
        off += name_len;
        if off + 4 > data.len() { break; }
        let val_len = u32_le(data, off) as usize; off += 4;
        if off + val_len > data.len() { break; }
        let val = &data[off..off + val_len];
        match name.as_str() {
            "S" => seed = Some(val.to_vec()),
            "R" if val.len() == 8 => rounds = u64_le(val, 0),
            _ => {}
        }
        off += val_len;
    }
    Some((seed, rounds))
}
