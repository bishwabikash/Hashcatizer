use crate::common::to_hex;

pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    // Binary plist starting with "bplist00"
    if !data.starts_with(b"bplist00") {
        return None;
    }
    // Scan for SALTED-SHA512-PBKDF2 or SALTED-SHA512 plist keys
    let pbkdf2_marker = b"SALTED-SHA512-PBKDF2";
    let sha512_marker = b"SALTED-SHA512";

    if data.windows(pbkdf2_marker.len()).any(|w| w == pbkdf2_marker) {
        return extract_pbkdf2(data);
    }
    if data.windows(sha512_marker.len()).any(|w| w == sha512_marker) {
        return extract_sha512(data);
    }
    None
}

fn extract_pbkdf2(data: &[u8]) -> Option<Vec<String>> {
    // Locate entropy/salt/iterations after marker
    let entropy_key  = b"entropy";
    let salt_key     = b"salt";
    let iter_key     = b"iterations";

    let entropy  = find_blob_after(data, entropy_key)?;
    let salt_raw = find_blob_after(data, salt_key)?;
    let iters    = find_u32_after(data, iter_key)?;

    Some(vec![format!("$ml${}${}${}", iters, to_hex(salt_raw), to_hex(entropy))])
}

fn extract_sha512(data: &[u8]) -> Option<Vec<String>> {
    // 68 bytes = 4-byte salt + 64-byte digest somewhere in the plist
    let sha512_marker = b"SALTED-SHA512";
    let pos = data.windows(sha512_marker.len()).position(|w| w == sha512_marker)?;
    // Skip forward to data blob
    let after = &data[pos + sha512_marker.len()..];
    // Find 68-byte data blob (binary plist data marker 0x44 = 68 bytes)
    let idx = after.iter().position(|&b| b == 0x44)?;
    let raw = crate::common::safe_take(after, idx + 1, 68)?;
    // SALTED-SHA512 without PBKDF2 is the 10.7 format, hashcat -m 1722, which
    // takes the 4 byte salt and 64 byte digest as one 136 character hex string.
    // Emitting "$ml$0$..." here borrowed the shape of -m 7100, but that mode is
    // the 10.8+ PBKDF2 format and needs a real iteration count, so a zero there
    // matched no mode and the hash could not be cracked.
    let salt   = to_hex(&raw[..4]);
    let digest = to_hex(&raw[4..68]);
    Some(vec![format!("{}{}", salt, digest)])
}

fn find_blob_after<'a>(data: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let pos = data.windows(key.len()).position(|w| w == key)? + key.len();
    // Skip to data marker
    let after = &data[pos..];
    // Find 0x4x data byte
    let idx = after.iter().position(|&b| b & 0xF0 == 0x40)?;
    let len = (after[idx] & 0x0F) as usize;
    let start = idx + 1;
    if start + len > after.len() { return None; }
    Some(&after[start..start + len])
}

fn find_u32_after(data: &[u8], key: &[u8]) -> Option<u32> {
    let pos = data.windows(key.len()).position(|w| w == key)? + key.len();
    let after = &data[pos..];
    // 0x13 = 4-byte int
    let idx = after.iter().position(|&b| b == 0x13)?;
    if idx + 5 > after.len() { return None; }
    Some(u32::from_be_bytes(after[idx + 1..idx + 5].try_into().ok()?))
}
