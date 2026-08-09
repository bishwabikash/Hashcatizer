//! Shared byte-parsing utilities used by every converter.

/// Encode bytes as lowercase hex string.
#[inline]
pub fn to_hex(data: &[u8]) -> String {
    hex::encode(data)
}

/// Decode a hex string to bytes.
#[inline]
#[allow(dead_code)]
pub fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s).map_err(|e| e.to_string())
}

// All integer readers below operate on untrusted file bytes, so an out-of-bounds
// `offset` must never panic — it returns 0 (consistent with `safe_slice` returning
// an empty slice). Callers already validate lengths before using the value, so a
// truncated file produces a graceful `None` instead of aborting the process.

/// Read a little-endian u16 from `data` at `offset` (0 if out of bounds).
#[inline]
pub fn u16_le(data: &[u8], offset: usize) -> u16 {
    match data.get(offset..offset + 2) {
        Some(b) => u16::from_le_bytes(b.try_into().unwrap()),
        None => 0,
    }
}

/// Read a big-endian u16 from `data` at `offset` (0 if out of bounds).
#[inline]
pub fn u16_be(data: &[u8], offset: usize) -> u16 {
    match data.get(offset..offset + 2) {
        Some(b) => u16::from_be_bytes(b.try_into().unwrap()),
        None => 0,
    }
}

/// Read a little-endian u32 from `data` at `offset` (0 if out of bounds).
#[inline]
pub fn u32_le(data: &[u8], offset: usize) -> u32 {
    match data.get(offset..offset + 4) {
        Some(b) => u32::from_le_bytes(b.try_into().unwrap()),
        None => 0,
    }
}

/// Read a big-endian u32 from `data` at `offset` (0 if out of bounds).
#[inline]
pub fn u32_be(data: &[u8], offset: usize) -> u32 {
    match data.get(offset..offset + 4) {
        Some(b) => u32::from_be_bytes(b.try_into().unwrap()),
        None => 0,
    }
}

/// Read a little-endian u64 from `data` at `offset` (0 if out of bounds).
#[inline]
pub fn u64_le(data: &[u8], offset: usize) -> u64 {
    match data.get(offset..offset + 8) {
        Some(b) => u64::from_le_bytes(b.try_into().unwrap()),
        None => 0,
    }
}

/// Read a little-endian i64 from `data` at `offset` (0 if out of bounds).
#[inline]
#[allow(dead_code)]
pub fn i64_le(data: &[u8], offset: usize) -> i64 {
    match data.get(offset..offset + 8) {
        Some(b) => i64::from_le_bytes(b.try_into().unwrap()),
        None => 0,
    }
}

/// Safe slice access — returns empty slice if out of bounds.
#[inline]
pub fn safe_slice(data: &[u8], start: usize, end: usize) -> &[u8] {
    let end = end.min(data.len());
    if start >= end { &[] } else { &data[start..end] }
}

/// Safe length-prefixed slice — `&data[start..start + len]`, or `None` if that
/// range is out of bounds. Use instead of direct slicing on untrusted offsets.
#[inline]
pub fn safe_take(data: &[u8], start: usize, len: usize) -> Option<&[u8]> {
    data.get(start..start.checked_add(len)?)
}

/// Decode bytes as UTF-16-LE to String.
pub fn utf16le_decode(data: &[u8]) -> String {
    let words: Vec<u16> = data
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    String::from_utf16_lossy(&words).trim_end_matches('\0').to_string()
}

/// Base64-decode a string (standard alphabet).
pub fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| e.to_string())
}

/// Base64-encode bytes (standard alphabet).
pub fn b64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Read a 4-byte big-endian length-prefixed byte string.
#[allow(dead_code)]
pub fn read_be_blob(data: &[u8], offset: usize) -> Option<(&[u8], usize)> {
    if offset + 4 > data.len() {
        return None;
    }
    let len = u32_be(data, offset) as usize;
    let end = offset + 4 + len;
    if end > data.len() {
        return None;
    }
    Some((&data[offset + 4..end], end))
}

/// Bitcoin wallet compact-size integer.
pub fn read_compact_size(data: &[u8], offset: usize) -> Option<(u64, usize)> {
    if offset >= data.len() {
        return None;
    }
    match data[offset] {
        v if v < 0xfd => Some((v as u64, offset + 1)),
        0xfd => {
            if offset + 3 > data.len() { return None; }
            Some((u16_le(data, offset + 1) as u64, offset + 3))
        }
        0xfe => {
            if offset + 5 > data.len() { return None; }
            Some((u32_le(data, offset + 1) as u64, offset + 5))
        }
        _ => {
            if offset + 9 > data.len() { return None; }
            Some((u64_le(data, offset + 1), offset + 9))
        }
    }
}

/// Shannon entropy in bits per byte.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Whether a buffer plausibly holds ciphertext.
///
/// Formats whose headers are fully encrypted (TrueCrypt, VeraCrypt, SQLCipher
/// databases, AES-GCM backups) carry no magic bytes, so this is the only
/// content-based signal available. It is not proof of format -- nothing can be
/// -- but ciphertext is near-uniform at ~7.99 bits/byte while text, source code
/// and structured binaries sit far below, so it removes essentially every
/// accidental match.
///
/// `min_entropy` is per-format: use ~7.0 for whole encrypted headers and lower
/// where the sample includes plaintext framing.
pub fn looks_encrypted(data: &[u8], min_entropy: f64) -> bool {
    // Too small a sample makes the estimate meaningless: a 32-byte buffer
    // cannot exceed 5 bits/byte even if perfectly random.
    if data.len() < 256 {
        return false;
    }
    // An all-zero or single-byte-repeated run scores 0 and is caught here too.
    shannon_entropy(data) >= min_entropy
}
