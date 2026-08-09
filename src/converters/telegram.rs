use crate::common::to_hex;
use md5::{Digest, Md5};

// Telegram Desktop local storage (map0 / key_datas) -> hashcat -m 22600 / 24500.
//
//   $telegram$1*4000*<salt>*<encrypted_key>     Desktop <  v2.1.14 (PBKDF2-SHA1)
//   $telegram$2*100000*<salt>*<encrypted_key>   Desktop >= v2.1.14 (PBKDF2-SHA512)
//
// The container carries a trailing MD5 over its own body, which is verified
// here before anything is emitted. That check is what makes this converter safe
// to run in the auto-detect sweep: without it the old implementation accepted
// literally any file of 32 bytes or more and reported a Telegram hash for it.

const MAGIC: &[u8] = b"TDF$";
const SALT_SIZE: usize = 32;
/// 16 message key + 16 length/alignment + 256 key.
const KEY_SIZE: usize = 288;
/// AppVersion at which Telegram Desktop moved to PBKDF2-HMAC-SHA512.
const STRONG_VERSION: u32 = 2_001_014;

pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    if !data.starts_with(MAGIC) || data.len() < 8 {
        return None;
    }
    let version_bytes = data.get(4..8)?;
    let version = u32::from_le_bytes(version_bytes.try_into().ok()?);
    let body = data.get(8..)?;
    if body.len() < 16 {
        return None;
    }

    let (actual, checksum) = body.split_at(body.len() - 16);

    // MD5(body || len(body) || version || magic) — reject anything that is not
    // genuinely a Telegram container.
    let mut hasher = Md5::new();
    hasher.update(actual);
    hasher.update((actual.len() as u32).to_le_bytes());
    hasher.update(version_bytes);
    hasher.update(MAGIC);
    if hasher.finalize().as_slice() != checksum {
        return None;
    }

    // Both length prefixes are big-endian and fixed by the format.
    if u32::from_be_bytes(actual.get(0..4)?.try_into().ok()?) as usize != SALT_SIZE {
        return None;
    }
    let salt = actual.get(4..4 + SALT_SIZE)?;

    let key_len_off = 4 + SALT_SIZE;
    if u32::from_be_bytes(actual.get(key_len_off..key_len_off + 4)?.try_into().ok()?) as usize
        != KEY_SIZE
    {
        return None;
    }
    let key_off = key_len_off + 4;
    let key = actual.get(key_off..key_off + KEY_SIZE)?;

    let (variant, iterations) = if version >= STRONG_VERSION {
        (2, 100_000)
    } else {
        (1, 4_000)
    };

    Some(vec![format!(
        "$telegram${}*{}*{}*{}",
        variant,
        iterations,
        to_hex(salt),
        to_hex(key)
    )])
}

/// Which hashcat mode the emitted variant needs.
pub fn hashcat_mode(hash: &str) -> Option<&'static str> {
    match hash.strip_prefix("$telegram$")?.as_bytes().first()? {
        b'1' => Some("22600"),
        b'2' => Some("24500"),
        b'0' => Some("22301"),
        _ => None,
    }
}
