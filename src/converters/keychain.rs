use crate::common::to_hex;

// Apple Keychain (.keychain) -> hashcat -m 23100.
//
//   $keychain$*<salt>*<iv>*<ciphertext>
//
// The DB blob is located by scanning backwards from EOF for the 0xfade0711
// magic, matching keychain2john. Everything is at a fixed offset from there:
// salt at +44 (20 bytes), IV at +64 (8 bytes), and the wrapped key at the
// offset stored at +8.

const MAGIC: [u8; 4] = [0xfa, 0xde, 0x07, 0x11];
const SALT_LEN: usize = 20;
const IV_LEN: usize = 8;
const CT_LEN: usize = 48;

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let pos = find_magic_from_end(data)?;

    // The wrapped key sits at an offset recorded inside the blob.
    let cipher_off = be_u32(data, pos + 8)? as usize;

    let salt = data.get(pos + 44..pos + 44 + SALT_LEN)?;
    let iv = data.get(pos + 64..pos + 64 + IV_LEN)?;
    let ciphertext = data.get(cipher_off..cipher_off.checked_add(CT_LEN)?)?;

    Some(vec![format!(
        "$keychain$*{}*{}*{}",
        to_hex(salt),
        to_hex(iv),
        to_hex(ciphertext)
    )])
}

/// keychain2john walks backwards from the end in 4-byte steps looking for the
/// DB blob signature, because the trailing schema varies in length.
fn find_magic_from_end(data: &[u8]) -> Option<usize> {
    if data.len() < 4 {
        return None;
    }
    let mut pos = data.len() - 4;
    loop {
        if data.get(pos..pos + 4)? == MAGIC {
            return Some(pos);
        }
        pos = pos.checked_sub(4)?;
    }
}

fn be_u32(data: &[u8], off: usize) -> Option<u32> {
    let b = data.get(off..off.checked_add(4)?)?;
    Some(u32::from_be_bytes(b.try_into().ok()?))
}
