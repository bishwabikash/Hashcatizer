use crate::common::to_hex;

// KDE KWallet -> $kwallet$ (john).
//
//   $kwallet$<size>$<encrypted>                                 minor version 0
//   $kwallet$<size>$<encrypted>$<minor>$<salt len>$<salt>$<iter> minor version 1
//
// The folder-hash table between the header and the payload is variable length,
// so the encrypted region can only be found by walking it. The previous
// implementation dumped the first 512 bytes, which is mostly that table.
//
// From KWallet 4.13 (minor version 1) the KDF salt lives in a sibling `.salt`
// file rather than the wallet, so that is read alongside.

const MAGIC: &[u8] = b"KWALLET\n\r\0\r\n";
const VERSION_MAJOR: u8 = 0;

const CIPHER_BLOWFISH_ECB: u8 = 0;
const CIPHER_BLOWFISH_CBC: u8 = 3;
const HASH_SHA1: u8 = 0;
const HASH_PBKDF2_SHA512: u8 = 2;

const PBKDF2_SHA512_ITERATIONS: u32 = 50_000;
/// john truncates the payload; 65 bytes avoids being re-detected as another
/// format while still carrying the 64 bytes the cracker needs.
const SAMPLE_LEN: usize = 65;
const MIN_ENCRYPTED: usize = 88;

pub fn convert(data: &[u8], filename: &str) -> Option<Vec<String>> {
    if !data.starts_with(MAGIC) {
        return None;
    }
    let mut off = MAGIC.len();

    let header = data.get(off..off + 4)?;
    off += 4;
    let (major, minor, cipher, hash) = (header[0], header[1], header[2], header[3]);

    if major != VERSION_MAJOR || minor > 1 {
        return None;
    }
    if cipher != CIPHER_BLOWFISH_ECB && cipher != CIPHER_BLOWFISH_CBC {
        return None;
    }
    if hash != HASH_SHA1 && hash != HASH_PBKDF2_SHA512 {
        return None;
    }

    // Folder table: n entries, each a 16-byte hash plus a count of 16-byte
    // entry hashes.
    let n = be_u32(data, off)?;
    off += 4;
    if n > 0xffff {
        return None;
    }
    for _ in 0..n {
        off = off.checked_add(16)?;
        let entries = be_u32(data, off)?;
        off = off.checked_add(4)?;
        off = off.checked_add((entries as usize).checked_mul(16)?)?;
    }

    let encrypted = data.get(off..)?;
    let encrypted_size = encrypted.len();
    // Blowfish output is a whole number of 8-byte blocks.
    if !encrypted_size.is_multiple_of(8) || encrypted_size < MIN_ENCRYPTED {
        return None;
    }
    let sample = encrypted.get(..SAMPLE_LEN.min(encrypted_size))?;

    if minor == 0 {
        return Some(vec![format!("$kwallet${}${}", encrypted_size, to_hex(sample))]);
    }

    // Salted wallets keep the salt next to the file; without it the hash is
    // not crackable, so say nothing rather than emit an incomplete one.
    let salt = read_salt_sidecar(filename)?;
    Some(vec![format!(
        "$kwallet${}${}${}${}${}${}",
        encrypted_size,
        to_hex(sample),
        minor,
        salt.len(),
        to_hex(&salt),
        PBKDF2_SHA512_ITERATIONS
    )])
}

/// `<wallet>.kwl` -> `<wallet>.salt`
fn read_salt_sidecar(filename: &str) -> Option<Vec<u8>> {
    let path = std::path::Path::new(filename);
    let salt_path = path.with_extension("salt");
    std::fs::read(salt_path).ok().filter(|s| !s.is_empty())
}

fn be_u32(data: &[u8], off: usize) -> Option<u32> {
    let b = data.get(off..off.checked_add(4)?)?;
    Some(u32::from_be_bytes(b.try_into().ok()?))
}
