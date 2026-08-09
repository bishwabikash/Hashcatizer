use crate::common::{to_hex, u32_le, u64_le};

// Windows DPAPI master key files -> hashcat -m 15300 (v1) / -m 15900 (v2).
//
//   $DPAPImk$<version>*<context>*<SID>*<cipher>*<hash>*<rounds>*<salt>*<len>*<data>
//
// Windows stores these at
//   %APPDATA%\Microsoft\Protect\<SID>\<GUID>
// and the SID is part of the key derivation, so it is recovered from the parent
// directory name. Without it the hash cannot be cracked, which is why a file
// outside that layout is rejected rather than emitted with a placeholder.
//
// Context 1 vs 2 is the local/domain distinction; both are emitted as context 1
// (local), which is what DPAPImk2john defaults to for a standalone file.

/// Fixed-size preamble: version, two unknowns, the UTF-16 GUID, three more
/// unknowns, then the four blob lengths.
const GUID_LEN: usize = 72;
const HEADER_LEN: usize = 4 + 4 + 4 + GUID_LEN + 4 + 4 + 4 + 8 * 4;

pub fn convert(data: &[u8], filename: &str) -> Option<Vec<String>> {
    if data.len() < HEADER_LEN {
        return None;
    }
    let sid = sid_from_path(filename)?;

    // Blob lengths follow the header's fixed fields.
    let lengths_off = 4 + 4 + 4 + GUID_LEN + 4 + 4 + 4;
    let masterkey_len = u64_le(data, lengths_off) as usize;
    if masterkey_len < 32 || masterkey_len > data.len() {
        return None;
    }

    let mk = data.get(HEADER_LEN..HEADER_LEN.checked_add(masterkey_len)?)?;

    // MasterKey blob: version, salt[16], rounds, hashAlgo, cryptAlgo, ciphertext
    let mk_version = u32_le(mk, 0);
    let salt = mk.get(4..20)?;
    let rounds = u32_le(mk, 20);
    let hash_algo = u32_le(mk, 24);
    let crypt_algo = u32_le(mk, 28);
    let ciphertext = mk.get(32..)?;

    if rounds == 0 || ciphertext.is_empty() {
        return None;
    }

    // ALG_ID constants from wincrypt.h.
    let hash = match hash_algo {
        0x8004 => "sha1",
        0x800e => "sha512",
        _ => return None,
    };
    let cipher = match crypt_algo {
        0x6603 => "des3",
        0x6610 => "aes256",
        _ => return None,
    };
    // The two supported combinations pin the version, so a mismatch means the
    // blob was misparsed rather than being an exotic variant.
    let version = match (cipher, hash) {
        ("des3", "sha1") => 1,
        ("aes256", "sha512") => 2,
        _ => return None,
    };
    if mk_version != version {
        return None;
    }

    Some(vec![format!(
        "$DPAPImk${}*1*{}*{}*{}*{}*{}*{}*{}",
        version,
        sid,
        cipher,
        hash,
        rounds,
        to_hex(salt),
        ciphertext.len() * 2,
        to_hex(ciphertext)
    )])
}

/// The parent directory of a master key file is the owner's SID.
fn sid_from_path(path: &str) -> Option<String> {
    let parent = std::path::Path::new(path).parent()?.file_name()?;
    let sid = parent.to_string_lossy();
    // S-1-5-21-... — reject anything that is not shaped like a SID, since a
    // wrong value produces a hash that silently never cracks.
    if sid.starts_with("S-") && sid.split('-').count() >= 4 {
        Some(sid.to_string())
    } else {
        None
    }
}
