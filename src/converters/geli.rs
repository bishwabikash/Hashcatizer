use crate::common::{to_hex, u32_le, u64_le};

// FreeBSD GELI providers -> $geli$ (john only — hashcat has no GELI kernel;
// the 16800 this was previously advertised as is WPA-PMKID-PBKDF2).
//
//   $geli$0$<version>$<ealgo>$<keylen>$<aalgo>$<keys>$<iterations>$<salt>$<mkeys>
//
// The metadata block lives in the provider's last sector, so a full disk image
// is scanned backwards for the magic rather than assuming offset 0.

const MAGIC: &[u8] = b"GEOM::ELI";
const SALT_LEN: usize = 64;
const MKEYS_LEN: usize = 384;

/// v1+ layout: magic[16] version flags ealgo keylen aalgo provsize sectorsize
/// keys iterations salt[64] mkeys[384] hash[16]
const V1_SIZE: usize = 16 + 4 + 4 + 2 + 2 + 2 + 8 + 4 + 1 + 4 + SALT_LEN + MKEYS_LEN + 16;
/// v0 is the same without the md_aalgo field.
const V0_SIZE: usize = V1_SIZE - 2;

/// Ciphers john knows how to attack: AES-XTS and AES-CBC.
const CRYPTO_AES_XTS: u16 = 22;
const CRYPTO_AES_CBC: u16 = 11;

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let start = find_magic(data)?;
    let block = data.get(start..)?;

    let version = u32_le(block, 16);
    if version > 7 {
        return None;
    }

    // md_aalgo only exists from v1 onwards; every later field shifts by two.
    let has_aalgo = version != 0;
    let need = if has_aalgo { V1_SIZE } else { V0_SIZE };
    if block.len() < need {
        return None;
    }

    let ealgo = u16_at(block, 24)?;
    let keylen = u16_at(block, 26)?;
    let (aalgo, mut off) = if has_aalgo {
        (u16_at(block, 28)?, 30)
    } else {
        (0, 28)
    };
    if ealgo != CRYPTO_AES_XTS && ealgo != CRYPTO_AES_CBC {
        return None;
    }

    let _provsize = u64_le(block, off);
    off += 8;
    let _sectorsize = u32_le(block, off);
    off += 4;
    let keys = *block.get(off)?;
    off += 1;
    let iterations = u32_le(block, off) as i32;
    off += 4;

    let salt = block.get(off..off + SALT_LEN)?;
    off += SALT_LEN;
    let mkeys = block.get(off..off + MKEYS_LEN)?;

    Some(vec![format!(
        "$geli$0${}${}${}${}${}${}${}${}",
        version,
        ealgo,
        keylen,
        aalgo,
        keys,
        iterations,
        to_hex(salt),
        to_hex(mkeys)
    )])
}

/// GELI metadata sits in the final sector, so search from the end.
fn find_magic(data: &[u8]) -> Option<usize> {
    data.windows(MAGIC.len())
        .rposition(|w| w == MAGIC)
        .filter(|&p| data.len() - p >= V0_SIZE)
}

fn u16_at(data: &[u8], off: usize) -> Option<u16> {
    let b = data.get(off..off + 2)?;
    Some(u16::from_le_bytes(b.try_into().ok()?))
}
