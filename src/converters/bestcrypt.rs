use crate::common::{to_hex, u32_le};

// BestCrypt v8 containers -> $BestCrypt$ (john).
//
//   $BestCrypt$<fmt>$<keygen id>$<version>$<iterations>$<alg>$<mode>$<hash>
//              $<salt size>$<salt>$1$<key slot>
//
// Layout of DATA_BLOCK (little-endian, unpadded), from bestcrypt2john:
//
//   0    jmpCode[3]        43  volumeLabel[11]   128  alg_id
//   3    signature[8]      54  wKeyGenId         132  mode_id
//   11   cid[4]            56  wVersion          136  hash_id
//   15   occupiedTag[28]   58  iterations        140  keymap[512]
//   ...                                          1536 keys[2560]
//
// hashcat's -m 23900/-m 24000 use a different, narrower `$bcve$` encoding — an
// 8-byte salt and a 96-byte slot, where this format carries 32/64 and 256. That
// mapping is not documented and cannot be derived from the header without a
// reference container to check against, so it is deliberately not emitted:
// a wrong guess produces a well-formed hash that silently never cracks.

const SIGNATURE: &[u8] = b"LOCOS94 ";
const VOLUME_LABEL: &[u8] = b"BC_KeyGenID";

const OFF_SIGNATURE: usize = 3;
const OFF_VOLUME_LABEL: usize = 43;
const OFF_KEYGEN_ID: usize = 54;
const OFF_VERSION: usize = 56;
const OFF_ITERATIONS: usize = 58;
const OFF_ALG_ID: usize = 128;
const OFF_MODE_ID: usize = 132;
const OFF_HASH_ID: usize = 136;
const OFF_KEYMAP: usize = 140;
const OFF_KEYS: usize = 1536;

const KEYMAP_ENTRY: usize = 8;
const KEY_SLOT_SIZE: usize = 256;
/// The struct reserves room for ten slots.
const MAX_SLOTS: usize = 10;

const KGID: u16 = 4;
const KGID_V5: u16 = 5;

const ALG_RIJNDAEL: u32 = 240;
const MODE_CBC: u32 = 0xBC00_0002;
const MODE_XTS: u32 = 0xBC00_0004;

const HASH_SHA256: u32 = 0x80;
const HASH_WHIRLPOOL512: u32 = 0x81;
const HASH_SHA512: u32 = 10;

// Key slot types that hold no crackable key.
const KEY_TYPE_EMPTY: i16 = 0;
const KEY_TYPE_SALT: i16 = 5;
const KEY_TYPE_PART: i16 = -1;

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    if data.len() < OFF_KEYS + KEY_SLOT_SIZE {
        return None;
    }
    // An encrypted header has neither marker; john does not support those
    // either, so bail rather than emit noise.
    if data.get(OFF_SIGNATURE..OFF_SIGNATURE + SIGNATURE.len())? != SIGNATURE {
        return None;
    }
    if data.get(OFF_VOLUME_LABEL..OFF_VOLUME_LABEL + VOLUME_LABEL.len())? != VOLUME_LABEL {
        return None;
    }

    let keygen_id = u16_at(data, OFF_KEYGEN_ID)?;
    let version_field = u16_at(data, OFF_VERSION)?;
    let iterations = u32_le(data, OFF_ITERATIONS);

    // On pre-V5 keygens the version shares storage with the iteration count.
    let resolved_version = if keygen_id == KGID_V5 {
        version_field as u32
    } else {
        if iterations != 3 || keygen_id != KGID {
            return None;
        }
        iterations
    };

    let alg_id = u32_le(data, OFF_ALG_ID);
    if alg_id != ALG_RIJNDAEL {
        return None;
    }
    let mode_id = u32_le(data, OFF_MODE_ID);
    if mode_id != MODE_CBC && mode_id != MODE_XTS {
        return None;
    }
    let hash_id = u32_le(data, OFF_HASH_ID);
    let salt_size = match hash_id {
        HASH_SHA256 => 32,
        HASH_WHIRLPOOL512 | HASH_SHA512 => 64,
        _ => return None,
    };

    let keymap = data.get(OFF_KEYMAP..OFF_KEYMAP + MAX_SLOTS * KEYMAP_ENTRY)?;
    let keys = data.get(OFF_KEYS..)?;
    let salt = keys.get(..salt_size)?;

    // Slot 0 holds the salt by construction; anything else means a misparse.
    if slot_type(keymap, 0)? != KEY_TYPE_SALT {
        return None;
    }

    let mut out = Vec::new();
    for slot in 0..MAX_SLOTS {
        let ty = slot_type(keymap, slot)?;
        if ty == KEY_TYPE_EMPTY || ty == KEY_TYPE_SALT || ty == KEY_TYPE_PART {
            continue;
        }
        let Some(key) = keys.get(slot * KEY_SLOT_SIZE..(slot + 1) * KEY_SLOT_SIZE) else {
            break;
        };
        // One hash per active key slot: any of them opens the container.
        out.push(format!(
            "$BestCrypt$1${}${}${}${}${}${}${}${}$1${}",
            keygen_id,
            resolved_version,
            iterations,
            alg_id,
            mode_id,
            hash_id,
            salt_size,
            to_hex(salt),
            to_hex(key)
        ));
    }
    if out.is_empty() { None } else { Some(out) }
}

/// keymap entry is `{ u16 size; i16 type; u32 param }`.
fn slot_type(keymap: &[u8], slot: usize) -> Option<i16> {
    let off = slot * KEYMAP_ENTRY + 2;
    let b = keymap.get(off..off + 2)?;
    Some(i16::from_le_bytes(b.try_into().ok()?))
}

fn u16_at(data: &[u8], off: usize) -> Option<u16> {
    let b = data.get(off..off + 2)?;
    Some(u16::from_le_bytes(b.try_into().ok()?))
}
