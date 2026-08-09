use crate::common::{b64_decode, to_hex, u32_le};

// FileVault 2 / CoreStorage -> hashcat -m 16700.
//
//   $fvde$1$<salt len>$<salt>$<iterations>$<kek>
//
// Input is the decrypted `EncryptedRoot.plist.wipekey`, which holds one
// `PassphraseWrappedKEKStruct` per enabled user. Within that struct
// (offsets from fvde2john):
//
//   [8..24]    salt        (16 bytes)
//   [32..56]   wrapped KEK (24 bytes)
//   [168..172] PBKDF2 iterations (LE u32)
//
// Extracting the plist from a raw disk image needs the CoreStorage metadata
// walk plus the wipe key, which is a separate step (`fvde2john` does it with a
// filesystem driver); this converter takes the decrypted plist, which is what
// that step produces.

const KEY_NAME: &str = "PassphraseWrappedKEKStruct";
const SALT: (usize, usize) = (8, 24);
const KEK: (usize, usize) = (32, 56);
const ITERATIONS_OFF: usize = 168;
/// The struct must extend past the iterations field to be usable.
const MIN_STRUCT: usize = ITERATIONS_OFF + 4;

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();

    // A plist (XML or binary) carrying one or more wrapped KEKs.
    if let Ok(text) = std::str::from_utf8(data) {
        for encoded in plist_data_values(text, KEY_NAME) {
            if let Ok(raw) = b64_decode(&encoded) {
                if let Some(h) = build_hash(&raw) {
                    out.push(h);
                }
            }
        }
    }

    // Or the struct on its own, as produced by other extraction tooling.
    if out.is_empty() {
        if let Some(h) = build_hash(data) {
            out.push(h);
        }
    }

    if out.is_empty() { None } else { Some(out) }
}

fn build_hash(s: &[u8]) -> Option<String> {
    if s.len() < MIN_STRUCT {
        return None;
    }
    let salt = s.get(SALT.0..SALT.1)?;
    let kek = s.get(KEK.0..KEK.1)?;
    let iterations = u32_le(s, ITERATIONS_OFF);

    // A real FileVault volume uses tens of thousands of rounds; a zero or wild
    // value means this is not a wrapped-KEK struct.
    if !(1_000..=10_000_000).contains(&iterations) {
        return None;
    }
    // An all-zero salt marks an unused user slot.
    if salt.iter().all(|&b| b == 0) {
        return None;
    }

    Some(format!(
        "$fvde$1${}${}${}${}",
        salt.len(),
        to_hex(salt),
        iterations,
        to_hex(kek)
    ))
}

/// Every `<data>` payload following a given `<key>` in an XML plist.
fn plist_data_values(text: &str, key: &str) -> Vec<String> {
    let needle = format!("<key>{}</key>", key);
    let mut out = Vec::new();

    for (i, _) in text.match_indices(&needle) {
        let rest = &text[i + needle.len()..];
        let Some(open) = rest.find("<data>") else {
            continue;
        };
        let after = &rest[open + "<data>".len()..];
        let Some(close) = after.find("</data>") else {
            continue;
        };
        out.push(after[..close].split_whitespace().collect());
    }
    out
}
