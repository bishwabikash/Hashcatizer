// eCryptfs wrapped-passphrase files -> hashcat -m 12200.
//
//   $ecryptfs$0$<sig>              default salt
//   $ecryptfs$0$1$<salt>$<sig>     variable salt (file format v2)
//
// The file is tiny and its shape is what identifies the version: v2 starts with
// the two bytes ":\x02" followed by an 8-byte salt and a 16-character signature;
// v1 is just the 16-character signature. The old implementation hex-dumped 56
// bytes into both fields, which matches neither.

use crate::common::to_hex;

const V2_MARKER: [u8; 2] = [b':', 0x02];
const SIG_LEN: usize = 16;
const SALT_LEN: usize = 8;

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let version = data.get(..2)?;

    if version == V2_MARKER {
        let salt = data.get(2..2 + SALT_LEN)?;
        let sig = data.get(2 + SALT_LEN..2 + SALT_LEN + SIG_LEN)?;
        let sig = std::str::from_utf8(sig).ok()?;
        if !is_signature(sig) {
            return None;
        }
        Some(vec![format!("$ecryptfs$0$1${}${}", to_hex(salt), sig)])
    } else {
        let sig = std::str::from_utf8(data.get(..SIG_LEN)?).ok()?;
        if !is_signature(sig) {
            return None;
        }
        Some(vec![format!("$ecryptfs$0${}", sig)])
    }
}

/// The signature is 16 hex characters; requiring that keeps this from matching
/// arbitrary 16-byte files.
fn is_signature(s: &str) -> bool {
    s.len() == SIG_LEN && s.chars().all(|c| c.is_ascii_hexdigit())
}
