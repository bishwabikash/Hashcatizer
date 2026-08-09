use crate::common::{b64_decode, to_hex};

// Atmail {SSHA256} password hashes -> john's $dynamic_62$.
//
//   $dynamic_62$<sha256 hex>$HEX$<salt hex>
//
// The stored value is base64 of digest||salt. The previous implementation
// passed through any line containing a colon, which made it match SQL dumps,
// config files and CSV alike.

const TAG: &str = "{SSHA256}";
const DIGEST_LEN: usize = 32;

pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;
    let mut hashes = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        // Either "user:{SSHA256}<b64>" or a bare "{SSHA256}<b64>".
        let (user, encoded) = match line.split_once(TAG) {
            Some((prefix, rest)) => (prefix.strip_suffix(':').filter(|u| !u.is_empty()), rest),
            None => continue,
        };
        let Ok(raw) = b64_decode(encoded.trim()) else {
            continue;
        };
        // Anything shorter than the digest cannot carry a salt after it.
        if raw.len() <= DIGEST_LEN {
            continue;
        }
        let hash = format!(
            "$dynamic_62${}$HEX${}",
            to_hex(&raw[..DIGEST_LEN]),
            to_hex(&raw[DIGEST_LEN..])
        );
        hashes.push(match user {
            Some(u) => format!("{}:{}", u, hash),
            None => hash,
        });
    }
    if hashes.is_empty() { None } else { Some(hashes) }
}
