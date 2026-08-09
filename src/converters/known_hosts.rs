use crate::common::b64_decode;

// Hashed SSH known_hosts entries -> $known_hosts$ (john only).
//
//   |1|<base64 salt>|<base64 HMAC-SHA1>  hostname-key...
//
// hashcat has no mode for this: -m 160 is HMAC-SHA1 but takes a raw-text salt,
// and the salt here is 20 binary bytes. The previous implementation emitted a
// "$sshng$..." line, which collides with the SSH *private key* format and would
// be fed to the wrong kernel entirely.

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;
    let mut hashes = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with("|1|") {
            continue; // plaintext host entry: nothing to crack
        }
        // The entry proper is the first whitespace-delimited token.
        let entry = line.split_whitespace().next()?;
        let parts: Vec<&str> = entry.split('|').collect();
        // ["", "1", salt, hash]
        if parts.len() != 4 {
            continue;
        }
        // Both components must be real base64 of the right length, or this is
        // not a hashed entry.
        let salt = b64_decode(parts[2]).ok()?;
        let digest = b64_decode(parts[3]).ok()?;
        if salt.len() != 20 || digest.len() != 20 {
            continue;
        }
        hashes.push(format!("$known_hosts${}", entry));
    }
    if hashes.is_empty() { None } else { Some(hashes) }
}
