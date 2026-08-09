use crate::common::to_hex;

// Apache htdigest files -> john's $dynamic_4$ (MD5 of "user:realm:pass").
//
//   $dynamic_4$<md5hex>$HEX$<hex of "user:realm:">
//
// hashcat has no htdigest mode: -m 11400 is live SIP/HTTP digest challenge
// material, which is a different computation. The file line is
// "username:realm:md5hex".

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;
    let mut out = Vec::new();

    for line in text.lines() {
        let line = line.trim_end();
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() != 3 {
            continue;
        }
        let (user, realm, digest) = (parts[0], parts[1], parts[2]);
        // The third field must be a real MD5 or this is some other passwd file.
        if digest.len() != 32 || !digest.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        if user.is_empty() {
            continue;
        }
        let salt = format!("{}:{}:", user, realm);
        out.push(format!("$dynamic_4${}$HEX${}", digest, to_hex(salt.as_bytes())));
    }
    if out.is_empty() { None } else { Some(out) }
}
