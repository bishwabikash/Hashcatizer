// AIX /etc/security/passwd entries -> hashcat -m 6300 / 6400 / 6500 / 6700.
//
//   {smd5}<salt>$<hash>      -m 6300
//   {ssha256}NN$<salt>$<h>   -m 6400
//   {ssha512}NN$<salt>$<h>   -m 6500
//   {ssha1}NN$<salt>$<h>     -m 6700
//
// The file is stanza-formatted: a "user:" line followed by indented
// "password = ..." attributes, so the hash is taken from the attribute rather
// than by splitting the line on ':'.

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;
    let mut out = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        // Both "password = {ssha256}..." stanzas and bare hashes are accepted.
        let value = match line.split_once('=') {
            Some((key, v)) if key.trim() == "password" => v.trim(),
            _ => line,
        };
        if scheme(value).is_some() {
            out.push(value.to_string());
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

/// hashcat mode for an AIX hash, or None if the prefix is not one we know.
pub fn scheme(value: &str) -> Option<&'static str> {
    // A bare "*" or "!" means the account is locked, not hashed.
    if !value.starts_with('{') {
        return None;
    }
    let (tag, rest) = value[1..].split_once('}')?;
    if rest.is_empty() {
        return None;
    }
    match tag {
        "smd5" => Some("6300"),
        "ssha256" => Some("6400"),
        "ssha512" => Some("6500"),
        "ssha1" => Some("6700"),
        _ => None,
    }
}
