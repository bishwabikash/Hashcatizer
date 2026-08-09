use crate::common::to_hex;

// Files produced by `openssl enc` -> $openssl$, matching openssl2john.py.
//
//   $openssl$<cipher>$<md>$8$<salt>$<tail>$<short>[$<len>$<head>]$<check>
//
// The cipher and digest are unknown from the file alone (OpenSSL stores only
// the salt), so both are emitted as 0 and the cracker sweeps them. `check` is 0
// meaning "no known plaintext"; john also accepts a plaintext or an ASCII-ratio
// heuristic there, neither of which can be derived from the ciphertext.
//
// hashcat has no mode for this format — it is john-only.

const MAGIC: &[u8] = b"Salted__";

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    // A private key would be handled by the pem converter, not this one.
    if find(data, b"PRIVATE KEY-----").is_some() {
        return None;
    }

    // `openssl enc -a` wraps the container in base64.
    let owned;
    let data = if data.starts_with(MAGIC) {
        data
    } else {
        let text = std::str::from_utf8(data).ok()?;
        owned = crate::common::b64_decode(&text.replace(['\n', '\r'], "")).ok()?;
        if !owned.starts_with(MAGIC) {
            return None;
        }
        &owned
    };

    if data.len() < 32 {
        return None;
    }
    let salt = to_hex(data.get(8..16)?);
    let remaining = data.len() - 16;

    // Short payloads carry no usable interior block, so only the final block is
    // recorded and the "short" flag tells the cracker to expect that.
    let hash = if remaining <= 16 {
        let tail = to_hex(data.get(data.len() - 16..)?);
        format!("$openssl$0$0$8${}${}$1$0", salt, tail)
    } else {
        let tail = to_hex(data.get(data.len() - 32..)?);
        let head = data.get(16..(16 * 17).min(data.len()))?;
        format!(
            "$openssl$0$0$8${}${}$0${}${}$0",
            salt,
            tail,
            head.len(),
            to_hex(head)
        )
    };
    Some(vec![hash])
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
