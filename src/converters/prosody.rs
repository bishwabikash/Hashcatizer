use crate::common::to_hex;

// Prosody XMPP SCRAM credentials -> hashcat -m 23200.
//
//   $xmpp-scram$0$<iterations>$<salt length>$<salt hex>$<stored key>
//
// Prosody stores accounts as Lua tables in .dat files; the three fields needed
// are picked out by key rather than by parsing Lua. The salt is stored as raw
// text and hex-encoded here, which is what fixes the length field: it is the
// byte length of the salt, not of its hex representation.

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;

    let iterations = lua_value(text, "iteration_count")?;
    let stored_key = lua_value(text, "stored_key")?;
    let salt = lua_value(text, "salt")?;

    if !iterations.chars().all(|c| c.is_ascii_digit()) || iterations.is_empty() {
        return None;
    }
    if stored_key.is_empty() || !stored_key.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let salt_hex = to_hex(salt.as_bytes());

    Some(vec![format!(
        "$xmpp-scram$0${}${}${}${}",
        iterations,
        salt.len(),
        salt_hex,
        stored_key
    )])
}

/// Value of `key = "..."` or `key = 4096` in a Lua table.
fn lua_value(text: &str, key: &str) -> Option<String> {
    let idx = text.find(key)?;
    let rest = &text[idx + key.len()..];
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();

    if let Some(quoted) = rest.strip_prefix('"') {
        let end = quoted.find('"')?;
        Some(quoted[..end].to_string())
    } else {
        let end = rest
            .find(|c: char| !c.is_ascii_alphanumeric())
            .unwrap_or(rest.len());
        Some(rest[..end].to_string())
    }
}
