use crate::common::b64_decode;

// ejabberd SCRAM credentials -> hashcat -m 23200.
//
//   $xmpp-scram$0$<iterations>$<salt length>$<salt hex>$<stored key>
//
// ejabberd spool files are Erlang terms. Rather than parse Erlang, the SCRAM
// record is matched on its shape:
//
//   {scram,"<StoredKey b64>","<ServerKey b64>","<Salt b64>",<IterationCount>}
//
// StoredKey and Salt are base64 there but hex in the hash, so both are decoded.

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;
    let mut out = Vec::new();

    for start in find_all(text, "{scram,") {
        let rest = &text[start + "{scram,".len()..];
        let Some(end) = rest.find('}') else { continue };
        let fields = split_erlang(&rest[..end]);
        if fields.len() < 4 {
            continue;
        }
        let (Ok(stored), Ok(salt)) = (b64_decode(&fields[0]), b64_decode(&fields[2])) else {
            continue;
        };
        let iterations = fields[3].trim();
        if iterations.is_empty() || !iterations.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if stored.is_empty() || salt.is_empty() {
            continue;
        }
        out.push(format!(
            "$xmpp-scram$0${}${}${}${}",
            iterations,
            salt.len(),
            hex::encode(&salt),
            hex::encode(&stored)
        ));
    }
    if out.is_empty() { None } else { Some(out) }
}

fn find_all(haystack: &str, needle: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(i) = haystack[from..].find(needle) {
        out.push(from + i);
        from += i + needle.len();
    }
    out
}

/// Split a comma-separated Erlang term list, stripping the quotes around
/// binaries and leaving bare terms alone.
fn split_erlang(body: &str) -> Vec<String> {
    body.split(',')
        .map(|f| f.trim().trim_matches('"').trim_matches('<').trim_matches('>').to_string())
        .collect()
}
