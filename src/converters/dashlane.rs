use crate::common::to_hex;

// Dashlane vaults -> $dashlane$ (john only; see docs/HASHCAT_GAPS.md).
//
//   $dashlane$<v>*<salt>*<len>*<data>
//
// v=0 plain .aes database, v=1 when the payload is KWC3-compressed. Only the
// first 256 bytes are needed to crack. A "secure archive" export wraps the same
// bytes in base64 after a "Data BEGIN" marker.

const SALT_LEN: usize = 32;
const KWC3: &[u8] = b"KWC3";
const PREFIX_LEN: usize = 256;

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let owned;
    let data = match secure_archive_payload(data) {
        Some(decoded) => {
            owned = decoded;
            owned.as_slice()
        }
        None => data.get(..PREFIX_LEN.min(data.len()))?,
    };

    if data.len() < SALT_LEN {
        return None;
    }
    let body = data.get(SALT_LEN..)?;
    // Everything after the salt is AES output (optionally behind a KWC3 marker).
    let probe = body.strip_prefix(KWC3).unwrap_or(body);
    if !crate::common::looks_encrypted(probe, 7.0) {
        return None;
    }
    let salt = data.get(..SALT_LEN)?;

    // The KWC3 marker means the plaintext is compressed; the cracker needs to
    // know that, and the marker itself is not part of the ciphertext.
    let (version, aes_data) = match body.strip_prefix(KWC3) {
        Some(rest) => (1, rest),
        None => (0, body),
    };

    Some(vec![format!(
        "$dashlane${}*{}*{}*{}",
        version,
        to_hex(salt),
        aes_data.len(),
        to_hex(aes_data)
    )])
}

/// Dashlane "secure archive" exports base64 the vault after a `Data BEGIN` line.
fn secure_archive_payload(data: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(data).ok()?;
    let idx = text.find("Data BEGIN")?;
    let line = text[idx..].lines().nth(1)?.trim();
    let decoded = crate::common::b64_decode(line).ok()?;
    Some(decoded.into_iter().take(PREFIX_LEN).collect())
}
