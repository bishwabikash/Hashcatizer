use crate::common::{b64_decode, to_hex};

// VirtualBox disk encryption -> hashcat -m 27500 (AES-XTS128) / -m 27600 (AES-XTS256).
//
//   $vbox$0$<iter1>$<salt1>$<keylen>$<enc_pass>$<iter2>$<salt2>$<final>
//
// The key material lives in the *.vbox XML, not the .vdi: VirtualBox stores it
// base64-encoded in a `CRYPT/KeyStore` property. Decoded, it is an "SCNE" blob
// whose layout comes from vdi2john.pl:
//
//   magic[4] version[2] algorithm[32] kdf[32] gen_keylen[4] final[32]
//   keylen[4] salt2[32] salt2_iter[4] salt1[32] salt1_iter[4]
//   evp_len[4] enc_pass[evp_len]
//
// `keylen` in the hash line is hashcat's per-mode discriminator (8 for XTS128,
// 16 for XTS256), not a byte count — module_27500.c rejects anything else.

const MAGIC: &[u8] = b"SCNE";
const VERSION: u16 = 0x0100;
const FIELD: usize = 32;

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;
    let mut out = Vec::new();

    for encoded in keystore_values(text) {
        if let Some(hash) = parse_keystore(&encoded) {
            out.push(hash);
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

/// Every `value="..."` belonging to a CRYPT/KeyStore property. VirtualBox
/// escapes the newlines it wraps the base64 with.
fn keystore_values(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (i, _) in text.match_indices("CRYPT/KeyStore") {
        // The value may be on the same element or the following line.
        let window = &text[i..text.len().min(i + 8192)];
        if let Some(v) = window.find("value=\"") {
            let rest = &window[v + 7..];
            if let Some(end) = rest.find('"') {
                out.push(rest[..end].replace("&#13;&#10;", "").replace(['\n', '\r'], ""));
            }
        }
    }
    out
}

fn parse_keystore(encoded: &str) -> Option<String> {
    let blob = b64_decode(encoded).ok()?;
    if !blob.starts_with(MAGIC) {
        return None;
    }
    if u16::from_be_bytes(blob.get(4..6)?.try_into().ok()?) != VERSION {
        return None;
    }
    let mut r = Cursor { data: &blob, pos: 6 };

    let algorithm = r.take(FIELD)?;
    let kdf = r.take(FIELD)?;
    let _gen_keylen = r.u32()?;
    let final_key = r.take(FIELD)?;
    let _keylen = r.u32()?;
    let salt2 = r.take(FIELD)?;
    let salt2_iter = r.u32()?;
    let salt1 = r.take(FIELD)?;
    let salt1_iter = r.u32()?;
    let evp_len = r.u32()? as usize;
    let enc_pass = r.take(evp_len)?;

    // Only PBKDF2-SHA256 with AES-XTS is implemented by either cracker.
    if !starts_with_str(kdf, "PBKDF2-SHA256") {
        return None;
    }
    let aes_key_len = if starts_with_str(algorithm, "AES-XTS128-PLAIN64") {
        8
    } else if starts_with_str(algorithm, "AES-XTS256-PLAIN64") {
        16
    } else {
        return None;
    };
    // hashcat's parser requires exactly 32 bytes here.
    if enc_pass.len() != FIELD {
        return None;
    }

    Some(format!(
        "$vbox$0${}${}${}${}${}${}${}",
        salt1_iter,
        to_hex(salt1),
        aes_key_len,
        to_hex(enc_pass),
        salt2_iter,
        to_hex(salt2),
        to_hex(final_key)
    ))
}

/// The fixed-width name fields are NUL-padded.
fn starts_with_str(field: &[u8], name: &str) -> bool {
    field.starts_with(name.as_bytes())
        && field.get(name.len()).is_none_or(|&b| b == 0)
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
}
