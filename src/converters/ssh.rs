use crate::common::to_hex;

// SSH private keys -> $sshng$, matching John the Ripper's ssh2john.py.
//
//   legacy PEM:  $sshng$<cipher>$<saltlen>$<salt>$<datalen>$<data>
//   OpenSSH v1:  $sshng$<cipher>$<saltlen>$<salt>$<datalen>$<data>$<rounds>$<ctoff>
//
// Only the six-token legacy form is crackable by hashcat (modes 22911-22951).
// The eight-token form covers modern bcrypt-pbkdf keys — the default output of
// today's ssh-keygen — which hashcat has no kernel for; those are john-only.
// `hashcat_mode` below is what tells the caller which case it is landed in.
//
// The whole key blob is emitted, never a prefix: the cracker decrypts the full
// buffer and validates its trailing structure, so a truncated hash cannot be
// cracked even though it looks well-formed.

const AUTH_MAGIC: &[u8] = b"openssh-key-v1";

/// Key type, mirroring ssh2john's `ktype`. The cipher id depends on it.
#[derive(Clone, Copy, PartialEq)]
enum KeyType {
    Rsa = 0,
    Dsa = 1,
    OpenSsh = 2,
    Ec = 3,
}

pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    let text = std::str::from_utf8(data).ok()?;
    let mut out = Vec::new();

    for (tag, ktype) in blocks(text) {
        let hash = if ktype == KeyType::OpenSsh {
            parse_openssh(text, &tag)
        } else {
            parse_pem_legacy(text, &tag, ktype)
        };
        if let Some(h) = hash {
            out.push(h);
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

/// Which hashcat mode, if any, can crack a hash this converter produced.
/// Returns None for bcrypt-pbkdf keys, which only john handles.
pub fn hashcat_mode(hash: &str) -> Option<&'static str> {
    let fields: Vec<&str> = hash.split('$').collect();
    // ["", "sshng", cipher, saltlen, salt, datalen, data, (rounds, ctoff)]
    if fields.len() > 7 {
        return None; // OpenSSH bcrypt-pbkdf: john only
    }
    match *fields.get(2)? {
        "0" => Some("22911"),
        "6" => Some("22921"),
        "1" | "3" => Some("22931"),
        "4" => Some("22941"),
        "5" => Some("22951"),
        _ => None,
    }
}

/// Every PEM block in the file, in order, with its key type.
fn blocks(text: &str) -> Vec<(String, KeyType)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let k = if line.contains("BEGIN RSA PRIVATE") {
            (("RSA"), KeyType::Rsa)
        } else if line.contains("BEGIN DSA PRIVATE KEY") {
            ("DSA", KeyType::Dsa)
        } else if line.contains("BEGIN OPENSSH PRIVATE KEY") {
            ("OPENSSH", KeyType::OpenSsh)
        } else if line.contains("BEGIN EC PRIVATE KEY") {
            ("EC", KeyType::Ec)
        } else {
            continue;
        };
        out.push((k.0.to_string(), k.1));
    }
    out
}

/// RFC 1421 headers as lowercased (key, value) pairs.
type PemHeaders = Vec<(String, String)>;

/// Base64 body of a `-----BEGIN <tag> PRIVATE KEY-----` block, plus any
/// RFC 1421 headers (`Proc-Type`, `DEK-Info`) that precede it.
fn block_body(text: &str, tag: &str) -> Option<(Vec<u8>, PemHeaders)> {
    let begin = format!("-----BEGIN {} PRIVATE KEY-----", tag);
    let end = format!("-----END {} PRIVATE KEY-----", tag);
    // Start at the newline after the marker, otherwise the empty remainder of
    // the BEGIN line reads as a blank line and ends header parsing early.
    let marker = text.find(&begin)? + begin.len();
    let start = marker + text[marker..].find('\n').map_or(0, |i| i + 1);
    let stop = text[start..].find(&end)? + start;

    let mut headers = Vec::new();
    let mut b64 = String::new();
    let mut in_headers = true;
    for line in text[start..stop].lines() {
        let line = line.trim();
        if line.is_empty() {
            in_headers = false;
            continue;
        }
        if in_headers {
            if let Some((k, v)) = line.split_once(": ") {
                headers.push((k.to_lowercase(), v.trim().to_string()));
                continue;
            }
            in_headers = false;
        }
        b64.push_str(line);
    }
    let raw = crate::common::b64_decode(&b64).ok()?;
    Some((raw, headers))
}

fn parse_pem_legacy(text: &str, tag: &str, ktype: KeyType) -> Option<String> {
    let (raw, headers) = block_body(text, tag)?;
    let get = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    // No Proc-Type means the key is not encrypted, so there is nothing to crack.
    get("proc-type")?;
    let (cipher, salt) = get("dek-info")?.split_once(',')?;
    let keysize = keysize(cipher)?;
    let salt_len = salt.len() / 2;

    // Branch order is load-bearing: it reproduces ssh2john's ladder exactly, so
    // the cipher id matches what the crackers expect for each key type.
    let cipher_id = if keysize == 24 && cipher == "AES-192-CBC" && is_rsa_dsa(ktype) {
        4
    } else if keysize == 32 && cipher == "AES-256-CBC" && (is_rsa_dsa(ktype) || ktype == KeyType::Ec)
    {
        5
    } else if keysize == 24 {
        0
    } else if keysize == 8 && salt_len == 8 {
        6
    } else if keysize == 16 && is_rsa_dsa(ktype) {
        1
    } else if keysize == 16 && ktype == KeyType::Ec {
        3
    } else {
        return None;
    };

    Some(format!(
        "$sshng${}${}${}${}${}",
        cipher_id,
        salt_len,
        salt,
        raw.len(),
        to_hex(&raw)
    ))
}

fn parse_openssh(text: &str, tag: &str) -> Option<String> {
    let (raw, _) = block_body(text, tag)?;
    if !raw.starts_with(AUTH_MAGIC) {
        return None;
    }
    // The magic is stored NUL-terminated.
    let mut off = AUTH_MAGIC.len() + 1;

    let len = be_u32(&raw, off)? as usize;
    off += 4;
    let cipher_name = std::str::from_utf8(raw.get(off..off.checked_add(len)?)?).ok()?;
    let cipher = match cipher_name {
        "none" => return None, // unencrypted
        "aes256-cbc" => "AES-256-CBC",
        "aes256-ctr" => "AES-256-CTR",
        _ => return None,
    };
    off += len;

    let len = be_u32(&raw, off)? as usize; // kdfname
    off = off.checked_add(4)?.checked_add(len)?;

    let kdf_len = be_u32(&raw, off)? as usize;
    // Skip the kdfoptions length and the salt's own length prefix inside it.
    let salt_offset = off.checked_add(8)?;
    off = off.checked_add(4)?.checked_add(kdf_len)?;

    // ssh2john's walk to the ciphertext: skip the key count, then step over the
    // public key blob by its own length prefix. This offset is a field in the
    // hash, so it has to match john's arithmetic exactly.
    off = off.checked_add(4)?; // past the key count, onto the public key blob
    let len = be_u32(&raw, off)? as usize; // public key blob length
    off = off.checked_add(4)?.checked_add(len)?;
    off = off.checked_add(4)?; // past the encrypted blob's own length field
    if off > raw.len() {
        return None;
    }
    let ciphertext_begin_offset = off;

    let salt = raw.get(salt_offset..salt_offset.checked_add(16)?)?;
    let rounds = be_u32(&raw, salt_offset + 16)?;

    let cipher_id = match cipher {
        "AES-256-CBC" => 2,
        _ => 6,
    };

    Some(format!(
        "$sshng${}${}${}${}${}${}${}",
        cipher_id,
        salt.len(),
        to_hex(salt),
        raw.len(),
        to_hex(&raw),
        rounds,
        ciphertext_begin_offset
    ))
}

fn is_rsa_dsa(k: KeyType) -> bool {
    k == KeyType::Rsa || k == KeyType::Dsa
}

fn keysize(cipher: &str) -> Option<usize> {
    Some(match cipher {
        "AES-128-CBC" => 16,
        "DES-EDE3-CBC" => 24,
        "AES-192-CBC" => 24,
        "AES-256-CBC" => 32,
        "AES-256-CTR" => 32,
        "DES-CBC" => 8,
        _ => return None,
    })
}

fn be_u32(data: &[u8], off: usize) -> Option<u32> {
    let b = data.get(off..off.checked_add(4)?)?;
    Some(u32::from_be_bytes(b.try_into().ok()?))
}
