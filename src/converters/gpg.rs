use crate::common::to_hex;

// GnuPG / OpenPGP secret keys -> hashcat -m 17010 ($gpg$).
//
// Supports v4 Secret-Key (tag 5) / Secret-Subkey (tag 7) packets protected with
// an iterated+salted S2K (type 3), S2K usage 254, AES cipher (7/9). Handles both
// binary keyrings (secring.gpg, *.gpg, *.key) and ASCII-armored *.asc input.
//
// Output: $gpg$*<algo>*<datalen>*<bits>*<data_hex>*<spec>*<usage>*<hash_algo>*
//         <cipher_algo>*<iv_len>*<iv_hex>*<count>*<salt_hex>

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let raw = dearmor(data);
    let bytes: &[u8] = raw.as_deref().unwrap_or(data);
    parse_packets(bytes).map(|h| vec![h])
}

/// If the input is an ASCII-armored private key block, strip the armor and
/// base64-decode the body. Returns None for binary input (use bytes as-is).
fn dearmor(data: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(data).ok()?;
    if !text.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----") {
        return None;
    }
    let mut body = String::new();
    let mut in_body = false;
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with("-----BEGIN") { in_body = true; continue; }
        if l.starts_with("-----END") { break; }
        if !in_body { continue; }
        // Skip armor headers, the blank separator line, and the CRC24 checksum.
        if l.is_empty() || l.starts_with('=') || l.contains(':') { continue; }
        body.push_str(l);
    }
    if body.is_empty() { return None; }
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(&body).ok()
}

fn parse_packets(data: &[u8]) -> Option<String> {
    let mut off = 0usize;
    while off < data.len() {
        let tagbyte = data[off];
        if tagbyte & 0x80 == 0 { return None; } // not a valid packet header
        let new_format = tagbyte & 0x40 != 0;
        let (tag, body_start, body_len) = if new_format {
            let tag = tagbyte & 0x3f;
            let (len, p) = read_new_len(data, off + 1)?;
            (tag, p, len)
        } else {
            let tag = (tagbyte >> 2) & 0x0f;
            let ltype = tagbyte & 0x03;
            let (len, p) = read_old_len(data, off + 1, ltype)?;
            (tag, p, len)
        };
        let body_end = body_start.checked_add(body_len)?;
        if body_end > data.len() { return None; }

        if tag == 5 || tag == 7 {
            if let Some(h) = parse_secret_key(&data[body_start..body_end]) {
                return Some(h);
            }
        }
        if body_len == 0 { return None; } // indeterminate length -> bail
        off = body_end;
    }
    None
}

fn parse_secret_key(b: &[u8]) -> Option<String> {
    let mut p = 0usize;
    let version = *b.get(p)?; p += 1;
    if version != 4 { return None; } // only v4 supported
    p += 4; // creation time (4 bytes)
    let algo = *b.get(p)?; p += 1;

    // Public-key MPIs. Record the first modulus bit-length for <bits>.
    let (bits, np) = match algo {
        1..=3 => { // RSA: n, e
            let (nbits, q) = read_mpi(b, p)?;
            let (_ebits, q) = read_mpi(b, q)?;
            (nbits, q)
        }
        16 => { // ElGamal: p, g, y
            let (pbits, q) = read_mpi(b, p)?;
            let (_g, q) = read_mpi(b, q)?;
            let (_y, q) = read_mpi(b, q)?;
            (pbits, q)
        }
        17 => { // DSA: p, q, g, y
            let (pbits, q) = read_mpi(b, p)?;
            let (_q, q) = read_mpi(b, q)?;
            let (_g, q) = read_mpi(b, q)?;
            let (_y, q) = read_mpi(b, q)?;
            (pbits, q)
        }
        _ => return None, // ECC etc. not supported by 17010
    };
    p = np;

    let usage = *b.get(p)?; p += 1;
    if usage != 254 { return None; } // 17010 requires usage 254 (S2K + SHA-1 checksum)

    let cipher_algo = *b.get(p)?; p += 1;
    if cipher_algo != 7 && cipher_algo != 9 { return None; } // AES-128 / AES-256

    let spec = *b.get(p)?; p += 1;
    if spec != 3 { return None; } // iterated + salted S2K

    let hash_algo = *b.get(p)?; p += 1;
    if hash_algo != 2 { return None; } // SHA-1 for 17010

    let salt = b.get(p..p + 8)?; p += 8;
    let coded = *b.get(p)?; p += 1;
    let count: u64 = (16u64 + (coded as u64 & 15)) << ((coded as u64 >> 4) + 6);

    let iv_len = 16usize; // AES block size
    let iv = b.get(p..p + iv_len)?; p += iv_len;

    let enc_data = b.get(p..)?;
    if enc_data.is_empty() { return None; }

    Some(format!(
        "$gpg$*{}*{}*{}*{}*{}*{}*{}*{}*{}*{}*{}*{}",
        algo, enc_data.len(), bits, to_hex(enc_data),
        spec, usage, hash_algo, cipher_algo,
        iv_len, to_hex(iv), count, to_hex(salt)
    ))
}

/// Read an OpenPGP MPI: 2-byte big-endian bit length, then ceil(bits/8) bytes.
/// Returns (bit_length, offset-past-mpi).
fn read_mpi(b: &[u8], off: usize) -> Option<(u32, usize)> {
    let bits = u16::from_be_bytes([*b.get(off)?, *b.get(off + 1)?]) as u32;
    let nbytes = bits.div_ceil(8) as usize;
    let end = off.checked_add(2)?.checked_add(nbytes)?;
    if end > b.len() { return None; }
    Some((bits, end))
}

/// New-format packet length (RFC 4880 4.2.2). Returns (length, offset-past-len).
/// Partial body lengths are not supported (returns None).
fn read_new_len(data: &[u8], off: usize) -> Option<(usize, usize)> {
    let first = *data.get(off)?;
    if first < 192 {
        Some((first as usize, off + 1))
    } else if first < 224 {
        let second = *data.get(off + 1)?;
        let len = ((first as usize - 192) << 8) + second as usize + 192;
        Some((len, off + 2))
    } else if first == 255 {
        let l = data.get(off + 1..off + 5)?;
        let len = u32::from_be_bytes([l[0], l[1], l[2], l[3]]) as usize;
        Some((len, off + 5))
    } else {
        None // partial body length
    }
}

/// Old-format packet length (RFC 4880 4.2.1) keyed by length-type 0/1/2/3.
fn read_old_len(data: &[u8], off: usize, ltype: u8) -> Option<(usize, usize)> {
    match ltype {
        0 => Some((*data.get(off)? as usize, off + 1)),
        1 => {
            let l = data.get(off..off + 2)?;
            Some((u16::from_be_bytes([l[0], l[1]]) as usize, off + 2))
        }
        2 => {
            let l = data.get(off..off + 4)?;
            Some((u32::from_be_bytes([l[0], l[1], l[2], l[3]]) as usize, off + 4))
        }
        _ => Some((0, off)), // indeterminate length
    }
}
