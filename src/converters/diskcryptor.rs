use crate::common::to_hex;

// DiskCryptor volumes -> hashcat -m 20011-20013.
//
//   $diskcryptor$0*<2048-byte header, hex>
//
// Like TrueCrypt the header is fully encrypted and carries no magic, so the
// only available sanity check is statistical: a real header is indistinguishable
// from random, while a wrong disk or an unencrypted partition is not. Both
// checks below come from diskcryptor2john.

const HEADER_SIZE: usize = 2048;

/// Markers that mean this is a readable, unencrypted volume.
const PLAINTEXT_MARKERS: [&[u8]; 3] = [b"BOOTMGR", b"NTFS", b"disk read"];

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let header = data.get(..HEADER_SIZE)?;

    if PLAINTEXT_MARKERS
        .iter()
        .any(|m| header.windows(m.len()).any(|w| w == *m))
    {
        return None; // not an encrypted DiskCryptor volume
    }
    // Encrypted data is near-uniform; anything materially below 6 bits/byte is
    // structured content that only looks like a header by accident.
    if shannon_entropy(header) < 6.0 {
        return None;
    }

    Some(vec![format!("$diskcryptor$0*{}", to_hex(header))])
}

fn shannon_entropy(data: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}
