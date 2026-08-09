use crate::common::to_hex;

// Strip password manager databases (SQLCipher) -> $strip$ (john only; see
// docs/HASHCAT_GAPS.md).
//
//   $strip$*<first 1024 bytes, hex>
//
// Like other SQLCipher databases the first page is fully encrypted, so the
// absence of the plaintext "SQLite format 3" header is the only usable check.

const PREFIX_LEN: usize = 1024;

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    // An unencrypted SQLite file has nothing to crack.
    if data.starts_with(b"SQLite format 3\x00") {
        return None;
    }
    let head = data.get(..PREFIX_LEN)?;
    Some(vec![format!("$strip$*{}", to_hex(head))])
}
