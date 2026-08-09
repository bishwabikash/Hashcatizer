use crate::common::to_hex;

// Enpass 6.x vaults (SQLCipher) -> $enpass$ (john only; see
// docs/HASHCAT_GAPS.md).
//
//   $enpass$<version>$<iterations>$<first 1024 bytes, hex>
//
// An Enpass vault is a SQLCipher database: the first 16 bytes are the KDF salt
// and the rest of the page is encrypted, which is why the plaintext "SQLite
// format 3" header is absent. That absence is the only available check.
//
// hashcat's -m 24600 is SQLCipher but takes a different, much narrower encoding
// (SQLCIPHER*1*<iter>*<salt>*<page>), so it is not emitted here.

const VERSION: u32 = 1;
const ITERATIONS: u32 = 100_000;
const PREFIX_LEN: usize = 1024;

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    // A readable SQLite header means the database is not encrypted at all.
    if data.starts_with(b"SQLite format 3\x00") {
        return None;
    }
    let head = data.get(..PREFIX_LEN)?;

    Some(vec![format!(
        "$enpass${}${}${}",
        VERSION,
        ITERATIONS,
        to_hex(head)
    )])
}
