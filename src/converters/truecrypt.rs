use crate::common::to_hex;

// TrueCrypt volumes -> hashcat -m 29311-29343 ($truecrypt$) and the legacy
// -m 6211-6243 (bare hex) modes.
//
// The volume has no magic number by design — the whole 512-byte header is
// encrypted, so an unopened volume is indistinguishable from random data. That
// makes this converter unsafe for the blind auto-detect sweep (it would claim
// every file), which is why it is excluded from `fallback_safe` and reached by
// extension or by explicit selection only.
//
// A hidden volume, if present, keeps its header at offset 65536; both are
// emitted because either passphrase may be the one the user has.

pub const HEADER_SIZE: usize = 512;
pub const HIDDEN_OFFSET: usize = 65536;

pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    headers(data, "$truecrypt$")
}

/// Shared with the VeraCrypt converter, which differs only in its prefix and
/// the PBKDF2 iteration counts the cracker applies.
pub fn headers(data: &[u8], prefix: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();

    if let Some(primary) = data.get(..HEADER_SIZE) {
        out.push(format!("{}{}", prefix, to_hex(primary)));
    }
    if let Some(hidden) = data.get(HIDDEN_OFFSET..HIDDEN_OFFSET + HEADER_SIZE) {
        // An all-zero block means there is simply no hidden volume there.
        if hidden.iter().any(|&b| b != 0) {
            out.push(format!("{}{}", prefix, to_hex(hidden)));
        }
    }
    if out.is_empty() { None } else { Some(out) }
}
