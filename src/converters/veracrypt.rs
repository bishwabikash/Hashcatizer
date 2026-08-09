// VeraCrypt volumes -> hashcat -m 29411-29483 ($veracrypt$) and the legacy
// -m 13711-13783 (bare hex) modes.
//
// Structurally identical to TrueCrypt — an encrypted 512-byte header with no
// magic, plus an optional hidden volume at 65536 — so the header extraction is
// shared. The formats differ only in prefix: VeraCrypt raises the PBKDF2
// iteration count, and the cracker picks that up from the mode, not the hash.

pub fn convert(data: &[u8], _filename: &str) -> Option<Vec<String>> {
    super::truecrypt::headers(data, "$veracrypt$")
}
