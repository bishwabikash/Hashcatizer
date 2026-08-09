// Android ADB backups (adb backup) -> hashcat -m 18900.
//
//   $ab$<version>*<cipher>*<rounds>*<user_salt>*<ck_salt>*<user_iv>*<masterkey_blob>
//
// The header is seven newline-terminated ASCII lines:
//   ANDROID BACKUP / version / compressed / encryption / user salt /
//   checksum salt / rounds / user IV / master key blob
// The salts, IV and blob are already hex there, so they are copied through
// rather than re-encoded.

const MAGIC: &str = "ANDROID BACKUP";

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let head = data.get(..data.len().min(4096))?;
    let text = std::str::from_utf8(head).ok()?;
    if !text.starts_with(MAGIC) {
        return None;
    }
    let lines: Vec<&str> = text.lines().collect();

    // [0] magic [1] version [2] compressed [3] algorithm, then the key material.
    let version: u32 = lines.get(1)?.trim().parse().ok()?;
    let algorithm = lines.get(3)?.trim();
    if algorithm == "none" {
        return None; // unencrypted backup
    }
    let user_salt = hex_field(lines.get(4)?)?;
    let ck_salt = hex_field(lines.get(5)?)?;
    let rounds: u32 = lines.get(6)?.trim().parse().ok()?;
    let user_iv = hex_field(lines.get(7)?)?;
    let masterkey = hex_field(lines.get(8)?)?;

    // hashcat's cipher field: 0 = AES-256, which is all Android ever wrote.
    Some(vec![format!(
        "$ab${}*{}*{}*{}*{}*{}*{}",
        version, 0, rounds, user_salt, ck_salt, user_iv, masterkey
    )])
}

fn hex_field(line: &str) -> Option<String> {
    let v = line.trim();
    if v.is_empty() || !v.len().is_multiple_of(2) || !v.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(v.to_ascii_lowercase())
}
