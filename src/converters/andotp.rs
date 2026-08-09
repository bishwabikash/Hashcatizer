use crate::common::to_hex;

// andOTP encrypted backups (.json.aes) -> $andotp$ (john only; see
// docs/HASHCAT_GAPS.md).
//
//   $andotp$0*<iv>*<ciphertext>*<tag>
//
// AES-GCM layout: a 12-byte IV, the ciphertext, then the 16-byte auth tag. The
// previous implementation assumed a fixed 244-byte body and emitted the tag as
// part of the ciphertext, so the GCM check could never pass.

const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// Smallest body that can hold anything meaningful between IV and tag.
const MIN_BODY: usize = 2;

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    if data.len() < IV_LEN + MIN_BODY + TAG_LEN {
        return None;
    }
    // GCM ciphertext is indistinguishable from random; requiring that rules
    // out the plaintext files this previously claimed.
    if !crate::common::looks_encrypted(data.get(IV_LEN..)?, 7.0) {
        return None;
    }
    let iv = data.get(..IV_LEN)?;
    let ciphertext = data.get(IV_LEN..data.len() - TAG_LEN)?;
    let tag = data.get(data.len() - TAG_LEN..)?;

    Some(vec![format!(
        "$andotp$0*{}*{}*{}",
        to_hex(iv),
        to_hex(ciphertext),
        to_hex(tag)
    )])
}
