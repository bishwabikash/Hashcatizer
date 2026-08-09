use crate::common::to_hex;

// MultiBit Classic .key files -> hashcat -m 22500.
//
//   $multibit$1*<salt>*<encrypted_data>
//
// The .key export is an OpenSSL "Salted__" container: 8-byte salt followed by
// the ciphertext, of which the first two AES blocks are enough to verify a
// candidate password.
//
// The .wallet variant (-m 27700, `$multibit$2*`/`$multibit$3*` with scrypt N/r/p)
// is a bitcoinj protobuf and is not handled here — parsing protobuf to emit it
// would be guesswork without a fixture, and .key is the file john's own tooling
// recommends cracking anyway.

const MAGIC: &[u8] = b"Salted__";
const SALT_OFF: usize = 8;
const SALT_END: usize = 16;
/// Two AES blocks — what the cracker needs to test a candidate.
const DATA_END: usize = 48;

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    if !data.starts_with(MAGIC) {
        return None;
    }
    let salt = data.get(SALT_OFF..SALT_END)?;
    let encrypted = data.get(SALT_END..DATA_END)?;

    Some(vec![format!(
        "$multibit$1*{}*{}",
        to_hex(salt),
        to_hex(encrypted)
    )])
}
