use crate::common::to_hex;
use crate::protobuf;

// bitcoinj-format wallets (Coinomi, MultiBit Classic .wallet)
// -> hashcat -m 27700, emitted as john's $multibit$3* variant.
//
//   $multibit$3*<N>*<r>*<p>*<salt>*<encrypted_data>
//
// The wallet is serialised protobuf. Relevant fields:
//
//   Wallet.key                   = 3   (repeated Key)
//   Wallet.encryption_type       = 6   (2 = ENCRYPTED_SCRYPT_AES)
//   Wallet.encryption_parameters = 7   (ScryptParameters)
//   Key.type                     = 1
//   Key.encrypted_data           = 6   (EncryptedData)
//   EncryptedData.encrypted_private_key = 2
//   ScryptParameters { salt = 1, n = 2, r = 3, p = 4 }
//
// Only the trailing 32 bytes of a 48-byte encrypted key are needed: that is the
// final AES block pair the cracker verifies against.

const ENCRYPTED_SCRYPT_AES: u64 = 2;
const ENCRYPTED_KEY_LEN: usize = 48;
const CHECK_LEN: usize = 32;

// bitcoinj scrypt defaults, applied when a field is omitted.
const DEFAULT_N: u64 = 16384;
const DEFAULT_R: u64 = 8;
const DEFAULT_P: u64 = 1;

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    // Field 1 is the network identifier string, and a bitcoinj wallet always
    // starts with it; this doubles as the format check.
    let network = protobuf::find(data, 1)?;
    if network.wire_type != protobuf::WIRE_LEN || network.bytes.is_empty() {
        return None;
    }

    // An unencrypted wallet has nothing to crack.
    let enc_type = protobuf::find(data, 6).map(|f| f.varint).unwrap_or(0);
    if enc_type != ENCRYPTED_SCRYPT_AES {
        return None;
    }

    let params = protobuf::find(data, 7)?.bytes;
    let salt = protobuf::find(params, 1)?.bytes;
    if salt.is_empty() {
        return None;
    }
    let n = protobuf::find(params, 2).map(|f| f.varint).unwrap_or(DEFAULT_N);
    let r = protobuf::find(params, 3).map(|f| f.varint).unwrap_or(DEFAULT_R);
    let p = protobuf::find(params, 4).map(|f| f.varint).unwrap_or(DEFAULT_P);

    let mut out = Vec::new();
    for key in protobuf::find_all(data, 3) {
        let Some(enc) = protobuf::find(key.bytes, 6) else {
            continue; // key is not encrypted
        };
        let Some(priv_key) = protobuf::find(enc.bytes, 2) else {
            continue;
        };
        if priv_key.bytes.len() != ENCRYPTED_KEY_LEN {
            continue;
        }
        let part = &priv_key.bytes[ENCRYPTED_KEY_LEN - CHECK_LEN..];

        out.push(format!(
            "$multibit$3*{}*{}*{}*{}*{}",
            n,
            r,
            p,
            to_hex(salt),
            to_hex(part)
        ));
        // One hash per wallet is enough; every key shares the same scrypt salt.
        break;
    }
    if out.is_empty() { None } else { Some(out) }
}
