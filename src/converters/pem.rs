use crate::common::to_hex;
use crate::der::{self, TAG_INTEGER, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE};

// Encrypted PKCS#8 private keys -> hashcat -m 24410 / 24420.
//
//   $PEM$<type>$<cipher>$<salt>$<iterations>$<iv>$<len>$<data>
//
//   type   1 = PBKDF2-HMAC-SHA1 (-m 24410), 2 = PBKDF2-HMAC-SHA256 (-m 24420)
//   cipher 1 = 3DES, 2 = AES-128, 3 = AES-192, 4 = AES-256
//
// Note this is the compact form hashcat parses. Current pem2john.py emits a
// wider, self-describing variant for non-SHA1 PRFs
// (`$PEM$2$pbkdf2$sha256$aes256_cbc$...`) which hashcat rejects, so the two
// intentionally diverge for SHA-256 keys; the SHA-1 case is identical to john's.

const OID_PBES2: &str = "1.2.840.113549.1.5.13";
const OID_PBKDF2: &str = "1.2.840.113549.1.5.12";

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let der_bytes = unwrap_pem(data)?;
    let root = der::parse(&der_bytes)?;
    if root.tag != TAG_SEQUENCE {
        return None;
    }

    // EncryptedPrivateKeyInfo ::= SEQUENCE { encryptionAlgorithm, encryptedData }
    let mut top = root.children();
    let alg = top.expect(TAG_SEQUENCE)?;
    let encrypted = top.expect(TAG_OCTET_STRING)?;

    let mut alg_parts = alg.children();
    if alg_parts.expect(TAG_OID)?.as_oid()? != OID_PBES2 {
        return None; // PBES1 and the password-privacy modes are not supported
    }

    // PBES2-params ::= SEQUENCE { keyDerivationFunc, encryptionScheme }
    let mut params = alg_parts.expect(TAG_SEQUENCE)?.children();
    let kdf = params.expect(TAG_SEQUENCE)?;
    let scheme = params.expect(TAG_SEQUENCE)?;

    let mut kdf_parts = kdf.children();
    if kdf_parts.expect(TAG_OID)?.as_oid()? != OID_PBKDF2 {
        return None;
    }
    let mut kdf_params = kdf_parts.expect(TAG_SEQUENCE)?.children();
    let salt = kdf_params.expect(TAG_OCTET_STRING)?.value;
    let iterations = kdf_params.expect(TAG_INTEGER)?.as_u64()?;

    // keyLength is optional and precedes the equally optional PRF block;
    // an absent PRF means hmacWithSHA1 by definition.
    let mut prf = None;
    while let Some(tag) = kdf_params.peek_tag() {
        match tag {
            TAG_INTEGER => {
                kdf_params.next()?;
            }
            TAG_SEQUENCE => {
                let mut p = kdf_params.expect(TAG_SEQUENCE)?.children();
                prf = p.expect(TAG_OID)?.as_oid();
                break;
            }
            _ => break,
        }
    }
    let pem_type = match prf.as_deref() {
        None | Some("1.2.840.113549.2.7") => 1, // hmacWithSHA1
        Some("1.2.840.113549.2.9") => 2,        // hmacWithSHA256
        _ => return None,
    };

    let mut scheme_parts = scheme.children();
    let cipher_oid = scheme_parts.expect(TAG_OID)?.as_oid()?;
    let iv = scheme_parts.expect(TAG_OCTET_STRING)?.value;
    let cipher_id = match cipher_oid.as_str() {
        "1.2.840.113549.3.7" => 1,      // des-ede3-cbc
        "2.16.840.1.101.3.4.1.2" => 2,  // aes128-CBC
        "2.16.840.1.101.3.4.1.22" => 3, // aes192-CBC
        "2.16.840.1.101.3.4.1.42" => 4, // aes256-CBC
        _ => return None,
    };

    Some(vec![format!(
        "$PEM${}${}${}${}${}${}${}",
        pem_type,
        cipher_id,
        to_hex(salt),
        iterations,
        to_hex(iv),
        encrypted.value.len(),
        to_hex(encrypted.value)
    )])
}

/// Strip the PEM armour around an ENCRYPTED PRIVATE KEY block. A bare DER file
/// is passed through untouched.
fn unwrap_pem(data: &[u8]) -> Option<Vec<u8>> {
    let text = match std::str::from_utf8(data) {
        Ok(t) => t,
        Err(_) => return Some(data.to_vec()),
    };
    const BEGIN: &str = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
    const END: &str = "-----END ENCRYPTED PRIVATE KEY-----";
    let Some(start) = text.find(BEGIN) else {
        return Some(data.to_vec());
    };
    let start = start + BEGIN.len();
    let end = text[start..].find(END)? + start;
    let b64: String = text[start..end].split_whitespace().collect();
    crate::common::b64_decode(&b64).ok()
}
