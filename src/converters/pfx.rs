use crate::common::to_hex;
use crate::der::{self, Parser, TAG_INTEGER, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE};

// PKCS#12 / PFX bundles -> $pfxng$ (john only; see docs/HASHCAT_GAPS.md).
//
//   $pfxng$<mac_algo>$<key_len>$<iterations>$<salt_len>$<salt>$<data>$<mac>
//
// The crackable material is the MacData at the end of the PFX: the password
// derives an HMAC key over the authSafe contents, so `data` is the authSafe
// content octets and `mac` is the stored digest.
//
//   PFX ::= SEQUENCE { version, authSafe ContentInfo, macData MacData OPTIONAL }
//   MacData ::= SEQUENCE { mac DigestInfo, macSalt OCTET STRING, iterations }
//   DigestInfo ::= SEQUENCE { AlgorithmIdentifier, digest OCTET STRING }
//
// A PFX with no MacData is password-integrity-free and has nothing to attack.

/// PKCS#12 default when the iterations field is absent.
const DEFAULT_ITERATIONS: u64 = 1;

pub fn convert(data: &[u8], _f: &str) -> Option<Vec<String>> {
    let root = der::parse(data)?;
    if root.tag != TAG_SEQUENCE {
        return None;
    }
    let mut top = root.children();

    let _version = top.expect(TAG_INTEGER)?;
    let auth_safe = top.expect(TAG_SEQUENCE)?; // ContentInfo
    let mac_data = top.expect(TAG_SEQUENCE)?; // MacData

    // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
    let mut ci = auth_safe.children();
    ci.expect(TAG_OID)?;
    let content = ci.next()?; // [0] wrapper
    let inner = Parser::new(content.value).next()?;
    // The MAC covers the OCTET STRING contents, not its tag/length header.
    let signed = inner.value;

    let mut md = mac_data.children();
    let digest_info = md.expect(TAG_SEQUENCE)?;
    let salt = md.expect(TAG_OCTET_STRING)?.value;
    let iterations = match md.expect(TAG_INTEGER) {
        Some(e) => e.as_u64()?,
        None => DEFAULT_ITERATIONS,
    };

    let mut di = digest_info.children();
    let alg = di.expect(TAG_SEQUENCE)?;
    let mac = di.expect(TAG_OCTET_STRING)?.value;

    let mut alg_parts = alg.children();
    let (mac_algo, key_len) = digest_params(&alg_parts.expect(TAG_OID)?.as_oid()?)?;

    Some(vec![format!(
        "$pfxng${}${}${}${}${}${}${}",
        mac_algo,
        key_len,
        iterations,
        salt.len(),
        to_hex(salt),
        to_hex(signed),
        to_hex(mac)
    )])
}

/// john identifies the MAC algorithm by its digest size in bits, paired with
/// the HMAC key length in bytes.
fn digest_params(oid: &str) -> Option<(u32, u32)> {
    Some(match oid {
        "1.3.14.3.2.26" => (1, 20),           // sha1
        "2.16.840.1.101.3.4.2.1" => (256, 32), // sha256
        "2.16.840.1.101.3.4.2.2" => (384, 48), // sha384
        "2.16.840.1.101.3.4.2.3" => (512, 64), // sha512
        "2.16.840.1.101.3.4.2.4" => (224, 28), // sha224
        _ => return None,
    })
}
